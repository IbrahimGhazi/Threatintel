-- ============================================================
-- Attack Path & Fan-Out Analysis Engine
--
-- System-of-record for run history, config-file metadata, and
-- the curated findings produced by the analysis engine. The
-- topology graph itself lives in Neo4j; Postgres holds only what
-- needs to survive Neo4j re-builds and integrate with the rest of
-- the platform (alerts, tuning, ack/suppress lifecycle).
-- ============================================================

CREATE TYPE topology_run_status AS ENUM (
    'pending', 'parsing', 'loading', 'analyzing', 'completed', 'failed'
);

CREATE TYPE attack_path_finding_kind AS ENUM ('path', 'fanout');

CREATE TYPE attack_path_finding_status AS ENUM (
    'open', 'acknowledged', 'suppressed'
);

-- ── Runs ─────────────────────────────────────────────────────

CREATE TABLE topology_runs (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    status              topology_run_status NOT NULL DEFAULT 'pending',
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at         TIMESTAMPTZ,
    duration_ms         INTEGER,
    -- Counts populated as the run progresses.
    device_count        INTEGER NOT NULL DEFAULT 0,
    neo4j_node_count    INTEGER NOT NULL DEFAULT 0,
    neo4j_rel_count     INTEGER NOT NULL DEFAULT 0,
    findings_count      INTEGER NOT NULL DEFAULT 0,
    -- Normalised IR snapshot — re-load without re-parsing if needed.
    ir_snapshot         JSONB NOT NULL DEFAULT '{}',
    -- Non-fatal warnings from parsers/normaliser/loader.
    parse_warnings      JSONB NOT NULL DEFAULT '[]',
    -- Hard error message when status = 'failed'.
    error_message       TEXT,
    -- Effective scoring weights at run time (snapshotted from platform_settings).
    weights             JSONB NOT NULL DEFAULT '{}',
    triggered_by        TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_topology_runs_status     ON topology_runs (status);
CREATE INDEX idx_topology_runs_started_at ON topology_runs (started_at DESC);

CREATE TRIGGER trg_topology_runs_updated_at
    BEFORE UPDATE ON topology_runs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ── Config uploads ───────────────────────────────────────────

CREATE TABLE topology_config_uploads (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id              UUID REFERENCES topology_runs(id) ON DELETE CASCADE,
    vendor              TEXT NOT NULL
                          CHECK (vendor IN ('panos', 'f5', 'fortinet', 'unknown')),
    -- 'firewall' | 'loadbalancer'
    role                TEXT NOT NULL DEFAULT 'unknown',
    device_id           TEXT,                      -- canonical id we use in Neo4j
    hostname            TEXT,
    original_filename   TEXT NOT NULL,
    sha256              TEXT NOT NULL,
    size_bytes          INTEGER NOT NULL,
    stored_path         TEXT NOT NULL,
    parse_status        TEXT NOT NULL DEFAULT 'pending'
                          CHECK (parse_status IN ('pending','ok','failed')),
    parse_error         TEXT,
    uploaded_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_topology_uploads_run     ON topology_config_uploads (run_id);
CREATE INDEX idx_topology_uploads_sha     ON topology_config_uploads (sha256);
CREATE INDEX idx_topology_uploads_device  ON topology_config_uploads (device_id);

-- ── Findings ─────────────────────────────────────────────────
-- One row per (deduplicated) attack path or fan-out node. Status
-- survives across runs; re-runs UPSERT by fingerprint.

CREATE TABLE attack_path_findings (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fingerprint         TEXT NOT NULL UNIQUE,
    kind                attack_path_finding_kind NOT NULL,
    severity            severity_level NOT NULL,
    score               NUMERIC(5,2) NOT NULL,
    status              attack_path_finding_status NOT NULL DEFAULT 'open',

    -- Asset / target context (path findings)
    asset_ip            INET,
    asset_hostname      TEXT,
    asset_criticality   TEXT,
    -- Where the path enters from: 'internet' | 'zone:<name>' | 'host:<ip>'
    ingress             TEXT NOT NULL,
    hops                SMALLINT,

    -- Full path payload (Section 8.2 of plan)
    path_json           JSONB,
    -- Fan-out payload (Section 8.3 of plan)
    fanout_json         JSONB,
    -- Rules cited for traceability
    rules_cited         JSONB NOT NULL DEFAULT '[]',
    -- Score-factor breakdown for explainability
    score_breakdown     JSONB NOT NULL DEFAULT '{}',

    -- Run lineage — first_seen never moves; last_seen updates each time the
    -- finding re-appears in a new run.
    first_seen_run_id   UUID REFERENCES topology_runs(id) ON DELETE SET NULL,
    last_seen_run_id    UUID REFERENCES topology_runs(id) ON DELETE SET NULL,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Lifecycle tracking
    acknowledged_at     TIMESTAMPTZ,
    acknowledged_by     TEXT,
    suppressed_at       TIMESTAMPTZ,
    suppressed_by       TEXT,
    suppression_reason  TEXT,
    notes               TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_path_or_fanout CHECK (
        (kind = 'path'   AND path_json   IS NOT NULL) OR
        (kind = 'fanout' AND fanout_json IS NOT NULL)
    ),
    CONSTRAINT chk_score_range CHECK (score >= 0 AND score <= 100)
);

CREATE INDEX idx_apf_status_severity ON attack_path_findings (status, severity);
CREATE INDEX idx_apf_kind            ON attack_path_findings (kind);
CREATE INDEX idx_apf_asset_ip        ON attack_path_findings (asset_ip)
                                        WHERE asset_ip IS NOT NULL;
CREATE INDEX idx_apf_last_seen_run   ON attack_path_findings (last_seen_run_id);
CREATE INDEX idx_apf_last_seen_at    ON attack_path_findings (last_seen_at DESC);
CREATE INDEX idx_apf_score           ON attack_path_findings (score DESC);

CREATE TRIGGER trg_apf_updated_at
    BEFORE UPDATE ON attack_path_findings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ── Asset criticality registry ───────────────────────────────
-- Tags hosts as crown_jewel / high / medium / low, used by the scorer
-- and the :Asset mixin in Neo4j. Decoupled from host_metadata so the
-- attack-path team can manage criticality without colliding with the
-- topology-map's device_type taxonomy.

CREATE TABLE attack_path_assets (
    ip            INET PRIMARY KEY,
    hostname      TEXT,
    criticality   TEXT NOT NULL
                    CHECK (criticality IN ('crown_jewel','high','medium','low')),
    business_unit TEXT,
    notes         TEXT,
    created_by    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_apa_criticality ON attack_path_assets (criticality);

CREATE TRIGGER trg_apa_updated_at
    BEFORE UPDATE ON attack_path_assets
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ── Default scoring weights → platform_settings ──────────────
-- Platform_settings is hot-reloaded; values here are starter defaults
-- and may be tuned without redeployment.

INSERT INTO platform_settings (key, value, description)
VALUES
    ('attack_path_weight_exposure',    '0.30', 'Weight for Internet-exposure factor (0..1)'),
    ('attack_path_weight_proximity',   '0.25', 'Weight for path-proximity factor (0..1)'),
    ('attack_path_weight_branching',   '0.20', 'Weight for fan-out branching factor (0..1)'),
    ('attack_path_weight_criticality', '0.25', 'Weight for asset-criticality factor (0..1)'),
    ('attack_path_max_depth',          '6',    'Max DFS/BFS depth for path enumeration'),
    ('attack_path_top_k',              '5',    'Top-K paths returned per (asset, ingress)'),
    ('attack_path_fanout_out_min',     '5',    'Minimum out-degree to qualify as fan-out node'),
    ('attack_path_fanout_in_max',      '3',    'Maximum Internet-ingress paths for fan-out qualification')
ON CONFLICT (key) DO NOTHING;
