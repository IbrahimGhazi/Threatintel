-- ============================================================
-- Threat Intelligence Platform – PostgreSQL Schema
-- ============================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- ── Enums ────────────────────────────────────────────────────

CREATE TYPE indicator_type AS ENUM (
    'ip', 'cidr', 'domain', 'url', 'md5', 'sha1', 'sha256', 'sha512',
    'email', 'filename', 'mutex', 'registry_key', 'user_agent'
);

CREATE TYPE severity_level AS ENUM ('info', 'low', 'medium', 'high', 'critical');

CREATE TYPE alert_status AS ENUM ('open', 'acknowledged', 'resolved', 'false_positive');

CREATE TYPE sandbox_status AS ENUM ('pending', 'running', 'completed', 'failed', 'timeout');

-- ── Core Indicator Table ─────────────────────────────────────

CREATE TABLE indicators (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type            indicator_type NOT NULL,
    value           TEXT NOT NULL,
    -- normalized_value stores lowercase, trimmed, canonicalized form for dedup
    normalized_value TEXT NOT NULL,
    severity        severity_level NOT NULL DEFAULT 'medium',
    -- confidence: 0-100, aggregated from all sources
    confidence      SMALLINT NOT NULL DEFAULT 50
                    CONSTRAINT confidence_range CHECK (confidence BETWEEN 0 AND 100),
    -- reputation_score: -100 (benign) to 100 (malicious)
    reputation_score SMALLINT NOT NULL DEFAULT 0
                    CONSTRAINT reputation_range CHECK (reputation_score BETWEEN -100 AND 100),
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    false_positive  BOOLEAN NOT NULL DEFAULT FALSE,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    -- enrichment stores GeoIP, WHOIS, ASN, rDNS etc.
    enrichment      JSONB NOT NULL DEFAULT '{}',
    -- metadata: free-form source-specific fields
    metadata        JSONB NOT NULL DEFAULT '{}',
    -- TTL support: NULL means no expiry
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_indicator UNIQUE (type, normalized_value)
);

-- Partial index for active indicators (most queries filter on active=true)
CREATE INDEX idx_indicators_active ON indicators (type, normalized_value)
    WHERE active = TRUE;

-- GIN index for tag array searches
CREATE INDEX idx_indicators_tags ON indicators USING GIN (tags);

-- GIN index for JSONB enrichment queries
CREATE INDEX idx_indicators_enrichment ON indicators USING GIN (enrichment);

-- Trigram index for fuzzy value searches
CREATE INDEX idx_indicators_value_trgm ON indicators USING GIN (value gin_trgm_ops);

-- Index for time-based queries
CREATE INDEX idx_indicators_last_seen ON indicators (last_seen DESC);
CREATE INDEX idx_indicators_first_seen ON indicators (first_seen DESC);

-- ── Indicator Sources ────────────────────────────────────────

CREATE TABLE indicator_sources (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    indicator_id    UUID NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    source_name     TEXT NOT NULL,
    source_category TEXT NOT NULL DEFAULT 'open_source',
    -- raw_data: original feed record (trimmed to reasonable size)
    raw_data        JSONB NOT NULL DEFAULT '{}',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- per-source confidence contribution
    confidence      SMALLINT NOT NULL DEFAULT 50,

    CONSTRAINT uq_source UNIQUE (indicator_id, source_name)
);

CREATE INDEX idx_sources_indicator_id ON indicator_sources (indicator_id);
CREATE INDEX idx_sources_name ON indicator_sources (source_name);

-- ── Feed Configuration ───────────────────────────────────────

CREATE TABLE feeds (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                TEXT NOT NULL UNIQUE,
    display_name        TEXT NOT NULL,
    description         TEXT,
    feed_type           TEXT NOT NULL,   -- 'http', 'taxii', 'api'
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    url                 TEXT,
    -- interval in seconds between polling cycles
    poll_interval       INTEGER NOT NULL DEFAULT 3600
                        CONSTRAINT positive_interval CHECK (poll_interval > 0),
    -- last successful and last attempted run
    last_run_at         TIMESTAMPTZ,
    last_success_at     TIMESTAMPTZ,
    last_error          TEXT,
    last_error_at       TIMESTAMPTZ,
    -- running totals
    total_ingested      BIGINT NOT NULL DEFAULT 0,
    -- custom config per feed (api keys, headers, etc.)
    config              JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Alerts ───────────────────────────────────────────────────

CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title           TEXT NOT NULL,
    description     TEXT,
    severity        severity_level NOT NULL,
    status          alert_status NOT NULL DEFAULT 'open',
    -- may reference an indicator
    indicator_id    UUID REFERENCES indicators(id) ON DELETE SET NULL,
    indicator_value TEXT,
    indicator_type  indicator_type,
    -- source of the detection
    rule_name       TEXT,
    source_service  TEXT NOT NULL DEFAULT 'correlation',
    -- associated log entry
    log_entry_id    UUID,
    -- enrichment snapshot at alert time
    context         JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    resolved_at     TIMESTAMPTZ,
    notes           TEXT
);

CREATE INDEX idx_alerts_status ON alerts (status, created_at DESC);
CREATE INDEX idx_alerts_severity ON alerts (severity, created_at DESC);
CREATE INDEX idx_alerts_indicator ON alerts (indicator_id);
CREATE INDEX idx_alerts_created ON alerts (created_at DESC);

-- ── Log Entries ───────────────────────────────────────────────

CREATE TABLE log_entries (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- source device classification
    source_type     TEXT NOT NULL,   -- 'firewall', 'proxy', 'edr', 'email', 'web_gw'
    source_name     TEXT,            -- device hostname / identifier
    -- raw unparsed log line
    raw_log         TEXT,
    -- structured parsed fields
    parsed          JSONB NOT NULL DEFAULT '{}',
    -- IDs of matched indicators
    indicator_ids   UUID[] NOT NULL DEFAULT '{}',
    -- was any matched indicator malicious?
    is_malicious    BOOLEAN NOT NULL DEFAULT FALSE,
    -- original event timestamp (from the log itself)
    log_timestamp   TIMESTAMPTZ,
    processed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_logs_processed ON log_entries (processed_at DESC);
CREATE INDEX idx_logs_malicious ON log_entries (is_malicious, processed_at DESC)
    WHERE is_malicious = TRUE;
CREATE INDEX idx_logs_source ON log_entries (source_type, source_name);
CREATE INDEX idx_logs_indicators ON log_entries USING GIN (indicator_ids);

-- ── Sandbox Results ───────────────────────────────────────────

CREATE TABLE sandbox_results (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_sha256         TEXT NOT NULL UNIQUE,
    file_md5            TEXT,
    file_sha1           TEXT,
    file_name           TEXT,
    file_size           BIGINT,
    file_type           TEXT,
    status              sandbox_status NOT NULL DEFAULT 'pending',
    -- verdict: 'malicious', 'suspicious', 'clean', 'unknown'
    verdict             TEXT,
    malware_score       SMALLINT,   -- 0-100
    malware_family      TEXT,
    -- external sandbox task identifier
    sandbox_task_id     TEXT,
    sandbox_engine      TEXT NOT NULL DEFAULT 'cape',
    -- full analysis report
    report              JSONB NOT NULL DEFAULT '{}',
    -- extracted IOCs from sandbox run
    extracted_iocs      JSONB NOT NULL DEFAULT '{}',
    submitted_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    error               TEXT
);

CREATE INDEX idx_sandbox_sha256 ON sandbox_results (file_sha256);
CREATE INDEX idx_sandbox_status ON sandbox_results (status, submitted_at DESC);

-- ── EDL (External Dynamic List) Configurations ───────────────

CREATE TABLE edl_configs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT NOT NULL UNIQUE,
    slug            TEXT NOT NULL UNIQUE,   -- URL-safe identifier
    description     TEXT,
    indicator_type  indicator_type NOT NULL,
    -- filtering criteria
    min_confidence  SMALLINT NOT NULL DEFAULT 50,
    min_severity    severity_level NOT NULL DEFAULT 'medium',
    -- optional tag filter (NULL = all tags)
    tags_filter     TEXT[],
    -- max age of indicators to include (days), NULL = no limit
    max_age_days    INTEGER,
    -- output format: 'plain', 'csv', 'json', 'stix'
    format          TEXT NOT NULL DEFAULT 'plain',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    -- cached count (updated on refresh)
    cached_count    INTEGER NOT NULL DEFAULT 0,
    last_built_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Enrichment Cache ──────────────────────────────────────────

CREATE TABLE enrichment_cache (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cache_key   TEXT NOT NULL UNIQUE,   -- e.g. 'geoip:1.2.3.4'
    module      TEXT NOT NULL,
    data        JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_enrichment_cache_key ON enrichment_cache (cache_key);
CREATE INDEX idx_enrichment_cache_expires ON enrichment_cache (expires_at);

-- ── Update Trigger for updated_at ────────────────────────────

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_indicators_updated_at
    BEFORE UPDATE ON indicators
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_feeds_updated_at
    BEFORE UPDATE ON feeds
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_edl_updated_at
    BEFORE UPDATE ON edl_configs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ── Default Feed Configurations ───────────────────────────────

INSERT INTO feeds (name, display_name, description, feed_type, url, poll_interval, config) VALUES
(
    'urlhaus',
    'URLHaus',
    'Abuse.ch URLHaus malicious URL database',
    'http',
    'https://urlhaus.abuse.ch/downloads/csv_recent/',
    3600,
    '{"format": "csv", "indicator_type": "url"}'
),
(
    'threatfox',
    'ThreatFox',
    'Abuse.ch ThreatFox IOC database',
    'api',
    'https://threatfox-api.abuse.ch/api/v1/',
    3600,
    '{"format": "json"}'
),
(
    'malwarebazaar',
    'MalwareBazaar',
    'Abuse.ch MalwareBazaar malware sample database',
    'api',
    'https://mb-api.abuse.ch/api/v1/',
    7200,
    '{"format": "json", "indicator_type": "hash"}'
),
(
    'openphish',
    'OpenPhish',
    'OpenPhish phishing URL feed',
    'http',
    'https://openphish.com/feed.txt',
    3600,
    '{"format": "txt", "indicator_type": "url"}'
),
(
    'abuseipdb',
    'AbuseIPDB',
    'AbuseIPDB blacklisted IP database (requires API key)',
    'api',
    'https://api.abuseipdb.com/api/v2/blacklist',
    86400,
    '{"format": "json", "indicator_type": "ip", "requires_key": true}'
),
(
    'otx',
    'AlienVault OTX',
    'AlienVault Open Threat Exchange (requires API key)',
    'api',
    'https://otx.alienvault.com/api/v1/',
    3600,
    '{"format": "json", "requires_key": true}'
);

-- ── Default EDL Configurations ────────────────────────────────

INSERT INTO edl_configs (name, slug, description, indicator_type, min_confidence, min_severity, format) VALUES
(
    'Malicious IPs - High Confidence',
    'malicious-ips-high',
    'High confidence malicious IP addresses for firewall blocking',
    'ip', 70, 'high', 'plain'
),
(
    'Malicious Domains',
    'malicious-domains',
    'Malicious domains for DNS sinkholing and proxy blocking',
    'domain', 60, 'medium', 'plain'
),
(
    'Malicious URLs',
    'malicious-urls',
    'Malicious URLs for web proxy blocking',
    'url', 60, 'medium', 'plain'
),
(
    'Malware File Hashes',
    'malware-hashes-sha256',
    'Known malware SHA256 hashes for EDR blocking',
    'sha256', 70, 'high', 'plain'
);
