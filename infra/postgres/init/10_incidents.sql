-- ============================================================
-- Incident Grouping – groups related alerts into security incidents
-- ============================================================

-- Enum for incident lifecycle status
CREATE TYPE incident_status AS ENUM ('open', 'investigating', 'resolved', 'closed');

-- ── Incidents Table ─────────────────────────────────────────
CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title           TEXT NOT NULL,
    description     TEXT,
    severity        severity_level NOT NULL DEFAULT 'medium',
    status          incident_status NOT NULL DEFAULT 'open',
    source_ip       TEXT,
    attack_type     TEXT,
    mitre_tactics   TEXT[] NOT NULL DEFAULT '{}',
    total_events    INTEGER NOT NULL DEFAULT 0,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Link alerts to their parent incident
ALTER TABLE alerts ADD COLUMN incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL;

-- ── Indexes ─────────────────────────────────────────────────
CREATE INDEX idx_incidents_status      ON incidents (status, created_at DESC);
CREATE INDEX idx_incidents_severity    ON incidents (severity, created_at DESC);
CREATE INDEX idx_incidents_source_ip   ON incidents (source_ip);
CREATE INDEX idx_incidents_attack_type ON incidents (attack_type);
CREATE INDEX idx_incidents_last_seen   ON incidents (last_seen DESC);
CREATE INDEX idx_alerts_incident_id    ON alerts (incident_id);

-- ── Update trigger ──────────────────────────────────────────
CREATE TRIGGER trg_incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
