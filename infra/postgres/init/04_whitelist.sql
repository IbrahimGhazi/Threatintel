-- ============================================================
-- Whitelist / Allowlist System
-- ============================================================
-- Allows analysts to suppress alerts for known-good IPs, CIDRs,
-- hostnames, rule names, or indicator values.

CREATE TABLE whitelist_entries (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- What to whitelist: 'ip', 'cidr', 'hostname', 'rule_name', 'indicator_value'
    entry_type      TEXT NOT NULL
                    CONSTRAINT valid_entry_type CHECK (
                        entry_type IN ('ip', 'cidr', 'hostname', 'rule_name', 'indicator_value')
                    ),
    -- The value to match (IP address, CIDR block, hostname, rule name, etc.)
    value           TEXT NOT NULL,
    -- Optional: only suppress for a specific rule (NULL = all rules)
    scope_rule      TEXT,
    -- Human-readable reason
    reason          TEXT,
    -- Who created this entry
    created_by      TEXT NOT NULL DEFAULT 'system',
    -- Optional expiry (NULL = permanent)
    expires_at      TIMESTAMPTZ,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    -- Link back to the alert that triggered this whitelist (optional)
    source_alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_whitelist UNIQUE (entry_type, value, scope_rule)
);

CREATE INDEX idx_whitelist_type_value ON whitelist_entries (entry_type, value) WHERE enabled = TRUE;
CREATE INDEX idx_whitelist_enabled ON whitelist_entries (enabled, expires_at);

CREATE TRIGGER trg_whitelist_updated_at
    BEFORE UPDATE ON whitelist_entries
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
