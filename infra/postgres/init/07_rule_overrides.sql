-- Rule override table: stores analyst-accepted threshold changes
-- picked up by the correlation service every 60 seconds.

CREATE TABLE IF NOT EXISTS rule_overrides (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_name     TEXT        NOT NULL,
    entity_type   TEXT        NOT NULL DEFAULT 'global',
    entity_value  TEXT        NOT NULL DEFAULT '*',
    threshold     NUMERIC,
    window_secs   INTEGER,
    applied_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_by    TEXT        NOT NULL DEFAULT 'analyst',
    suggestion_id UUID REFERENCES tuning_suggestions(id) ON DELETE SET NULL,
    UNIQUE (rule_name, entity_type, entity_value)
);

CREATE INDEX IF NOT EXISTS idx_rule_overrides_rule ON rule_overrides(rule_name);
