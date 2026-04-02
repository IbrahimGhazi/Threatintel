-- ============================================================
-- 05_adaptive_baseline.sql
-- Adaptive baseline and rule-tuning tables
-- ============================================================

-- Behavioral baselines: per-entity, per-metric running statistics
-- Populated by the correlation service's baseline engine.
CREATE TABLE IF NOT EXISTS behavioral_baselines (
  id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_type     VARCHAR(20)  NOT NULL,   -- 'host', 'subnet', 'user', 'global'
  entity_value    VARCHAR(255) NOT NULL,   -- IP, CIDR, username, or '*' for global
  metric          VARCHAR(64)  NOT NULL,   -- dns_qpm, conn_count, unique_dst, failed_auth, etc.
  category        VARCHAR(64)  NOT NULL,   -- dns, port_scan, auth, connection, lateral_movement, c2
  mean            FLOAT        NOT NULL DEFAULT 0,
  std_dev         FLOAT        NOT NULL DEFAULT 0,
  sample_count    INTEGER      NOT NULL DEFAULT 0,
  min_observed    FLOAT,
  max_observed    FLOAT,
  p95             FLOAT,                   -- 95th-percentile estimate from reservoir sampling
  last_updated    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_baseline UNIQUE (entity_type, entity_value, metric)
);

CREATE INDEX IF NOT EXISTS idx_baselines_entity   ON behavioral_baselines (entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_baselines_category ON behavioral_baselines (category);
CREATE INDEX IF NOT EXISTS idx_baselines_updated  ON behavioral_baselines (last_updated DESC);

-- ── Tuning suggestions ────────────────────────────────────────────────────────
-- Generated when the same behavioral rule fires repeatedly for an entity
-- without confirmed malicious activity.
CREATE TABLE IF NOT EXISTS tuning_suggestions (
  id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  suggestion_type VARCHAR(64)  NOT NULL,   -- increase_threshold | add_allowlist | suppress_rule | adjust_window
  category        VARCHAR(64)  NOT NULL,   -- dns | port_scan | auth | connection | lateral_movement | c2
  entity_type     VARCHAR(20),             -- host | subnet | user | global
  entity_value    VARCHAR(255),            -- specific IP, CIDR, or username
  rule_name       VARCHAR(128) NOT NULL,
  current_value   JSONB,                   -- snapshot of current threshold / config
  suggested_value JSONB,                   -- what the engine recommends
  rationale       TEXT         NOT NULL,
  confidence      FLOAT        NOT NULL DEFAULT 0.0
                    CHECK (confidence >= 0 AND confidence <= 1),
  trigger_count   INTEGER      NOT NULL DEFAULT 1,
  status          VARCHAR(20)  NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'accepted', 'rejected', 'auto_applied')),
  auto_apply_at   TIMESTAMPTZ,             -- scheduled auto-apply; NULL = not yet scheduled
  applied_at      TIMESTAMPTZ,
  rejected_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_suggestions_status     ON tuning_suggestions (status);
CREATE INDEX IF NOT EXISTS idx_suggestions_rule       ON tuning_suggestions (rule_name);
CREATE INDEX IF NOT EXISTS idx_suggestions_entity     ON tuning_suggestions (entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_suggestions_confidence ON tuning_suggestions (confidence DESC);
CREATE INDEX IF NOT EXISTS idx_suggestions_auto_apply ON tuning_suggestions (auto_apply_at)
  WHERE status = 'pending' AND auto_apply_at IS NOT NULL;

-- ── Adaptive rule changes ─────────────────────────────────────────────────────
-- Full audit log of every rule change (auto-applied or analyst-applied).
-- Administrators can review and revert any entry.
CREATE TABLE IF NOT EXISTS adaptive_rule_changes (
  id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  suggestion_id   UUID         REFERENCES tuning_suggestions(id) ON DELETE SET NULL,
  change_type     VARCHAR(64)  NOT NULL,   -- threshold_increase | allowlist_add | rule_suppression | threshold_restore
  rule_name       VARCHAR(128) NOT NULL,
  entity_type     VARCHAR(20),
  entity_value    VARCHAR(255),
  previous_value  JSONB,
  new_value       JSONB,
  applied_by      VARCHAR(64)  NOT NULL DEFAULT 'system_auto',  -- 'system_auto' or analyst username
  reason          TEXT,
  reverted_at     TIMESTAMPTZ,
  reverted_by     VARCHAR(64),
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rule_changes_rule    ON adaptive_rule_changes (rule_name);
CREATE INDEX IF NOT EXISTS idx_rule_changes_entity  ON adaptive_rule_changes (entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_rule_changes_created ON adaptive_rule_changes (created_at DESC);

-- ── Auto-update trigger for tuning_suggestions.updated_at ────────────────────
CREATE OR REPLACE FUNCTION update_suggestion_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_suggestion_updated_at ON tuning_suggestions;
CREATE TRIGGER trg_suggestion_updated_at
  BEFORE UPDATE ON tuning_suggestions
  FOR EACH ROW EXECUTE FUNCTION update_suggestion_updated_at();
