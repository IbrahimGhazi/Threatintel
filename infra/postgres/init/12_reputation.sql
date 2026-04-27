-- ============================================================
-- 12_reputation.sql
-- Reputation-aware detection: scoring-based recon & DNS tunneling
-- ============================================================

-- ── First-seen domain tracker ────────────────────────────────────────────────
-- Populated by correlation service on every DNS query. Used by the reputation
-- scorer to bump risk for newly-observed domains.
CREATE TABLE IF NOT EXISTS domain_first_seen (
  domain         VARCHAR(255) PRIMARY KEY,
  first_seen_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  last_seen_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  sample_count   INTEGER      NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_domain_first_seen_recent
  ON domain_first_seen (first_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_domain_last_seen
  ON domain_first_seen (last_seen_at DESC);

-- ── Reputation shadow events ────────────────────────────────────────────────
-- During shadow mode the reputation scorer logs what it *would* do, without
-- affecting real alerts. Operators can compare the volume of real alerts
-- (still fired by count-based rules) against the volume the reputation rule
-- would have produced, and validate the suppression delta before switching
-- to enforcement.
CREATE TABLE IF NOT EXISTS reputation_shadow_events (
  id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_name       VARCHAR(128) NOT NULL,
  src_ip          VARCHAR(64),
  dst_ip          VARCHAR(64),
  real_alert_id   UUID         REFERENCES alerts(id) ON DELETE SET NULL,
  would_fire      BOOLEAN      NOT NULL,
  risk_score      FLOAT        NOT NULL DEFAULT 0,
  risk_threshold  FLOAT        NOT NULL DEFAULT 0,
  volume          INTEGER      NOT NULL DEFAULT 0,
  dos_floor       INTEGER      NOT NULL DEFAULT 0,
  detection_mode  VARCHAR(32)  NOT NULL,  -- 'reputation' | 'volumetric' | 'suppressed'
  context         JSONB,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_shadow_created    ON reputation_shadow_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shadow_rule       ON reputation_shadow_events (rule_name, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shadow_would_fire ON reputation_shadow_events (would_fire, created_at DESC);

-- Retention note: operators should prune rows older than 30 days via pg_cron
-- or similar. Left unscheduled here to avoid assuming cron availability.

-- ── Reputation settings ──────────────────────────────────────────────────────
-- Insert default values into platform_settings if absent. Do NOT overwrite
-- operator-tuned values.
INSERT INTO platform_settings (key, value, description) VALUES
  ('reputation_detection_mode',       'shadow', 'Reputation detection mode: off | shadow | enforce'),
  ('port_scan_risk_threshold',        '10.0',   'Weighted risk score at which port_scan fires (reputation mode)'),
  ('host_discovery_risk_threshold',   '6.0',    'Weighted risk score at which host_discovery fires'),
  ('service_scan_risk_threshold',     '8.0',    'Weighted risk score at which service_scan fires'),
  ('repeated_conn_risk_threshold',    '6.0',    'Weighted risk score at which repeated_connection_attempts fires'),
  ('blocked_conn_risk_threshold',     '6.0',    'Weighted risk score at which repeated_blocked_connections fires'),
  ('dns_tunnel_risk_threshold',       '15.0',   'Weighted risk score at which dns_tunneling fires'),
  ('port_scan_dos_floor',             '500',    'Raw unique-port count that always fires port_scan (volumetric)'),
  ('host_discovery_dos_floor',        '300',    'Raw unique-dest count that always fires host_discovery (volumetric)'),
  ('service_scan_dos_floor',          '200',    'Raw unique-host count that always fires service_scan (volumetric)'),
  ('repeated_conn_dos_floor',         '500',    'Raw failed-conn count that always fires repeated_connection_attempts'),
  ('blocked_conn_dos_floor',          '500',    'Raw blocked-conn count that always fires repeated_blocked_connections'),
  ('dns_tunnel_dos_floor',            '300',    'Raw DNS-query count that always fires dns_tunneling (volumetric)'),
  ('tranco_match_weight',             '-0.8',   'Risk weight reduction for destinations matching Tranco Top 100k'),
  ('baseline_match_weight',           '-1.0',   'Risk weight reduction for destinations in per-host learned set'),
  ('ti_match_weight',                 '+2.0',   'Risk weight bump for destinations matching a TI indicator'),
  ('nrd_weight',                      '+1.5',   'Risk weight bump for newly-registered domains (<30 days)'),
  ('unusual_tld_weight',              '+0.5',   'Risk weight bump for uncommon TLDs (.xyz, .top, .cc, .ru, .tk, .ml, .ga)'),
  ('high_entropy_weight',             '+0.8',   'Risk weight bump for DNS labels with entropy > 3.8'),
  ('long_label_weight',               '+0.5',   'Risk weight bump for DNS labels > 40 chars')
ON CONFLICT (key) DO NOTHING;
