-- Platform-wide settings table
-- Stores tunable configuration values that can be changed at runtime via the API.

CREATE TABLE IF NOT EXISTS platform_settings (
    key         TEXT        PRIMARY KEY,
    value       TEXT        NOT NULL,
    description TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed defaults (no-op if already present)
INSERT INTO platform_settings (key, value, description) VALUES
  ('auto_apply_delay_hours',
   '24',
   'Hours to wait after scheduling before auto-applying a tuning suggestion (1–168)'),
  ('auto_apply_confidence',
   '0.85',
   'Minimum confidence score [0–1] required to schedule a suggestion for auto-apply')
ON CONFLICT (key) DO NOTHING;

-- Keep updated_at current on every write
CREATE OR REPLACE FUNCTION trg_fn_platform_settings_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_platform_settings_updated_at ON platform_settings;
CREATE TRIGGER trg_platform_settings_updated_at
    BEFORE UPDATE ON platform_settings
    FOR EACH ROW EXECUTE FUNCTION trg_fn_platform_settings_updated_at();
