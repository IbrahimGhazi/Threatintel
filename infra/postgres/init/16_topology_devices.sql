-- ============================================================
-- Device registry for the Attack Path engine.
--
-- Replaces / supplements ad-hoc config uploads. A registered device is
-- polled on `poll_interval_seconds` (default 3600 = 1h); the puller
-- fetches the running config, sha256-diffs it against the last poll,
-- writes a new `topology_config_uploads` row when the config changed,
-- and auto-triggers a run.
--
-- Credentials are encrypted with Fernet using MASTER_ENCRYPTION_KEY
-- (already in `ti-secrets`). Plaintext never lands on disk or in the DB.
-- ============================================================

CREATE TYPE topology_device_status AS ENUM (
    'pending',     -- registered but never polled
    'ok',          -- last poll succeeded
    'auth_failed', -- credentials rejected
    'unreachable', -- network / TLS / DNS error
    'parse_error', -- fetched bytes but config didn't parse
    'disabled'     -- intentionally paused
);

CREATE TABLE topology_devices (
    id                       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vendor                   TEXT NOT NULL
                              CHECK (vendor IN ('panos', 'f5', 'fortinet')),
    role                     TEXT NOT NULL DEFAULT 'unknown'
                              CHECK (role IN ('firewall', 'loadbalancer', 'unknown')),
    hostname                 TEXT NOT NULL,            -- display name + canonical id
    address                  TEXT NOT NULL,            -- IP or DNS
    port                     INTEGER NOT NULL DEFAULT 443,
    verify_tls               BOOLEAN NOT NULL DEFAULT FALSE,

    -- Encrypted credential blob (Fernet token, ASCII). Shape after decrypt:
    --   PA:   {"api_key": "..."} OR {"user":"...","password":"..."}
    --   F5:   {"user":"...","password":"..."}
    credentials_encrypted    TEXT NOT NULL,

    enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
    poll_interval_seconds    INTEGER NOT NULL DEFAULT 3600
                              CHECK (poll_interval_seconds BETWEEN 60 AND 86400),

    -- Telemetry from the most recent poll attempt.
    last_polled_at           TIMESTAMPTZ,
    last_status              topology_device_status NOT NULL DEFAULT 'pending',
    last_error               TEXT,
    last_config_sha256       TEXT,            -- to detect changes
    last_upload_id           UUID REFERENCES topology_config_uploads(id) ON DELETE SET NULL,
    last_run_id              UUID REFERENCES topology_runs(id) ON DELETE SET NULL,
    -- Auto-set when fetched config matches an Internet-facing zone heuristic
    -- (zone has 0.0.0.0/0 or name in untrust|outside|wan|internet).
    is_edge                  BOOLEAN NOT NULL DEFAULT FALSE,

    notes                    TEXT,
    created_by               TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_topology_devices_addr_port UNIQUE (address, port)
);

CREATE INDEX idx_topology_devices_due
    ON topology_devices (last_polled_at)
    WHERE enabled = TRUE;

CREATE INDEX idx_topology_devices_vendor ON topology_devices (vendor);

CREATE TRIGGER trg_topology_devices_updated_at
    BEFORE UPDATE ON topology_devices
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Add 'source' to topology_config_uploads so we can distinguish manual
-- uploads from scheduled poll output. Default 'manual' preserves existing
-- rows. Foreign key out to topology_devices for poll-sourced rows.
ALTER TABLE topology_config_uploads
    ADD COLUMN IF NOT EXISTS source     TEXT NOT NULL DEFAULT 'manual'
                              CHECK (source IN ('manual', 'scheduler')),
    ADD COLUMN IF NOT EXISTS device_uuid UUID REFERENCES topology_devices(id)
                              ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_topology_uploads_device_uuid
    ON topology_config_uploads (device_uuid);
