-- ============================================================
-- Host Metadata — user-defined names, device types, and positions
-- for the network topology map.
-- ============================================================

CREATE TABLE IF NOT EXISTS host_metadata (
    ip              TEXT PRIMARY KEY,
    name            TEXT,
    device_type     TEXT NOT NULL DEFAULT 'unknown'
                      CHECK (device_type IN (
                        'firewall','server','switch','router',
                        'laptop','workstation','printer','iot',
                        'phone','access_point','unknown'
                      )),
    x_position      DOUBLE PRECISION,
    y_position      DOUBLE PRECISION,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_host_metadata_type ON host_metadata (device_type);

-- Update trigger
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_host_metadata_updated_at'
    ) THEN
        CREATE TRIGGER trg_host_metadata_updated_at
            BEFORE UPDATE ON host_metadata
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
    END IF;
END$$;
