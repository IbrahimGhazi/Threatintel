-- ============================================================
-- Schema v2 – Log Analysis enhancements
-- Safe to run on existing databases (all idempotent).
-- ============================================================

ALTER TABLE log_entries
    ADD COLUMN IF NOT EXISTS source_ip     TEXT,
    ADD COLUMN IF NOT EXISTS extracted_iocs JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS matched_iocs   JSONB NOT NULL DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_log_entries_created    ON log_entries(processed_at DESC);
CREATE INDEX IF NOT EXISTS idx_log_entries_malicious  ON log_entries(is_malicious) WHERE is_malicious = TRUE;
CREATE INDEX IF NOT EXISTS idx_log_entries_source_ip  ON log_entries(source_ip);
CREATE INDEX IF NOT EXISTS idx_log_entries_source_type ON log_entries(source_type);
