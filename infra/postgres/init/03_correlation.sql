-- Correlation performance indexes
-- Safe to run on existing databases

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_log_entries_id_processed ON log_entries(id, processed_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_log_entries_source_ip_timestamp ON log_entries(source_ip, log_timestamp) WHERE source_ip IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_log_entries_malicious_timestamp ON log_entries(is_malicious, processed_at DESC) WHERE is_malicious = true;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_log_entries_source_type ON log_entries(source_type);

-- Alert correlation indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_context_gin ON alerts USING GIN ((context));
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_attack_type ON alerts ((context->>'attack_type')) WHERE context->>'attack_type' IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_rule_name ON alerts (rule_name);

-- Vacuum analyze for optimal query planning
VACUUM ANALYZE log_entries;
VACUUM ANALYZE alerts;
