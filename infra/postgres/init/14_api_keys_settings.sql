-- BYO API keys — extends platform_settings with encryption + audit columns.
--
-- Idempotent: safe to run on fresh installs (via init dir) and on existing
-- clusters (via `kubectl exec ti-postgresql-0 -- psql ... -f`).
--
-- Resolution order at consumer (ingestion / sandbox / etc.):
--   1. DB value (decrypted with MASTER_ENCRYPTION_KEY)  →  if non-empty, use this
--   2. Env var fallback                                  →  legacy .env behaviour
--   3. None                                              →  feature disabled

ALTER TABLE platform_settings
    ADD COLUMN IF NOT EXISTS value_encrypted BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE platform_settings
    ADD COLUMN IF NOT EXISTS updated_by TEXT;

-- Seed the 7 supported provider rows. Empty values mean "no UI override —
-- consumer falls back to env var". value_encrypted=TRUE so that future PUTs
-- store ciphertext; the empty string is fine without a Fernet token.
INSERT INTO platform_settings (key, value, value_encrypted, description) VALUES
    ('api_key.abuseipdb',     '', TRUE, 'AbuseIPDB API key — https://www.abuseipdb.com/api'),
    ('api_key.otx',           '', TRUE, 'AlienVault OTX API key — https://otx.alienvault.com'),
    ('api_key.threatfox',     '', TRUE, 'abuse.ch ThreatFox API key — https://threatfox.abuse.ch'),
    ('api_key.malwarebazaar', '', TRUE, 'abuse.ch MalwareBazaar API key — https://bazaar.abuse.ch'),
    ('api_key.urlhaus',       '', TRUE, 'abuse.ch URLHaus API key — https://urlhaus.abuse.ch'),
    ('api_key.openphish',     '', TRUE, 'OpenPhish API key — https://openphish.com'),
    ('api_key.virustotal',    '', TRUE, 'VirusTotal API key — https://www.virustotal.com/api')
ON CONFLICT (key) DO NOTHING;
