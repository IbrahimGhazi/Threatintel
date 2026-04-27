-- url_reputation schema upgrade for the enriched URL-intel pipeline.
--
-- Adds:
--   * etld1              — registrable (eTLD+1) domain, indexed for the
--                          domain-reputation aggregate used in scoring.
--   * ml_probability_raw — pre-calibration XGBoost score, retained so we
--                          can re-fit the calibrator on production data
--                          without re-predicting.
--   * feed_verdict       — JSON blob of external-feed hits
--                          (urlhaus / openphish / dbl / gsb).
--   * dns_features       — JSON blob of DNS enrichment output
--                          (nxdomain, a_count, asn, country, ...).
--
-- Backwards compatible with the pre-enrichment service: all new columns
-- are NULL-able and the service tolerates NULL.
--
-- Apply:
--     psql -U tiplatform -d tiplatform -f 20260423_url_intel_enrich.sql
--
-- Rollback:
--     BEGIN;
--       DROP INDEX IF EXISTS url_reputation_etld1_idx;
--       ALTER TABLE url_reputation
--         DROP COLUMN IF EXISTS etld1,
--         DROP COLUMN IF EXISTS ml_probability_raw,
--         DROP COLUMN IF EXISTS feed_verdict,
--         DROP COLUMN IF EXISTS dns_features;
--     COMMIT;

BEGIN;

ALTER TABLE url_reputation
    ADD COLUMN IF NOT EXISTS etld1              text,
    ADD COLUMN IF NOT EXISTS ml_probability_raw real,
    ADD COLUMN IF NOT EXISTS feed_verdict       jsonb,
    ADD COLUMN IF NOT EXISTS dns_features       jsonb;

-- Index used by ReputationCache.domain_reputation() — an aggregate over
-- all rows sharing the same eTLD+1. Partial index skips NULLs so it
-- stays small while the backfill is in progress.
CREATE INDEX IF NOT EXISTS url_reputation_etld1_idx
    ON url_reputation (etld1)
    WHERE etld1 IS NOT NULL;

-- Best-effort backfill of etld1 from the existing `domain` column.
-- This is a PURELY-SQL heuristic: strips `www.` and keeps the last two
-- labels. It is correct for .com/.net/.org etc. and WRONG for ccTLDs
-- like .co.uk. The Python service will overwrite any row with the
-- tldextract-correct value on its first touch, so wrong rows self-heal
-- within the cache TTL. Run the offline backfill script for a proper
-- one-shot fix (see scripts/backfill_etld1.py when present).
UPDATE url_reputation
   SET etld1 = CASE
         WHEN domain IS NULL OR domain = '' THEN NULL
         WHEN domain ~ '^[0-9a-fA-F:.\[\]]+$'      -- IP literal passthrough
              AND (domain ~ '^(\d+\.){3}\d+$'
                   OR domain ~ ':') THEN domain
         ELSE regexp_replace(
                  regexp_replace(lower(domain), '^www\.', ''),
                  '^.*\.([^.]+\.[^.]+)$', '\1'
              )
       END
 WHERE etld1 IS NULL;

-- Note: no backfill for ml_probability_raw / feed_verdict / dns_features.
-- They populate naturally on each URL's next classification. Historical
-- rows keep the same ml_probability (calibrated ≈ raw pre-upgrade, since
-- the calibrator was previously an identity map).

COMMIT;
