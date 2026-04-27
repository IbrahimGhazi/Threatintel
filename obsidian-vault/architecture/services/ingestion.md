# ingestion #service

**Build:** `services/ingestion`
**Role:** Polls external threat-intel feeds and publishes new indicators into the platform.
**Memory:** 512 MB

## External sources
- AbuseIPDB
- AlienVault OTX
- ThreatFox
- MalwareBazaar
- URLHaus
- OpenPhish

(All toggleable via `*_ENABLED` envs; API keys via `*_API_KEY`.)

## Inputs (external)
- HTTPS poll, interval = `FEED_POLL_INTERVAL` (default 3600s)

## Outputs
- [[architecture/services/postgres]] — `indicators` table
- [[architecture/services/nats]] — publishes `ti.feeds.*` for downstream subscribers
- [[architecture/services/redis]] (DB 1) — feed dedup / cursor state

## Called by
- [[architecture/services/correlation]] indirectly via [[architecture/services/api]] `/indicators/lookup/...` — those lookups hit data this service curated.

## Key envs
`DATABASE_URL`, `REDIS_URL`, `NATS_URL`, `*_API_KEY`, `FEED_POLL_INTERVAL`
