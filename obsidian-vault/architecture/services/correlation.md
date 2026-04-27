# correlation #service

**Build:** `services/correlation`
**Image (k8s):** `ti-platform/correlation:1.3.0`
**Role:** Detection brain. Runs rules, reputation scorer, M3 embeddings hook, baseline learning, suggestion engine.
**Memory:** 512 MB
**Leader-elected** in k8s (only one replica runs the periodic loops).

## Inputs
- [[architecture/services/nats]] — log/enriched event stream
- [[architecture/services/postgres]] — settings, baselines, embeddings, schemas
- [[architecture/services/redis]] (DB 4) — dedup + leader lease state
- [[architecture/services/api]] — TI indicator + whitelist HTTP lookups

## Outputs
- [[architecture/services/postgres]] — `alerts`, `reputation_shadow_events`, baselines, suggestions

## Hot-reload loops
See [[architecture/data-flow]] table. Headline:
- Reputation config (60s) → [[milestones/M1-reputation]]
- **Entity embeddings (600s)** → [[milestones/M3-embeddings]]

## Sub-modules
- `main.py` — pipeline + leader + loops
- `reputation.py` — [[milestones/M1-reputation|scorer]] + cosine factor
- `rules/*.py` — service_scan, dns_tunneling, repeated_conn, host_discovery, ti_match, etc.

## Key envs
`DATABASE_URL`, `NATS_URL`, `REDIS_URL`, `API_URL`, `API_KEY`, `KNOWN_DEVICE_IPS`,
`ALERT_MIN_CONFIDENCE`, `BASELINE_*`, `SUGGESTION_MIN_TRIGGERS`

## Runbooks
- [[runbooks/redeploy-correlation]]
- [[runbooks/flip-detection-mode]]
