# api #service

**Build:** `services/api`
**Role:** REST surface. Auth, indicator lookup, whitelist, suggestions, sandbox triggers, alerts CRUD.
**Internal port:** 8000
**Health:** `GET /health`
**Memory:** 1 GB

## Reads from
- [[architecture/services/postgres]] (DATABASE_URL)
- [[architecture/services/redis]] (DB 0, sandbox progress)

## Writes to
- [[architecture/services/postgres]] — alerts, indicators, whitelist, suggestions
- [[architecture/services/nats]] — publishes events
- [[architecture/services/redis]] — sandbox progress

## Called by
- [[architecture/services/correlation]] — `/indicators/lookup/...`, `/whitelist/active`
- [[architecture/services/icap]] — verdict lookups
- [[architecture/services/logserver]] — log ingest endpoint
- [[architecture/services/sandbox]] — verdict push-back
- [[architecture/services/frontend]] — UI traffic
- [[architecture/services/nginx]] — reverse-proxied to here

## Key envs
`DATABASE_URL`, `REDIS_URL`, `NATS_URL`, `SECRET_KEY`, `API_KEY`, `KNOWN_DEVICE_IPS`, `SANDBOX_ENABLED`

## See also
- [[milestones/M1-reputation]] — scorer reads `/whitelist/active` from here
- [[product/overview]]
