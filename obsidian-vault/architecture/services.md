# Services Hub #service

> Each service has its own page in `services/` — see [[architecture/topology]] for the full diagram.

## Quick lookup

| Service | Layer | Image / Build |
|---|---|---|
| [[architecture/services/postgres]] | data | `postgres:16-alpine` |
| [[architecture/services/redis]] | data | `redis:7-alpine` |
| [[architecture/services/nats]] | data | `nats:2.10-alpine` |
| [[architecture/services/api]] | platform | `services/api` |
| [[architecture/services/correlation]] | platform | `services/correlation` (k8s `1.3.0`) |
| [[architecture/services/ingestion]] | platform | `services/ingestion` |
| [[architecture/services/enrichment]] | platform | `services/enrichment` |
| [[architecture/services/sandbox]] | platform | `services/sandbox` |
| [[architecture/services/learner]] | platform | `services/learner` (k8s `1.0.0`) |
| [[architecture/services/icap]] | edge | `services/icap` |
| [[architecture/services/logserver]] | edge | `services/logserver` |
| [[architecture/services/frontend]] | edge | `frontend/` |
| [[architecture/services/nginx]] | edge | `nginx:1.25-alpine` |
| [[architecture/services/prometheus]] | obs | `prom/prometheus:v2.48.0` |
| [[architecture/services/grafana]] | obs | `grafana/grafana:10.2.0` |

## Dependency order on cold start

1. postgres → redis → nats
2. api (needs all three)
3. ingestion, enrichment, correlation, icap, logserver (need api + their data deps)
4. sandbox (needs api + nats)
5. frontend (needs api)
6. nginx (needs api + frontend)
7. prometheus + grafana (independent)

## Leader election (k8s only)

- `ti-correlation` uses k8s Lease `ti-platform-correlation-leader` in namespace `ti`.
- Only the leader runs the periodic loops (reputation refresh, embedding refresh, baseline flush).
- See [[runbooks/redeploy-correlation]] for restart implications.

## See also
- [[architecture/topology]] — full topology diagrams
- [[architecture/data-flow]] — pipeline detail
- [[architecture/schema]] — DB shape
