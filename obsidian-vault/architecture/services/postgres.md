# postgres #service

**Image:** `postgres:16-alpine`
**Role:** Primary persistent store. Every stateful service writes here.
**Internal port:** 5432
**Network:** `ti-internal`
**Memory:** 2 GB

## Read by
- [[architecture/services/api]]
- [[architecture/services/ingestion]]
- [[architecture/services/enrichment]]
- [[architecture/services/correlation]]
- [[architecture/services/sandbox]]
- [[architecture/services/learner]]

## Init
- Schema files: `infra/postgres/init/*.sql` mounted at `/docker-entrypoint-initdb.d`
- Includes M3 schema: `13_embeddings.sql` ([[milestones/M3-embeddings]])

## Key tables
See [[architecture/schema]].

## In k8s
Deployed as `ti-postgresql-0` (StatefulSet) via bitnami chart. Secret: `ti-secrets` key `POSTGRES_PASSWORD`.
