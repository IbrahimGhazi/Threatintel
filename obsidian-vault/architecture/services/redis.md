# redis #service

**Image:** `redis:7-alpine`
**Role:** Cache, dedup, leader-election state, sandbox progress.
**Internal port:** 6379
**Network:** `ti-internal`
**Memory:** 768 MB (LRU eviction at 512 MB)

## DB allocation
| DB | Consumer |
|---|---|
| 0 | [[architecture/services/api]] |
| 1 | [[architecture/services/ingestion]] |
| 2 | [[architecture/services/enrichment]] |
| 3 | [[architecture/services/icap]] |
| 4 | [[architecture/services/correlation]] |
| 5 | [[architecture/services/sandbox]] |

> ⚠️ Don't mix DB indices across services — each gets its own to keep TTLs / dedup keys isolated.

## Read/written by
All of the above. Persisted via AOF (`appendonly yes`, `appendfsync everysec`).

## In k8s
Released as `ti-redis-master`. Secret: `ti-secrets` key `REDIS_PASSWORD`.
