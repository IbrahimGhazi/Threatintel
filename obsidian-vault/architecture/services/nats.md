# nats #service

**Image:** `nats:2.10-alpine` with JetStream (`-js`)
**Role:** Message bus. All async event flow goes through here.
**Internal port:** 4222 (client), 8222 (monitor)
**Network:** `ti-internal`

## Publishers
- [[architecture/services/api]]
- [[architecture/services/ingestion]]
- [[architecture/services/enrichment]]
- [[architecture/services/sandbox]]

## Subscribers
- [[architecture/services/enrichment]]
- [[architecture/services/correlation]]
- [[architecture/services/sandbox]]

## Subjects (typical)
- `logs.firewall.*` — raw firewall events from logserver→api→nats
- `logs.parsed.*` — after parsing
- `enriched.*` — geo/asn enriched
- `ti.feeds.*` — ingestion publishes new indicators
- `sandbox.verdict.*` — analysis results

## In k8s
Released as `ti-nats`. Secret: `ti-secrets` key `NATS_PASSWORD`. User: `tiplatform`.

## See also
- [[architecture/data-flow]] for end-to-end pipeline
