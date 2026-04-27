# prometheus #service

**Image:** `prom/prometheus:v2.48.0`
**Role:** Metrics scraping & TSDB.
**Internal port:** 9090
**Retention:** `PROMETHEUS_RETENTION` (default 30d)

## Scrapes
All platform services exposing `/metrics`:
- [[architecture/services/api]]
- [[architecture/services/correlation]]
- [[architecture/services/ingestion]]
- [[architecture/services/enrichment]]
- [[architecture/services/sandbox]]
- [[architecture/services/icap]]
- [[architecture/services/logserver]]

## Read by
- [[architecture/services/grafana]]

## Config
`infra/prometheus/prometheus.yml`
