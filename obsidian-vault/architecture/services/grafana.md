# grafana #service

**Image:** `grafana/grafana:10.2.0`
**Role:** Dashboards over [[architecture/services/prometheus]] metrics.
**Internal port:** 3000 (mapped to host 3001)

## Inputs
- [[architecture/services/prometheus]] (datasource)

## Provisioning
- `infra/grafana/provisioning/` — auto-imported dashboards + datasources

## Auth
- Admin user: `GRAFANA_USER` (default `admin`)
- Admin pass: `GRAFANA_PASSWORD`
- Sign-up disabled
