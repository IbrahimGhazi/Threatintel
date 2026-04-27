# enrichment #service

**Build:** `services/enrichment`
**Role:** Adds geo / ASN / reverse-DNS context to events.
**Workers:** `ENRICHMENT_WORKERS` (default 4)
**Memory:** 512 MB

## Inputs
- [[architecture/services/nats]] — subscribes to raw event subjects

## Outputs
- [[architecture/services/postgres]] — enriched event rows
- [[architecture/services/nats]] — re-publishes on `enriched.*` subjects
- [[architecture/services/redis]] (DB 2) — geoip lookup cache

## Static data
- MaxMind GeoLite2-City: `/geoip/GeoLite2-City.mmdb`
- MaxMind GeoLite2-ASN: `/geoip/GeoLite2-ASN.mmdb`
(Mounted from `geoip-data` volume.)

## Used by
- [[architecture/services/correlation]] consumes the `enriched.*` stream.
