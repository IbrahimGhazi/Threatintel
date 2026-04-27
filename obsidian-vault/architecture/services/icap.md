# icap #service

**Build:** `services/icap`
**Role:** ICAP server — web proxies (Squid, F5, etc.) call it to scan HTTP traffic for malicious content.
**Internal port:** 1344 (ICAP)
**External port:** 1344 (exposed on `ti-dmz`)
**Memory:** 512 MB

## Inputs (external)
- ICAP REQMOD / RESPMOD requests from a web proxy

## Outputs
- [[architecture/services/api]] — verdict lookups + sandbox triggers
- [[architecture/services/redis]] (DB 3) — verdict cache (avoid repeat scanning)
- Optional: triggers [[architecture/services/sandbox]] via api when a file download is intercepted

## Key envs
`API_URL`, `API_KEY`, `ICAP_HOST`, `ICAP_PORT`, `ICAP_MAX_CONNECTIONS`, `SANDBOX_ENABLED`, `SANDBOX_URL`

## Networks
On both `ti-internal` and `ti-dmz` — DMZ exposure required for upstream proxies to reach it.
