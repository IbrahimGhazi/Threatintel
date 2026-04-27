# nginx #service

**Image:** `nginx:1.25-alpine`
**Role:** Reverse proxy / TLS termination. Single external entrypoint for the analyst-facing UI.
**External ports:** 80, 443
**Networks:** `ti-internal` + `ti-dmz`

## Routes
- `/api/*` → [[architecture/services/api]]
- `/*` → [[architecture/services/frontend]]
- TLS via mounted `infra/nginx/ssl/`

## Config
- `infra/nginx/nginx.conf`
- `infra/nginx/conf.d/`

## Health
`nginx -t` (config syntax check)
