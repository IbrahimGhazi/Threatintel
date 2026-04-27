# frontend #service

**Build:** `frontend/` (Next.js)
**Role:** Analyst-facing UI — alerts, indicators, suggestions, sandbox results, settings.
**Memory:** 512 MB
**Network:** `ti-internal` only (reached via [[architecture/services/nginx]])

## Inputs
- Browser via [[architecture/services/nginx]]

## Outputs
- [[architecture/services/api]] — REST calls (auth via `API_KEY`)

## Build args
- `NEXT_PUBLIC_API_URL` (default `/api`)
- `NEXT_PUBLIC_API_KEY`
