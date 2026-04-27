# Threat Intelligence Platform

A self-hosted threat-intelligence and detection platform for internal
SOC teams. Ingests open-source feeds (AbuseIPDB, AlienVault OTX,
ThreatFox, MalwareBazaar, OpenPhish, URLhaus), correlates them against
firewall/proxy logs in real time, and surfaces alerts through a
Next.js dashboard with sandbox triage, indicator enrichment, and
external dynamic lists (EDL) for firewall feedback.

> **Status**: deployed in production for one customer. Single-tenant
> for now; multi-tenant work is on the roadmap (see
> `obsidian-vault/milestones/M4-roadmap.md`).

## What's in this repo

| Directory | What |
|---|---|
| `services/` | Python backend microservices (FastAPI, asyncio workers). |
| `frontend/` | Next.js 14 dashboard (React, Tailwind, SWR). |
| `infra/` | Postgres init SQLs, NGINX reverse-proxy, Prometheus, Grafana. |
| `deploy/k8s/charts/ti-platform/` | Helm chart for k8s/k3d deployment. |
| `ml/` | Indicator-embedding training pipeline. |
| `obsidian-vault/` | Architecture docs, ADRs, runbooks, milestones. |
| `docs/SETUP.md` | **Start here if you want to deploy this.** |

## Architecture (one-liner per service)

```
                       ┌───────── Next.js frontend ─────────┐
                       │  /api/*  →  api  →  postgres        │
                       └─────────────────┬───────────────────┘
                                         │
   feeds ──→ ingestion ──┐               │
   logs  ──→ logserver ──┼──→ NATS ──→ correlation ──→ alerts
                         │               │
                         └──→ enrichment ┘
                                         │
                              icap proxy ─┘   sandbox (samples)
```

Full diagrams: `obsidian-vault/architecture/topology.md` and
`obsidian-vault/architecture/data-flow.md`.

## Quick start

You need: Docker, k3d (or any k3s/k8s ≥1.27), kubectl, Helm 3, Python 3.11+.

```bash
git clone https://github.com/IbrahimGhazi/Threatintel.git
cd Threatintel
cp .env.example .env             # then EDIT every change-me-* value
# follow docs/SETUP.md from "Step 1" — do NOT skip the build-arg section
```

The setup guide is mandatory reading. The frontend has a build-time
gotcha (`NEXT_PUBLIC_API_KEY` is inlined into JavaScript at
`docker build` time, not read at runtime) that will silently produce a
"Could not connect to the API server" message in the browser if you
miss it. SETUP.md walks through it step by step.

## Bring-Your-Own API keys

Threat-feed credentials (AbuseIPDB, OTX, ThreatFox, MalwareBazaar,
URLhaus, OpenPhish, VirusTotal) can be supplied two ways:

1. **At deploy time** via `.env` / k8s Secret.
2. **At runtime** through `Settings → API Keys` in the UI. Values are
   encrypted at rest with the `MASTER_ENCRYPTION_KEY` Fernet key and
   stored in the `platform_settings` table. The UI shows only the last
   four characters; plaintext never round-trips through the browser.

DB-stored keys take precedence over `.env` values; clearing a DB entry
falls back to `.env`. Services pick up changes on next pod restart.

## Documentation

The single source of truth is the Obsidian vault. Open it in
[Obsidian](https://obsidian.md/) by pointing at `obsidian-vault/`.
Highlights:

- `00-index.md` — vault entry point.
- `architecture/services/*.md` — one note per service.
- `runbooks/` — operational procedures (deploy, recover, retrain).
- `decisions/` — ADRs explaining why things are the way they are.
- `incidents/` — postmortems for production incidents.
- `milestones/` — roadmap and shipping log.

## Development

There is a docker-compose-flavored `Makefile` at the root for local
non-k8s development (`make up`, `make logs`, etc.). It references
`docker-compose.yml`, which is **not in the repo** — the production
deployment path is k3d + Helm. The Makefile is kept for the
single-developer "I just want to hack on the API" workflow; treat it
as legacy until that compose file is restored.

For the standard k3d-based workflow, see `docs/SETUP.md`.

## License

Proprietary — internal use only. Contact the maintainer before
redistributing.

## Maintainer

Ibrahim Ghazi · [github.com/IbrahimGhazi](https://github.com/IbrahimGhazi)
