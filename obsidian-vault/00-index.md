# TI Platform Knowledge Vault

Defensive threat-intelligence platform protecting banks. This vault is the single source of truth for architecture, decisions, runbooks, and incidents.

## How to use

- Every Claude session reads from and writes to this vault.
- Notes use `[[wikilinks]]` so Obsidian's graph view shows relationships.
- Open Obsidian's **Graph view** (Ctrl+G) to see the whole project as a network.
- Tags: `#service`, `#runbook`, `#decision`, `#milestone`, `#incident`, `#schema`, `#gotcha`.

---

## 🎯 For selling / first overview
- **[[product/overview]]** — pitch-deck-friendly, simple diagrams, value props

## 🗺 For understanding the architecture
- **[[architecture/topology]]** — full system diagram + per-service catalogue
- [[architecture/services|legacy services hub]]
- [[architecture/data-flow]]
- [[architecture/schema]]

### Services (one page each)
| Layer | Services |
|---|---|
| Edge | [[architecture/services/nginx]] · [[architecture/services/logserver]] · [[architecture/services/icap]] · [[architecture/services/frontend]] |
| Platform | [[architecture/services/api]] · [[architecture/services/correlation]] · [[architecture/services/ingestion]] · [[architecture/services/enrichment]] · [[architecture/services/sandbox]] · [[architecture/services/learner]] |
| Data | [[architecture/services/postgres]] · [[architecture/services/redis]] · [[architecture/services/nats]] |
| Observability | [[architecture/services/prometheus]] · [[architecture/services/grafana]] |

## 🚀 Milestones (intelligence layers)
- [[milestones/M1-reputation]] — weighted reputation scorer ✅
- [[milestones/M2-enforce]] — shadow → enforce flip ✅
- [[milestones/M3-embeddings]] — host/destination autoencoder vectors ✅ *(latest)*
- [[milestones/M4-roadmap]] — what's next

## 🔧 Runbooks
- [[runbooks/deploy-pattern]]
- [[runbooks/redeploy-correlation]]
- [[runbooks/flip-detection-mode]]
- [[runbooks/retrain-embeddings]]
- [[runbooks/connect-server-vm]]

## 🧠 Decisions (ADRs)
See [[decisions/README]].

## 🚨 Incidents
See [[incidents/README]].

## 📅 Daily notes
See [[daily/README]].

---

## Constants

| Thing | Value |
|---|---|
| Server VM | `192.168.3.210` (`tiuser`) |
| Firewall | `192.168.3.19` (set in `KNOWN_DEVICE_IPS`) |
| k3d cluster | `ti-k8s` |
| Namespace | `ti` |
| Postgres pod | `ti-postgresql-0` |
| Postgres user | `tiplatform` |
| Postgres password | _set in secret `ti-secrets` key `POSTGRES_PASSWORD` — see local `.env` or your secrets manager_ |
| Database URL pattern | `postgresql://tiplatform:$(POSTGRES_PASSWORD)@ti-postgresql.ti.svc.cluster.local:5432/tiplatform` |

> ⚠️ The cluster secret is **`ti-secrets`** (NOT `ti-platform-secret` — that name does not exist).
