# 2026-04-24 — Wrong secret name in M3 deploy script

**Severity:** sev3 (deploy hung, no production impact)
**Detected:** ~10 min into [[milestones/M3-embeddings|M3 deploy]] when seed pod stayed in `Pending` and `kubectl describe pod` showed `Error: secret "ti-platform-secret" not found` x12.
**Resolved:** ~5 min after detection by relaunching with the correct envFrom + direct env synthesis.
**Root cause:** `deploy_m3_embeddings.py` referenced `ti-platform-secret` but the actual cluster secret is **`ti-secrets`**. The correlation deployment doesn't use `envFrom` at all — it pulls `POSTGRES_PASSWORD` via `valueFrom.secretKeyRef` and synthesizes `DATABASE_URL` from POSTGRES_* vars using k8s expansion (`postgresql+asyncpg://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@...`).
**Fix:** Replaced envFrom with direct `env` carrying:
- `POSTGRES_PASSWORD` → `secretKeyRef: {name: ti-secrets, key: POSTGRES_PASSWORD}`
- `DATABASE_URL` → `postgresql://tiplatform:$(POSTGRES_PASSWORD)@ti-postgresql.ti.svc.cluster.local:5432/tiplatform`
**Followups:**
- ✅ Documented correct values in [[00-index]] (Constants table)
- ✅ Documented in [[runbooks/retrain-embeddings]] gotcha section
- ✅ Documented in [[runbooks/deploy-pattern]] gotcha list
- ⚠️ Note: learner uses psycopg2, NOT SQLAlchemy — DB URL must be `postgresql://`, NOT `postgresql+asyncpg://`
