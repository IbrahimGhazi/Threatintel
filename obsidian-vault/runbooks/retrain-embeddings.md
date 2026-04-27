# Retrain M3 Embeddings #runbook

The [[milestones/M3-embeddings|learner]] is a one-shot job. Run on demand or via CronJob (TODO).

## Quick retrain (re-runs against current 7-day window)

```sh
# On the server VM:
JOB="ti-learner-seed-$(date +%s)"
kubectl -n ti run "$JOB" \
  --image=ti-platform/learner:1.0.0 \
  --image-pull-policy=IfNotPresent \
  --restart=Never \
  --overrides='{
    "spec": {
      "containers": [{
        "name": "'"$JOB"'",
        "image": "ti-platform/learner:1.0.0",
        "imagePullPolicy": "IfNotPresent",
        "env": [
          {"name": "POSTGRES_PASSWORD",
           "valueFrom": {"secretKeyRef": {"name": "ti-secrets", "key": "POSTGRES_PASSWORD"}}},
          {"name": "DATABASE_URL",
           "value": "postgresql://tiplatform:$(POSTGRES_PASSWORD)@ti-postgresql.ti.svc.cluster.local:5432/tiplatform"}
        ]
      }]
    }
  }'

# Watch
kubectl -n ti get pod "$JOB" -w
kubectl -n ti logs "$JOB" -f

# Cleanup
kubectl -n ti delete pod "$JOB"
```

## Tunable env vars

| Var | Default | Effect |
|---|---|---|
| `LEARNER_WINDOW_DAYS` | 7 | How much history to aggregate |
| `LEARNER_DIM_HIDDEN` | 32 | Embedding dimensionality |
| `LEARNER_MIN_HOST_SAMPLES` | 5 | Drop hosts with fewer hour-buckets |
| `LEARNER_MIN_DST_CALLERS` | 2 | Drop destinations called by fewer hosts |

## Verification (post-job)

```sql
-- Should show fresh updated_at
SELECT entity_type, COUNT(*), MAX(updated_at) FROM entity_embedding GROUP BY entity_type;

-- New model row
SELECT model_name, training_loss, sample_count, trained_at FROM embedding_model;
```

Wait up to 600s for correlation to pick up via the refresh loop. Marker:
```
ReputationScorer embeddings refreshed: hosts=N destinations=M far=0.30 near=0.85
```

## Common gotchas #gotcha

- **Wrong secret name** — must use `ti-secrets`, key `POSTGRES_PASSWORD`. The string `ti-platform-secret` does NOT exist in this cluster.
- **DB URL format** — `postgresql://`, NOT `postgresql+asyncpg://` (psycopg2 in learner, not SQLAlchemy).
- **Old failed pods linger** — clean up before re-running:
  ```sh
  kubectl -n ti delete pod -l run=ti-learner-seed --all 2>/dev/null
  ```

## See also
- [[milestones/M3-embeddings]] for what this trains
- [[runbooks/deploy-pattern]] for image build pattern (when learner code changes)
