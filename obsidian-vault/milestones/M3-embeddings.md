# M3 — Behavioural Embeddings #milestone

**Status:** ✅ Live in production (correlation `1.3.0`, learner `1.0.0`)
**Deployed:** 2026-04-24

> Hosts / users / destinations live as learned vectors, not feature tables.

## Architecture

```
log_entries ──▶ ti-learner (one-shot job, nightly)
                  │
                  ├─ aggregate per (host, hour) → 41 features
                  ├─ standardize (means/stds in embedding_model)
                  ├─ train tiny autoencoder 41→32→41 (200 epochs, lr=0.05, bs=64)
                  ├─ encode per host → mean of hour-samples → L2-normalize
                  ├─ destination centroid = mean of caller embeddings
                  └─ upsert to entity_embedding
                          │
                          ▼
              ti-correlation (every 600s)
                  └─ ReputationScorer.update_embeddings(host_vecs, dst_vecs)
                          │
                          ▼
            score_destination() per event:
              learned_similarity factor = f(cosine(host_emb, dst_centroid))
                near (0.85+) → +learned_familiarity (discount)
                far  (0.30-) → +learned_similarity (bump)
                linear interp between
```

## Numbers (2026-04-24 seed run)

| Metric | Value |
|---|---|
| Hour-buckets aggregated | 1,257 |
| Feature dim | 41 |
| Hidden dim | 32 |
| Initial loss | 9.44 |
| Final loss | **0.59** |
| Host embeddings | 58 |
| Destination centroids | 5,118 |
| Total upserts | 5,176 |

## Why these choices

- **pgvector unavailable** → `DOUBLE PRECISION[]` + Python-side cosine. Scale is small enough.
- **Pure numpy AE** → ~2 MB, sub-ms inference, no GPU/torch dependency. CPU-only nightly job.
- **Tanh hidden + L2-normalized output** → stable cosine geometry.
- **Destination = caller centroid** → "where do hosts that touch this dest usually look like?" If a new host's embedding is close, they fit the normal-caller profile.
- **far_cos=0.30 / near_cos=0.85** → conservative: only the very-close get a meaningful discount, only the very-far get a meaningful bump.

## Files

- `infra/postgres/init/13_embeddings.sql` — schema + 4 setting keys
- `services/learner/learn_embeddings.py` — full training pipeline
- `services/learner/Dockerfile` — python:3.12-slim + numpy + psycopg2
- `services/correlation/reputation.py:278` — `update_embeddings()`
- `services/correlation/reputation.py:304+` — `_cosine()` + `_learned_similarity_factor()`
- `services/correlation/main.py:1393` — `_load_entity_embeddings()`
- `services/correlation/main.py:1429` — `_entity_embedding_refresh_loop()` (600s)

## Verification markers

In `kubectl logs deploy/ti-correlation`:
- `ReputationScorer loaded: ... 'learned_similarity': 1.0, 'learned_familiarity': -0.8`
- `Reputation detection mode=enforce`
- `ReputationScorer embeddings refreshed: hosts=58 destinations=5118 far=0.30 near=0.85` (every 600s)

## What's next ([[milestones/M4-roadmap]])

- Daily CronJob for the learner (currently manual one-shot)
- Per-user embeddings (not just per-source-IP)
- Drift detection: alert if a host's daily embedding moves > X cosine from its 7-day centroid
- Embedding-aware suggestion engine

See also: [[runbooks/retrain-embeddings]], [[runbooks/deploy-pattern]].
