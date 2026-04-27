# learner #service

**Build:** `services/learner`
**Image (k8s):** `ti-platform/learner:1.0.0`
**Role:** Trains the [[milestones/M3-embeddings|tiny autoencoder]] over 7 days of logs and writes per-host + per-destination embedding vectors.
**Lifecycle:** One-shot job (k8s `kubectl run --restart=Never`). Not in docker-compose — k8s-only.
**Runtime:** ~30s end-to-end at current scale.

## Inputs
- [[architecture/services/postgres]] — reads `log_entries` (7-day window)

## Outputs
- [[architecture/services/postgres]] — writes `entity_embedding` (5,176 rows) + `embedding_model` (1 row with trained weights)

## Stack
- Python 3.12-slim base
- Pure numpy autoencoder (~2 MB, CPU-only, sub-ms inference)
- psycopg2 for Postgres
- No torch, no GPU, no LLM

## Pipeline
1. Aggregate per `(source_ip, hour)` → 41-feature row
2. Standardize (means/stds)
3. Train autoencoder 41→32→41, 200 epochs, lr 0.05, batch 64
4. Encode per-host = mean of hour-samples → L2-normalize
5. Destination centroid = mean of caller embeddings
6. Upsert to `entity_embedding`

## Tunable envs
| Var | Default |
|---|---|
| `LEARNER_WINDOW_DAYS` | 7 |
| `LEARNER_DIM_HIDDEN` | 32 |
| `LEARNER_MIN_HOST_SAMPLES` | 5 |
| `LEARNER_MIN_DST_CALLERS` | 2 |

## Consumed by
- [[architecture/services/correlation]] — reads `entity_embedding` every 600s and pushes vectors into the [[milestones/M1-reputation|reputation scorer]]

## See also
- [[runbooks/retrain-embeddings]] — how to fire a manual run
- [[milestones/M4-roadmap]] — CronJob conversion is a planned followup
