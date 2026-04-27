# M4+ Roadmap #milestone

Open. Things floated but not yet planned in detail.

## Near-term (extends M3)

- **CronJob the learner** — currently launched ad-hoc via [[runbooks/retrain-embeddings]]. Convert to a `kind: CronJob` running nightly at 02:00 local.
- **Drift detection** — embed each host's *most recent 24h* and compare to its 7-day centroid. Cosine drop > 0.4 → suggestion-engine ticket.
- **Per-user embeddings** — currently per-source-IP. Pull `user` field from auth logs, embed users separately from hosts.
- **Embedding sample-count gating** — currently `MIN_HOST_SAMPLES=5`, `MIN_DST_CALLERS=2`. Tune after a week of production data.

## Medium

- **SimCLR-style contrastive** — replace plain AE with positive pairs (same host, adjacent hours) vs negative pairs (different hosts). Likely better separation.
- **Time-of-day decomposition** — current features include hour_sin/cos, but the model treats all hours of one host as one entity. Maybe split: weekday-business-hours vs nights/weekends.
- **Embedding-aware suggestion engine** — for each suggestion, show the source-IP's nearest-neighbour hosts to help the analyst judge.

## Far

- **Federated learning across customer banks** — same architecture, hashed source identifiers, central learner training on aggregated features.
- **Active learning** — feed analyst feedback (alert was real / was noise) back into the loss function.

> Pull from this file when planning a new milestone.
