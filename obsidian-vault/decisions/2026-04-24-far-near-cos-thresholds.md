# 2026-04-24 — far_cos=0.30 / near_cos=0.85 for learned similarity

**Status:** accepted
**Context:** [[milestones/M3-embeddings]] maps cosine similarity into a reputation contribution. Need thresholds at the "far" (suspicious) and "near" (familiar) ends, with linear interpolation between.
**Options considered:**
1. Tight band (0.50 / 0.75) — many events affected, more model influence
2. Wide band (0.30 / 0.85) — only the very-far / very-near contribute, conservative
3. Sigmoid mapping (no hard thresholds)
**Decision:** Wide band 0.30 / 0.85. Tunable via `platform_settings.learned_similarity_far_cos` / `..._near_cos`.
**Consequences:**
- ➕ Minimal disruption to existing M1/M2 thresholds during M3 rollout
- ➕ Conservative on first deploy — easier to widen later than to narrow under fire
- ➖ Most events sit in the linear-interp zone with small contribution; the model "matters" mostly at the tails
- ➖ Unclear how often we'll see cosines > 0.85 in real bank traffic. Need observation period.
**Revisit when:**
- 1 week of production data — measure cosine distribution per event
- If `would_fire` rate is too noisy (widen) or too quiet (narrow)
