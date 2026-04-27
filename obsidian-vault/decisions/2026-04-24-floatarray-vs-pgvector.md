# 2026-04-24 — Use `DOUBLE PRECISION[]` instead of pgvector for embeddings

**Status:** accepted
**Context:** [[milestones/M3-embeddings]] needs to store 32-dim embeddings for ~5k-10k entities. Original plan used `VECTOR(32)` from pgvector for native cosine ops.
**Options considered:**
1. Install pgvector extension into the bitnami postgres image
2. Use native `DOUBLE PRECISION[]` and do cosine in Python
3. Add a separate vector store (Qdrant, Weaviate)
**Decision:** Option 2 — native arrays + Python-side cosine.
**Consequences:**
- ➕ Zero infra change. `pg_available_extensions` shows pgvector unavailable in this build; installing it would fork the image.
- ➕ At our scale (~100 hosts × ~10k destinations), Python-side cosine is sub-ms.
- ➖ When we 10x scale, we'll need to revisit. Cosine join across 100k destinations starts to bite.
- ➖ No native ANN index — full scan every refresh. Acceptable for 5k-row tables.
**Revisit when:** entity_embedding > 100k rows, or we need real-time nearest-neighbour at score-time.
