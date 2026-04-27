# Postgres Schema Map #schema #gotcha

Init scripts live in `infra/postgres/init/*.sql`, applied by helm chart on first launch. Manual applications happen via:

```sh
kubectl -n ti exec ti-postgresql-0 -- sh -c \
  "echo {b64} | base64 -d | PGPASSWORD={pw} psql -U tiplatform -d tiplatform"
```

## Key tables

### `log_entries` ⚠️ #gotcha
- ~1.5M rows under firewall load
- **`source_ip`** is top-level (NOT `src_ip`)
- **`log_timestamp`** is often NULL for firewall — use **`processed_at`** for time filters
- `parsed` JSONB carries: `dst_ip`, `dst_port`, `protocol`, `action`, `bytes_total`, `application`, `category`

### `alerts`
- Created when correlation rule fires AND `reputation_detection_mode=enforce` AND score crosses threshold

### `reputation_shadow_events` (M1/M2 audit trail)
- Always written when scorer runs (regardless of mode)
- `would_fire` boolean: would this have fired in enforce mode?
- Useful 3-min sanity check:
  ```sql
  SELECT rule_name,
         COUNT(*) FILTER (WHERE would_fire) AS would_fire,
         COUNT(*) AS total
  FROM reputation_shadow_events
  WHERE created_at > NOW() - INTERVAL '3 minutes'
  GROUP BY rule_name ORDER BY total DESC;
  ```

### `platform_settings`
- Hot-reloaded key/value config. Common keys:
  - `reputation_detection_mode` — `off` / `shadow` / `enforce`
  - `learned_similarity_weight` (`+1.0`) / `learned_familiarity_weight` (`-0.8`)
  - `learned_similarity_far_cos` (`0.30`) / `learned_similarity_near_cos` (`0.85`)
  - per-rule thresholds and floors

### `entity_embedding` (M3) #milestone
- `(entity_type, entity_value)` primary key — types: `host`, `destination`
- `vector DOUBLE PRECISION[]` (32-dim, L2-normalized) — pgvector NOT installed, native array used
- 5176 rows currently (58 hosts + 5118 destinations)

### `embedding_model` (M3)
- Single row keyed by `model_name='host_v1'`
- Stores trained AE weights (W1/b1/W2/b2 as float arrays), feature_means, feature_stds
- Used to encode new (host, hour-window) feature vectors at scoring time *if* needed

### `host_baseline` / `port_baseline`
- Adaptive baseline learning: per-source-IP normal port/protocol/destination distributions
- z-score thresholding for anomaly suggestions

### `host_overrides`
- Per-source-IP rule modifiers (suppress, lower threshold, force-flag, etc.)

## pgvector status #gotcha

```sql
SELECT * FROM pg_available_extensions WHERE name='vector';
-- 0 rows
```

Not available in this postgres image. M3 pivoted to `DOUBLE PRECISION[]` with cosine math done Python-side. Scale (~100 hosts × ~10k destinations) is small enough that this is a non-issue.
