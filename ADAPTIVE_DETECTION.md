# Adaptive Detection & Automatic Rule Tuning

This document describes the behavioral baseline learning system and adaptive
rule-tuning pipeline added to the TI Platform SIEM.

---

## Overview

Traditional SIEM systems use **static thresholds** for behavioral detections
(e.g., "alert if DNS queries exceed 20/min"). This causes false positives
when normal activity varies across hosts — a corporate DNS server, a developer
workstation, and a kiosk all have very different baseline behaviors.

The adaptive system solves this by:

1. **Learning** normal behavior per host/user from live log data using window-rate metrics.
2. **Detecting** anomalies relative to the learned baseline (not a fixed number).
3. **Suggesting** threshold adjustments when rules fire repeatedly for benign behavior.
4. **Auto-applying** high-confidence suggestions after a configurable review window.
5. **Enforcing** accepted suggestions directly into correlation rule thresholds.

---

## Architecture

```
log ingestion
     │
     ▼
  parsing / normalization  (services/correlation/parser.py)
     │
     ├──► baseline learning ──────────────────────────────────────────────┐
     │    (services/correlation/baseline.py)                              │
     │    records window-rate metrics per host/subnet/user                │
     │                                                                    │
     ▼                                                                    │
  detection engine  (behavioral rules — services/correlation/rules.py)   │
     │    thresholds patched live from rule_overrides table               │
     │                                                                    │
     ├─ anomaly? ──► escalate alert severity                              │
     │                                                                    │
     ▼                                                                    ▼
  suggestion engine  (services/correlation/suggestion_engine.py)
     │  trigger counters persisted in DB; survive service restarts
     │
     ▼
  alert pipeline → PostgreSQL → dashboard
     │
     ▼
  auto-apply loop (every 5 min) → adaptive_rule_changes audit log
     │
     ▼
  _rule_overrides_refresh_loop (every 60 s) patches rules.py globals
```

---

## Behavioral Baseline Engine

**File:** `services/correlation/baseline.py`

### Algorithm

Uses **Welford's online algorithm** for incremental mean and variance — the
engine never needs to store all historical values, making it memory-efficient
regardless of data volume.

```
On each new observation x:
  n    = n + 1
  δ    = x − mean
  mean = mean + δ / n
  δ₂   = x − mean
  M₂   = M₂ + δ × δ₂

variance = M₂ / (n − 1)
std_dev  = √variance
```

**Reservoir sampling** (Algorithm R, up to 200 values per metric) provides a
p95 estimate without full storage.

### What is recorded

Metrics are recorded as **window-rate values** — the size of the current
sliding EventStore window for a host on each event — rather than flat 1.0
per-event flags. This produces meaningful mean/std_dev distributions.

```python
# Example: for every log from src_ip, record the current window sizes
n_connections = len(store.by_src[src_ip])
n_unique_dsts = len({e.dst_ip for e in src_events if e.dst_ip})
baseline_engine.record("host", src_ip, "connection_count_per_hour", n_connections)
baseline_engine.record("host", src_ip, "unique_destinations",       n_unique_dsts)
```

### Entity granularity

Baselines are maintained at four levels simultaneously:

| Level      | entity_type | entity_value example |
|------------|-------------|----------------------|
| Host       | `host`      | `192.168.1.50`       |
| /24 subnet | `subnet`    | `192.168.1.0/24`     |
| User       | `user`      | `jsmith`             |
| Global     | `global`    | `*`                  |

### Tracked metrics

| Metric                      | Category           | Description                              |
|-----------------------------|--------------------|------------------------------------------|
| `connection_count_per_hour` | `connection`       | Outbound connection window size          |
| `unique_destinations`       | `connection`       | Unique destination IPs in window         |
| `unique_ports_per_window`   | `port_scan`        | Unique dest ports in window              |
| `failed_auth_per_hour`      | `auth`             | Failed login attempts in window          |
| `rdp_connections`           | `lateral_movement` | RDP connections in window                |
| `smb_connections`           | `lateral_movement` | SMB/CIFS connections in window           |
| `dns_qpm`                   | `dns`              | DNS queries per minute                   |
| `unique_domains_per_hour`   | `dns`              | Unique domains queried per hour          |
| `beacon_interval_std`       | `c2`               | Variance in outbound interval (C2)       |
| `outbound_connection_rate`  | `c2`               | Outbound connection rate                 |

### Anomaly detection

An observation is flagged as anomalous when its **z-score** exceeds the
configured threshold (default: 3.0):

```
z = (observed − mean) / std_dev
anomalous = |z| > Z_SCORE_THRESHOLD
```

Anomaly detection is **disabled** until `BASELINE_MIN_SAMPLES` observations
have been collected (default: 20), preventing false positives during learning.

### Persistence

- In-memory store for low-latency access
- Flushed to `behavioral_baselines` in PostgreSQL every `BASELINE_FLUSH_INTERVAL` seconds
- Restored from DB at service startup via `load_from_db()`

### Configuration

| Environment variable         | Default | Description                                            |
|------------------------------|---------|--------------------------------------------------------|
| `BASELINE_MIN_SAMPLES`       | `20`    | Samples required before anomaly detection activates    |
| `BASELINE_Z_SCORE_THRESHOLD` | `3.0`   | Standard deviations above mean to flag as anomalous    |
| `BASELINE_FLUSH_INTERVAL`    | `300`   | Seconds between flushing in-memory stats to PostgreSQL |

---

## Suggestion Engine

**File:** `services/correlation/suggestion_engine.py`

### How suggestions are generated

1. The correlation service calls `SuggestionEngine.record_alert()` on every
   behavioral incident (before the cooldown check, so deduped triggers still
   count toward confidence).
2. The engine tracks an in-memory trigger counter per `(rule_name, entity_value)`.
3. **On service restart**, `load_triggers_from_db()` seeds the in-memory counters
   from pending suggestions in the DB so the count never regresses to zero.
4. On every upsert the engine reconciles the in-memory counter with the DB value:
   if the DB is higher (e.g. after a crash), it adopts `db_count + 1`.
5. Once the trigger count reaches `SUGGESTION_MIN_TRIGGERS` (default: 5), the
   engine creates or updates a `tuning_suggestions` row in PostgreSQL.

### Confidence model

Confidence grows asymptotically using:

```
confidence = 0.20 + 0.70 × (1 − e^(−triggers / 30))
```

This means:

| Triggers | Confidence |
|----------|-----------|
| 5        | ~21 %     |
| 15       | ~40 %     |
| 30       | ~55 %     |
| 60       | ~73 %     |
| 90       | ~82 %     |
| 120      | ~87 %     |
| 150      | ~89 %     |

The maximum is capped at **90 %** (never 100 %).

### Suggested threshold

When baseline data is available, the engine suggests:

```
new_threshold = mean + 3 × std_dev
```

This is the upper edge of the normal distribution for that entity.

### Auto-apply scheduling

When confidence crosses `auto_apply_confidence` (default 0.85), the engine sets:

```
auto_apply_at = NOW() + auto_apply_delay_hours
```

`auto_apply_at` is stored as a **datetime object** (not an ISO string) so
asyncpg can bind it correctly to the `TIMESTAMPTZ` column.

The background loop (`run_auto_apply_loop`, runs every 5 minutes) finds rows
where `status = 'pending' AND auto_apply_at <= NOW()` and marks them
`auto_applied` — the confidence threshold is **not** re-checked at apply time
(it was validated when the time was scheduled, so floating-point values like
0.8497 are not incorrectly blocked).

### Runtime settings

Both `auto_apply_delay_hours` and `auto_apply_confidence` are read from the
`platform_settings` table every 60 seconds, so changes in the UI take effect
without a service restart.

### Configuration

| Environment variable               | Default | Description                                          |
|------------------------------------|---------|------------------------------------------------------|
| `SUGGESTION_MIN_TRIGGERS`          | `5`     | Triggers before a suggestion is generated            |
| `BASELINE_AUTO_APPLY_CONFIDENCE`   | `0.85`  | Initial confidence threshold (overridable via UI)    |
| `BASELINE_AUTO_APPLY_DELAY_HOURS`  | `24`    | Initial review window in hours (overridable via UI)  |

---

## Automatic Rule Adaptation

### Auto-apply flow

When a suggestion's `auto_apply_at` elapses the background loop:

1. Marks `status = 'auto_applied'`, sets `applied_at = NOW()`
2. Writes an audit record to `adaptive_rule_changes`:
   - `previous_value` — threshold before the change (JSONB)
   - `new_value` — applied threshold (JSONB)
   - `applied_by = 'system_auto'`
   - `reason` — e.g. "Auto-applied after 1h with no response. confidence=87%, triggers=120"

### Threshold enforcement

When an analyst **accepts** a suggestion (or the system auto-applies one):

1. The `suggested_value.threshold` is written to the `rule_overrides` table.
2. `_apply_rule_overrides()` in `main.py` reads the table and patches the
   corresponding module-level variable in `rules.py` (e.g. sets
   `rules.REPEATED_CONN_ATTEMPTS_MIN = 45`).
3. `_rule_overrides_refresh_loop()` re-runs this every 60 seconds so the
   correlation service picks up changes without restart.

Rule name → threshold variable mapping:

| Rule name                      | Module variable                |
|--------------------------------|-------------------------------|
| `brute_force`                  | `BRUTE_FORCE_THRESHOLD`       |
| `port_scan`                    | `PORT_SCAN_PORTS_MIN`         |
| `host_discovery`               | `HOST_DISCOVERY_TARGETS_MIN`  |
| `service_scan`                 | `SERVICE_SCAN_HOSTS_MIN`      |
| `repeated_connection_attempts` | `REPEATED_CONN_ATTEMPTS_MIN`  |
| `blocked_connections`          | `BLOCKED_CONN_THRESHOLD`      |
| `c2_beaconing`                 | `C2_CONN_MIN`                 |
| `lateral_movement`             | `LATERAL_HOSTS_MIN`           |

### Safeguards (hard-coded, cannot be overridden)

| Safeguard | Description |
|-----------|-------------|
| Protected rule patterns | Rules containing `ti_match`, `threat_intel`, `malicious_ip`, `c2_beaconing`, `known_bad`, `ioc_match`, or `signature` are **never** auto-adjusted |
| Protected severities | `critical`-severity alerts are **never** suppressed |
| Audit trail | Every change is written to `adaptive_rule_changes` and visible in the dashboard |
| Revertibility | Every applied change can be reverted by an analyst; reverted changes reset the suggestion to `pending` |

---

## Database Schema

### `behavioral_baselines` — `05_adaptive_baseline.sql`

Stores per-entity running statistics flushed from the correlation service.

| Column          | Type        | Description                          |
|-----------------|-------------|--------------------------------------|
| `entity_type`   | varchar     | `host`, `subnet`, `user`, `global`   |
| `entity_value`  | varchar     | IP, CIDR, username, or `*`           |
| `metric`        | varchar     | Metric name                          |
| `category`      | varchar     | Detection category                   |
| `mean`          | float       | Current running mean                 |
| `std_dev`       | float       | Current standard deviation           |
| `sample_count`  | integer     | Number of observations               |
| `p95`           | float       | 95th percentile estimate             |
| `last_updated`  | timestamptz | When last flushed from memory        |

### `tuning_suggestions` — `05_adaptive_baseline.sql`

One row per `(rule_name, entity_value)` pair in `pending` state; updated as confidence grows.

| Column            | Type        | Description                                         |
|-------------------|-------------|-----------------------------------------------------|
| `suggestion_type` | varchar     | `increase_threshold`, `add_allowlist`, etc.         |
| `confidence`      | float       | 0.0 – 1.0, grows with trigger count                |
| `trigger_count`   | integer     | Times the pattern was observed                      |
| `status`          | varchar     | `pending` → `accepted/rejected/auto_applied`        |
| `auto_apply_at`   | timestamptz | Scheduled auto-apply time (datetime, not string)    |
| `current_value`   | jsonb       | Snapshot of current threshold/config                |
| `suggested_value` | jsonb       | Recommended new threshold/config (includes `basis`) |

### `adaptive_rule_changes` — `05_adaptive_baseline.sql`

Immutable audit log of every applied change.

| Column           | Type        | Description                          |
|------------------|-------------|--------------------------------------|
| `applied_by`     | varchar     | `system_auto` or analyst username    |
| `previous_value` | jsonb       | State before the change              |
| `new_value`      | jsonb       | State after the change               |
| `reverted_at`    | timestamptz | When reverted (NULL if active)       |
| `reverted_by`    | varchar     | Who reverted it                      |

### `platform_settings` — `06_platform_settings.sql`

Runtime-configurable key/value pairs read by the suggestion engine every 60 s.

| Key                      | Default | Range       | Description                          |
|--------------------------|---------|-------------|--------------------------------------|
| `auto_apply_delay_hours` | `24`    | 1 – 168     | Review window before auto-apply      |
| `auto_apply_confidence`  | `0.85`  | 0.50 – 0.99 | Confidence threshold for scheduling  |

### `rule_overrides` — `07_rule_overrides.sql`

Analyst-accepted threshold changes applied to correlation rules at runtime.

| Column          | Type        | Description                                     |
|-----------------|-------------|-------------------------------------------------|
| `rule_name`     | text        | Correlation rule name                           |
| `entity_type`   | text        | `global` (org-wide) or specific entity type    |
| `entity_value`  | text        | `*` for global or specific IP/username          |
| `threshold`     | numeric     | New threshold value for the rule                |
| `window_secs`   | integer     | New time window for the rule (optional)         |
| `suggestion_id` | uuid        | FK to originating suggestion                    |

---

## API Endpoints

All endpoints require `X-API-Key` authentication.

### Tuning

| Method | Path                                    | Description                                          |
|--------|-----------------------------------------|------------------------------------------------------|
| GET    | `/api/tuning/stats`                     | Summary counts for dashboard header                  |
| GET    | `/api/tuning/config`                    | Current auto-apply settings                          |
| PATCH  | `/api/tuning/config`                    | Update review window / confidence threshold          |
| GET    | `/api/tuning/suggestions`               | List suggestions (filterable by status, category)    |
| POST   | `/api/tuning/suggestions/{id}/accept`   | Accept; writes threshold to rule_overrides           |
| POST   | `/api/tuning/suggestions/{id}/reject`   | Reject; clears auto-apply schedule                   |
| GET    | `/api/tuning/changes`                   | Audit log of applied changes                         |
| POST   | `/api/tuning/changes/{id}/revert`       | Revert an applied change                             |
| GET    | `/api/tuning/baselines`                 | List behavioral baselines                            |

### Indicators

| Method | Path                                    | Description                                          |
|--------|-----------------------------------------|------------------------------------------------------|
| POST   | `/api/indicators/{id}/false-positive`   | Mark as false positive (deactivates indicator)       |
| DELETE | `/api/indicators/{id}`                  | Permanently delete an indicator                      |

### Statistics

| Method | Path                                    | Description                                          |
|--------|-----------------------------------------|------------------------------------------------------|
| GET    | `/api/stats/alerts-timeline`            | Alert counts by severity bucketed by hour or day     |

Query parameters for `/stats/alerts-timeline`:
- `days` — look-back window (1–90, default 14)
- `interval` — `hour` or `day` bucket size (default `day`)

---

## Dashboard — Tuning Page (`/tuning`)

### Stats header

Four cards: **Pending**, **Auto-Applied**, **Baselines**, **Changes**.

### Review window control

A slider (1–168 h) + number input lets analysts set the review window in real
time. Saving immediately reschedules all pending suggestions. The safeguards
note dynamically reflects the current setting.

### Suggestions tab

- Ordered pending-first, then by confidence descending.
- Each card shows: category badge, suggestion type, status, auto-apply
  countdown, rule name, entity, rationale, threshold comparison
  (current → suggested with `mean+3σ` basis label), confidence bar
  (Low / Medium / High), trigger count, Accept / Reject buttons.
- Status filters: **Pending / Auto-Applied / Accepted / Rejected / All**.

### Applied Changes tab

- Audit log of every rule change: rule name, entity, reason, `applied_by`, timestamp.
- **Revert** button on each active change.

### Baselines tab

- Per-entity metric statistics: mean, std dev, min, p95, sample count.
- Maturity label: **Learning** (< 50), **Building** (50–199), **Stable** (≥ 200).

---

## Dashboard — Alerts Page (`/alerts`)

### Alerts-over-time chart

A stacked bar chart at the top of the Alerts page shows alert volume over time,
color-coded by severity (critical / high / medium / low).

- Range switcher: **24h / 7d / 14d / 30d**
- Hover tooltip shows per-severity breakdown for each bucket
- A note reminds analysts that accepting tuning suggestions reduces alert volume
- Data source: `GET /api/stats/alerts-timeline`

---

## Dashboard — Indicator Detail Page (`/indicators/{id}`)

Two action buttons are available on every indicator detail card:

| Button | Action |
|--------|--------|
| **False Positive** | Marks the indicator as a false positive and deactivates it (`POST /indicators/{id}/false-positive`) |
| **Delete** | Shows a confirm dialog then permanently removes the indicator (`DELETE /indicators/{id}`) |

---

## Integration with the Correlation Service

The complete integration is in `services/correlation/main.py`. Key startup sequence:

```python
# 1. Create SQLAlchemy async session factory alongside asyncpg pool
sa_engine = create_async_engine("postgresql+asyncpg://...", ...)
session_factory = async_sessionmaker(sa_engine, expire_on_commit=False)

# 2. Instantiate engines
baseline_engine        = BaselineEngine(db_session_factory=session_factory)
suggestion_engine_inst = SuggestionEngine(db_session_factory=session_factory)

# 3. Restore prior state from DB
await baseline_engine.load_from_db()         # restores baselines
await suggestion_engine_inst.load_triggers_from_db()  # seeds trigger counters
await _apply_rule_overrides(pool)            # patches rules.py thresholds

# 4. Start background tasks
asyncio.create_task(_rule_overrides_refresh_loop(pool))   # every 60 s
asyncio.create_task(_baseline_flush_loop())               # every FLUSH_INTERVAL s
asyncio.create_task(suggestion_engine_inst.run_auto_apply_loop())  # every 5 min
```

Per-log recording (in `handle_log`):

```python
# Record window-rate metrics — NOT flat 1.0 per event
src_events = list(store.by_src.get(log.src_ip, []))
baseline_engine.record("host", log.src_ip, "connection_count_per_hour", float(len(src_events)))
baseline_engine.record("host", log.src_ip, "unique_destinations",
                       float(len({e.dst_ip for e in src_events if e.dst_ip})))
# ... etc for failed_auth, rdp, smb, user metrics

# Record suggestion trigger for every behavioral incident
await suggestion_engine_inst.record_alert(
    rule_name    = incident.attack_type,
    severity     = incident.severity,
    entity_type  = "host",
    entity_value = incident.source_ip,
    category     = _rule_to_category(incident.attack_type),
    baseline_info = baseline_engine.get_baseline(
        "host", incident.source_ip, "connection_count_per_hour"
    ),
)
```

---

## Known Limitations

- Rule overrides are **global** (apply to all entities). Per-entity threshold
  overrides are stored in the DB but not yet consumed at the per-entity level
  in rules.py — all entities use the same patched threshold.
- Baselines in memory are lost on a hard kill; the last flushed state is
  restored from DB. The flush interval (default 300 s) is the max data loss window.
- The `beacon_interval_std` and `outbound_connection_rate` metrics are defined
  in `METRIC_CATEGORY` but not yet extracted in `handle_log` — they require
  time-series analysis across the EventStore which is planned for a future iteration.
