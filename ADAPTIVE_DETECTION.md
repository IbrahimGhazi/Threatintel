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

1. **Learning** normal behavior per host/user from live log data.
2. **Detecting** anomalies relative to the learned baseline (not a fixed number).
3. **Suggesting** threshold adjustments when rules fire repeatedly for benign behavior.
4. **Auto-applying** accepted suggestions after a confidence threshold and review window.

---

## Architecture

```
log ingestion
     │
     ▼
  parsing / normalization  (services/correlation/parser.py)
     │
     ▼
  baseline learning  ──────────────────────────────────────────┐
  (services/correlation/baseline.py)                           │
     │                                                         │
     ▼                                                         │
  detection engine  (behavioral rules in correlation service)  │
     │                                                         │
     ├─ anomaly? ──► escalate alert severity                   │
     │                                                         │
     ▼                                                         │
  suggestion engine  (services/correlation/suggestion_engine.py)
     │
     ▼
  alert pipeline → PostgreSQL → dashboard
     │
     ▼
  adaptive rule changes (auto-apply after review window)
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

### Entity granularity

Baselines are maintained at three levels simultaneously:

| Level      | entity_type | entity_value example |
|------------|-------------|---------------------|
| Host       | `host`      | `192.168.1.50`      |
| /24 subnet | `subnet`    | `192.168.1.0/24`    |
| User       | `user`      | `jsmith`            |
| Global     | `global`    | `*`                 |

### Tracked metrics

| Metric                      | Category         | Description                        |
|-----------------------------|------------------|------------------------------------|
| `connection_count_per_hour` | `connection`     | Outbound connections per hour      |
| `unique_destinations`       | `connection`     | Unique destination IPs per window  |
| `failed_auth_per_hour`      | `auth`           | Failed login attempts per hour     |
| `rdp_connections`           | `lateral_movement` | RDP connections initiated        |
| `smb_connections`           | `lateral_movement` | SMB/CIFS connections initiated   |
| `dns_qpm`                   | `dns`            | DNS queries per minute             |
| `unique_domains_per_hour`   | `dns`            | Unique domains queried per hour    |
| `beacon_interval_std`       | `c2`             | Variance in outbound interval (C2) |

### Anomaly detection

An observation is flagged as anomalous when its **z-score** exceeds the
configured threshold (default: 3.0):

```
z = (observed − mean) / std_dev
anomalous = |z| > Z_SCORE_THRESHOLD
```

Anomaly detection is **disabled** until `BASELINE_MIN_SAMPLES` observations
have been collected for that entity (default: 20), preventing false positives
during the learning phase.

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

1. The correlation service calls `SuggestionEngine.record_alert()` whenever a
   behavioral rule fires for an entity.
2. The engine tracks an in-memory trigger counter per `(rule_name, entity_value)`.
3. Once the trigger count reaches `SUGGESTION_MIN_TRIGGERS` (default: 5), the
   engine creates or updates a `tuning_suggestions` row in PostgreSQL.

### Confidence model

Confidence grows asymptotically using:

```
confidence = 0.20 + 0.70 × (1 − e^(−triggers / 30))
```

This means:
- 5 triggers  → ~21 % confidence
- 15 triggers → ~40 % confidence
- 30 triggers → ~55 % confidence
- 60 triggers → ~73 % confidence
- 90 triggers → ~82 % confidence
- 120 triggers → ~87 % confidence (crosses AUTO_APPLY_CONFIDENCE)

### Suggested threshold

When baseline data is available, the engine suggests:

```
new_threshold = mean + 3 × std_dev
```

This is the upper edge of the normal range for that entity.

### Configuration

| Environment variable               | Default | Description                                          |
|------------------------------------|---------|------------------------------------------------------|
| `SUGGESTION_MIN_TRIGGERS`          | `5`     | Triggers before a suggestion is generated            |
| `BASELINE_AUTO_APPLY_CONFIDENCE`   | `0.85`  | Confidence [0–1] that schedules auto-apply           |
| `BASELINE_AUTO_APPLY_DELAY_HOURS`  | `24`    | Hours to wait before auto-applying                   |

---

## Automatic Rule Adaptation

When a suggestion reaches the confidence threshold, its `auto_apply_at` is set
to `NOW() + BASELINE_AUTO_APPLY_DELAY_HOURS`.  The `SuggestionEngine`
background loop (runs every 5 minutes) processes due suggestions:

1. Marks the suggestion `status = 'auto_applied'`.
2. Writes a full audit record to `adaptive_rule_changes` including:
   - `previous_value` — the threshold before the change
   - `new_value` — the applied threshold
   - `applied_by = 'system_auto'`
   - `reason` — human-readable explanation with confidence and trigger count

### Safeguards (hard-coded, cannot be overridden)

| Safeguard | Description |
|-----------|-------------|
| Protected rule patterns | Rules containing `ti_match`, `threat_intel`, `malicious_ip`, `c2_beaconing`, `known_bad`, `ioc_match`, or `signature` are **never** auto-adjusted |
| Protected severities | `critical`-severity alerts are **never** suppressed |
| Audit trail | Every change is written to `adaptive_rule_changes` and visible in the dashboard |
| Revertibility | Every applied change can be reverted by an analyst; reverted changes reset the suggestion to `pending` |

---

## Database Schema

Three new tables are created by `infra/postgres/init/05_adaptive_baseline.sql`:

### `behavioral_baselines`

Stores per-entity running statistics flushed from the correlation service.

| Column          | Type      | Description                          |
|-----------------|-----------|--------------------------------------|
| `entity_type`   | varchar   | `host`, `subnet`, `user`, `global`   |
| `entity_value`  | varchar   | IP, CIDR, username, or `*`           |
| `metric`        | varchar   | Metric name                          |
| `category`      | varchar   | Detection category                   |
| `mean`          | float     | Current running mean                 |
| `std_dev`       | float     | Current standard deviation           |
| `sample_count`  | integer   | Number of observations               |
| `p95`           | float     | 95th percentile estimate             |

### `tuning_suggestions`

One row per rule+entity pair in `pending` state; updated as confidence grows.

| Column           | Type      | Description                                         |
|------------------|-----------|-----------------------------------------------------|
| `suggestion_type`| varchar   | `increase_threshold`, `add_allowlist`, etc.         |
| `confidence`     | float     | 0.0 – 1.0, grows with trigger count                |
| `trigger_count`  | integer   | Times the pattern was observed                      |
| `status`         | varchar   | `pending` → `accepted/rejected/auto_applied`        |
| `auto_apply_at`  | timestamptz | Scheduled auto-apply time (set once confidence ≥ threshold) |
| `current_value`  | jsonb     | Snapshot of current threshold/config               |
| `suggested_value`| jsonb     | Recommended new threshold/config                   |

### `adaptive_rule_changes`

Immutable audit log of every applied change.

| Column          | Type      | Description                          |
|-----------------|-----------|--------------------------------------|
| `applied_by`    | varchar   | `system_auto` or analyst username    |
| `previous_value`| jsonb     | State before the change              |
| `new_value`     | jsonb     | State after the change               |
| `reverted_at`   | timestamptz | When reverted (NULL if active)     |

---

## API Endpoints

All endpoints require `X-API-Key` authentication.

| Method | Path                                    | Description                          |
|--------|-----------------------------------------|--------------------------------------|
| GET    | `/api/tuning/stats`                     | Summary counts for dashboard header  |
| GET    | `/api/tuning/suggestions`               | List suggestions (filterable)        |
| POST   | `/api/tuning/suggestions/{id}/accept`   | Analyst accepts a suggestion         |
| POST   | `/api/tuning/suggestions/{id}/reject`   | Analyst rejects; clears auto-apply   |
| GET    | `/api/tuning/changes`                   | Audit log of applied changes         |
| POST   | `/api/tuning/changes/{id}/revert`       | Revert an applied change             |
| GET    | `/api/tuning/baselines`                 | List behavioral baselines            |

Query parameters for `/suggestions` and `/baselines`:
- `status` — filter by `pending`, `accepted`, `rejected`, `auto_applied`
- `category` — filter by detection category
- `entity_value` — filter baselines by host IP or username
- `limit` / `offset` — pagination

---

## Dashboard

Navigate to **Tuning** in the sidebar (or `/tuning`).

The page has three tabs:

### Suggestions tab
- Lists tuning suggestions ordered by pending-first, then confidence descending.
- Each card shows the rule, affected entity, rationale, threshold comparison,
  confidence bar with color coding (Low / Medium / High), trigger count,
  auto-apply countdown, and Accept / Reject buttons.
- Status filters: Pending / Auto-Applied / Accepted / Rejected / All.

### Applied Changes tab
- Audit log of every rule change with `applied_by`, reason, and timestamp.
- **Revert** button on each non-reverted change.

### Baselines tab
- Per-entity metric statistics: mean, std dev, min, p95.
- Maturity label: **Learning** (< 50 samples), **Building** (50–199), **Stable** (≥ 200).

---

## Integration with the Correlation Service

To wire the baseline and suggestion engines into an existing correlation rule,
add calls like:

```python
from baseline import BaselineEngine
from suggestion_engine import SuggestionEngine

baseline_engine   = BaselineEngine(db_session_factory=async_session_factory)
suggestion_engine = SuggestionEngine(db_session_factory=async_session_factory)

# On startup:
await baseline_engine.load_from_db()
asyncio.create_task(suggestion_engine.run_auto_apply_loop())

# Inside a detection rule handler:
is_anom, z_score = baseline_engine.record("host", src_ip, "dns_qpm", query_count)

if is_anom:
    # Raise alert as usual, then register with suggestion engine
    baseline_info = baseline_engine.get_baseline("host", src_ip, "dns_qpm")
    await suggestion_engine.record_alert(
        rule_name         = "dns_query_spike",
        severity          = "medium",
        entity_type       = "host",
        entity_value      = src_ip,
        category          = "dns",
        current_threshold = {"threshold": DNS_QUERY_THRESHOLD, "window_secs": 60},
        baseline_info     = baseline_info,
    )

# Periodically (or on every batch):
await baseline_engine.maybe_flush()
```
