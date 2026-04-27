# M2 — Shadow → Enforce Flip #milestone

**Status:** ✅ Live in production (`reputation_detection_mode=enforce`)

[[milestones/M1-reputation|M1]] runs in two modes:
- **`shadow`** — scorer runs, writes to `reputation_shadow_events` only, no alerts gated
- **`enforce`** — scorer also blocks alerts whose score < threshold (suppressing noise)

The flip is the operational moment when M1 starts actually shaping production behaviour.

## How to flip

See [[runbooks/flip-detection-mode]] — a single `UPDATE platform_settings ... WHERE key='reputation_detection_mode'` plus a 75s wait for the 60s refresh loop to pick it up.

## Pre-flip baseline (24h alert volume)

| Rule | Count |
|---|---|
| service_scan | 74 |
| dns_tunneling | 58 |
| repeated_conn | 51 |
| host_discovery | 25 |
| ti_match | 25 |

## Post-flip behaviour

3-min snapshot directly after flip: 1245 shadow events, **0 would_fire**. Reputation scorer is suppressing noise in the bank's traffic profile — exactly the goal.

## What to watch after a flip

- `reputation_shadow_events` `would_fire` count over 24h vs pre-flip baseline
- `alerts` over 24h — should drop substantially
- correlation logs for `ERROR`/`CRITICAL`/`Traceback` (none expected)
- per-rule thresholds may need tuning if real attacks are getting suppressed

## Rollback

```sql
UPDATE platform_settings SET value='shadow' WHERE key='reputation_detection_mode';
```

Effective in <60s. No redeploy needed.
