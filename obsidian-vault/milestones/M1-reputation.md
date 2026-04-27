# M1 — Reputation Scorer #milestone

**Status:** ✅ Live in production

Weighted reputation score per (src_ip, dst) pair. Composes deterministic signals into one number; rules consult it instead of (or alongside) hard-coded thresholds.

## Inputs (DEFAULT_WEIGHTS)

| Signal | Weight | Source |
|---|---|---|
| `base` | `+1.0` | always |
| `whitelist` | `-1.0` | `/whitelist/active` |
| `baseline_match` | `-1.0` | host_baseline |
| `peer_baseline` | `-0.8` | other hosts' baselines |
| `tranco` | `-0.8` | Tranco Top 100k |
| `rfc1918` | `-0.5` | private IP space |
| `ti_match` | `+2.0` | `/indicators/lookup/...` |
| `nrd` | `+1.5` | newly-registered domain |
| `high_entropy` | `+0.8` | DGA-likely |
| `long_label` | `+0.5` | suspicious label length |
| `uncommon_tld` | `+0.5` | rare TLD |
| `unusual_rrtype` | `+0.5` | rare DNS RR |
| `first_seen_recent` | `+0.5` | first-seen <24h |
| `unusual_port` | `+0.3` | non-baseline port |
| **`learned_similarity`** | **`+1.0`** | [[milestones/M3-embeddings]] |
| **`learned_familiarity`** | **`-0.8`** | [[milestones/M3-embeddings]] |

Final score is clamped, then compared against per-rule thresholds in `platform_settings`.

## Hot reload

`platform_settings`-stored weights override DEFAULT_WEIGHTS every 60s. Marker: `Reputation detection mode=...`.

## Files

- `services/correlation/reputation.py` — scorer class
- `services/correlation/main.py` — `_load_reputation_config()` / `_reputation_settings_refresh_loop()`
- `infra/postgres/init/12_reputation.sql` — schema + seed weights

See also: [[milestones/M2-enforce]], [[milestones/M3-embeddings]].
