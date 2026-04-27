# Data Flow #service

```
firewall logs ─▶ ti-ingest ─▶ NATS ─▶ ti-correlation ─▶ alerts
                                    │
                                    ├─▶ reputation_shadow_events (audit)
                                    ├─▶ host_baseline / port_baseline (learning)
                                    └─▶ entity_embedding (via ti-learner nightly)
```

## In-correlation pipeline (per log event)

1. **Subscribe** from NATS subject (firewall, dns, etc.)
2. **Parse** → `log_entries` row (top-level `source_ip`, JSONB `parsed.dst_ip/dst_port/protocol/action`)
3. **TI lookup** → ti-api `/indicators/lookup/{ip|domain}/{value}` → flagged set
4. **Reputation score** → [[milestones/M1-reputation]] weight-sum (now includes [[milestones/M3-embeddings|learned_similarity]])
5. **Rule eval** → service_scan, dns_tunneling, repeated_conn, host_discovery, ti_match
6. **Mode gate** ([[runbooks/flip-detection-mode|enforce/shadow/off]])
   - `shadow` → write to `reputation_shadow_events` only (audit)
   - `enforce` → also write to `alerts` if score crosses threshold
7. **Side-effects** → baseline updates, suggestion engine, optional API call to push back to firewall

## Hot-reload loops (correlation only)

| Loop | Interval | Source | Marker |
|---|---|---|---|
| Reputation config | 60s | `platform_settings` (mode/thresholds/weights) | `Reputation detection mode=...` |
| Learning config | 30s | `platform_settings` | `Learning config: mode=...` |
| Per-host overrides | 60s | `host_overrides` | `Per-host overrides loaded for N source IPs` |
| Whitelist | ~60s | `/whitelist/active` | (HTTP 200 in logs) |
| Recent domains | ~5m | DNS table | (none — quiet refresh) |
| **Entity embeddings** | **600s** | `entity_embedding` | `ReputationScorer embeddings refreshed: hosts=N destinations=M` |

See [[runbooks/retrain-embeddings]] for how to push a fresh model.
