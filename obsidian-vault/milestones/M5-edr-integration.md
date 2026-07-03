# M5 — EDR Integration #milestone

**Status:** 📝 proposed (research / design)
**Author:** platform
**Date:** 2026-07-03
**Targets:** Palo Alto **Cortex XDR** · Trend Micro **Vision One** (XDR)

> Extend the platform's enforcement reach from network appliances (firewalls, proxies via [[architecture/services/icap]] and EDL) down to the **endpoint**: push our malicious indicators into EDR blocklists, pull EDR detections back as first-class [[architecture/schema|alerts]], and drive endpoint response (isolate / block) from the correlation brain.

This is a design document, not shipped code. It captures the API surface, data mapping, and a phased rollout so the connector can be built against a stable spec.

---

## Why now / what exists today

The platform already treats **`edr` as a known telemetry source** but never talks *to* an EDR:

- `edr` is an accepted inbound log/URL origin — `services/url_intel_service.py:138` (`AnalyzeRequest.source`) and the frontend log-forwarding UI (`frontend/src/app/firewall/page.tsx:741`).
- Outbound indicator distribution today is **pull-only and unauthenticated**: the EDL text feed at `/api/edl/feed/<slug>` that firewalls poll (`frontend/src/app/edl/page.tsx`). Good for PAN-OS/FortiGate EDLs; EDRs want an **authenticated push** to their IOC APIs instead.
- There is one clean **authenticated outbound API-client** pattern to copy: `ml/external_feeds.py` → `_gsb_check` (Google Safe Browsing v4 REST POST, async, fail-open, TTL-cached).
- The enforcement/feedback slot already exists conceptually — `architecture/data-flow.md` step 7 notes an "optional API call to push back to firewall". EDR response actions hook the same slot.

No Cortex XDR / Trend / STIX / TAXII / MISP code exists anywhere yet — this is greenfield.

---

## Architecture — three flows

```
                    ┌─────────────────────────── TI PLATFORM ───────────────────────────┐
                    │                                                                    │
  active malicious  │   [[architecture/services/ingestion|ingestion]] ─▶ indicators ─┐   │
  indicators  ──────┼──▶ (same set that feeds EDL / url_reputation)   │              │   │
  (ip/domain/url/   │                                                 ▼              │   │
   hash)            │                                    ┌── edr connector (new) ──┐ │   │
                    │                                    │  push loop (reconcile)  │─┼───┼──▶ ①  EDR IOC / suspicious-object API
                    │                                    │  pull loop (poll)       │◀┼───┼─── ②  EDR detections / workbench alerts
                    │   [[architecture/services/correlation|correlation]] ◀────────┤  action dispatch        │ │   │
                    │        (enforce/shadow/off) ───────┼──────────────────────────┼─┼───┼──▶ ③  EDR response (isolate / block)
                    │                                    └──────────────────────────┘ │   │
                    │   pulled detections ─▶ [[architecture/services/api|api]] ▶ alerts / incidents          │   │
                    └────────────────────────────────────────────────────────────────┘
                              ①  outbound push        ②  inbound pull        ③  response action
```

| # | Flow | Direction | Source of truth | Sink |
|---|---|---|---|---|
| ① | **Outbound push** | platform → EDR | active indicators (EDL set / `url_reputation`) | EDR IOC list |
| ② | **Inbound pull** | EDR → platform | EDR detections / workbench alerts | our `Alert`/`Incident` schema |
| ③ | **Response action** | platform → EDR | `correlation` verdict (gated) | EDR isolate / block-hash |

---

## Vendor API reference

### Cortex XDR (Palo Alto Networks)

- **Base URL:** `https://api-{tenant-fqdn}/public_api/v1/` (the FQDN is shown in the tenant when the API key is created).
- **Auth:** two headers — `x-xdr-auth-id: {api_key_id}` + `Authorization: {api_key}`.
  - *Standard* auth sends the key directly.
  - *Advanced* auth (recommended) sends `Authorization = SHA256(api_key + nonce + timestamp)` plus `x-xdr-nonce` and `x-xdr-timestamp` headers — the raw key never crosses the wire.
- **License:** IOC push and most response actions require **Cortex XDR Pro** (per-endpoint or per-TB). Confirm scope on the API key (each endpoint has a required permission scope).

| Flow | Endpoint | Notes |
|---|---|---|
| ① Push IOCs | `POST /public_api/v1/indicators/insert_jsons` (bulk JSON; `insert_csv` also exists) | body `{"request_data": {"validate": true, "indicators": [ … ]}}`. Per-IOC fields: `indicator`, `type` = `HASH`\|`IP`\|`DOMAIN_NAME`\|`PATH`\|`FILENAME`, `severity`, `expiration_date` (**epoch ms**, or `Never`), `comment`, `reputation` = `GOOD`\|`BAD`\|`SUSPICIOUS`\|`UNKNOWN`, `reliability` (A–F), `class`, `vendors[]`. |
| ② Pull detections | `POST /public_api/v1/incidents/get_incidents`, `.../get_incident_extra_data`, `POST /public_api/v1/alerts/get_alerts_multi_events` | filter by `creation_time` / `modification_time` gte; page with `search_from`/`search_to`. Alerts carry MITRE tactic/technique. |
| ③ Response | `POST /public_api/v1/endpoints/isolate` · `/unisolate` · `/quarantine` · `/scan`; hash block via `/public_api/v1/hash_exceptions/…` (blocklist) | target by `endpoint_id` / `filters`. |

> ⚠️ **No native URL type.** Cortex indicators are HASH/IP/DOMAIN_NAME/PATH/FILENAME. Normalize our URL indicators to their **domain** (and/or the file hash if we have one) before push.

### Trend Micro Vision One

- **Base URL:** `https://api.xdr.trendmicro.com` — **region-specific**; pick per tenant: `api.eu`, `api.in`, `api.sg`, `api.au`, `api.jp`, `api.mea`, `api.usgov` (`.xdr.trendmicro.com`). API version **v3.0**.
- **Auth:** `Authorization: Bearer {api_key}`. Keys are minted in **Administration → API Keys** and are **role-scoped** — the service account needs *Suspicious Object Management* and *Response Management* roles.

| Flow | Endpoint | Notes |
|---|---|---|
| ① Push IOCs | `POST /v3.0/threatintel/suspiciousObjects` (User-Defined Suspicious Objects) | observables: **URL, domain, SHA-1, SHA-256, IP, sender email**. Per-object: `scanAction` = `block`\|`log`, `riskLevel` = `high`\|`medium`\|`low`, `expiredDateTime` (ISO-8601), `description`. |
| ① Push (bulk / reports) | `POST /v3.0/threatintel/intelligenceReports` | STIX 2.0/2.1, OpenIOC or CSV import. **Limits: ≤ 2000 objects and ≤ 1 MB per import.** |
| ② Pull detections | `GET /v3.0/workbench/alerts` (MITRE-tagged), `GET /v3.0/oat/detections` (Observed Attack Techniques) | filter with `startDateTime`/`endDateTime` + `TMV1-Filter` header; cursor pagination. |
| ③ Response | `POST /v3.0/response/endpoints/isolate` · `/restore`; collect-file; add-to-block-list | target by `endpointName` / `agentGuid`. Long-running tasks return a task id to poll. |

> Vision One has a **native URL/domain/sender-email** type, so our URL indicators map cleanly here (unlike Cortex).

---

## Data mapping

### ① Our indicators → EDR IOCs

Our model is IOC-generic: `Indicator.type/value` + `severity` + `confidence` + `sources[]` (`frontend/src/lib/api.ts:112-136`). Mapping:

| Our `type` | Cortex `type` | Trend observable |
|---|---|---|
| `ip` | `IP` | `ip` |
| `domain` | `DOMAIN_NAME` | `domain` |
| `url` | → normalize to `DOMAIN_NAME` (+ hash) | `url` (native) |
| `hash` (sha256/sha1/md5) | `HASH` | `fileSha256` / `fileSha1` |

| Our field | Cortex | Trend |
|---|---|---|
| `severity` (low/med/high/critical) | `severity` + `reputation=BAD` | `riskLevel` (low/medium/high) |
| `confidence` (0–1) | `reliability` (A–F bucket) | (informs `scanAction`: high-conf → `block`, else `log`) |
| age / `last_seen` | `expiration_date` = `last_seen + max_age` (epoch ms) | `expiredDateTime` = same, ISO-8601 |
| `sources[]` provenance | `comment` + `vendors[]` | `description` |

TTL mirrors the existing EDL `max_age_days` knob (`EDLConfig`, `frontend/src/lib/api.ts:639-651`) so stale IOCs auto-expire in the EDR instead of accumulating.

### ② EDR detections → our Alert schema

Both EDRs' detections carry MITRE ATT&CK context, which our `Alert`/`AlertContext` already models (`frontend/src/lib/api.ts:41-331`):

| Our `Alert` field | Cortex source | Trend source |
|---|---|---|
| `severity` | alert `severity` | workbench alert `severity` |
| `status` (open/ack/resolved/fp) | incident `status` | workbench `investigationStatus` |
| `rule_name` | alert `name` / `category` | `model` (detection model name) |
| `source_service` | `"cortex_xdr"` | `"trend_vision_one"` |
| `indicator_value/type` | alert artifacts (file/host/domain) | `impactScope` entities |
| `context.mitre_*` | `mitre_tactic_id` / `mitre_technique_id` | `matchedRules[].tactics/techniques` |
| affected hosts / event chain | `host_name` + `events[]` | `impactScope.entities` |

Ingested detections get `source_name="cortex_xdr"` / `"trend_vision_one"` on the provenance record — same `IndicatorSource` provenance mechanism used for feeds.

---

## Why these choices

- **Native per-vendor REST IOC APIs over a generic STIX/TAXII exporter (phase 1).** Both vendors have first-class REST for IOCs; native calls are lower-latency, give per-IOC ack/validation, and support expiration + response actions that a plain STIX feed can't. STIX/TAXII becomes attractive only at 3+ EDRs (see ADR revisit trigger). Trend's `intelligenceReports` STIX route is kept as the **bulk** path (respecting its 2000-object cap).
- **Reconciliation push loop, not event-per-IOC.** Mirror `ingestion`'s periodic feed loop + the EDL rebuild model: each cycle compute the desired active-IOC set and diff against what's already in the EDR (add new, expire dropped). Idempotent, survives restarts, and won't hammer the API on every indicator write.
- **Fail-open async client.** Copy `ml/external_feeds.py:_gsb_check` — an `httpx.AsyncClient` with timeout, retry, and a fail-open contract so an EDR outage never blocks the detection pipeline.
- **Response actions gated behind the existing detection mode.** Reuse `platform_settings.reputation_detection_mode` (`off`/`shadow`/`enforce`, see [[milestones/M2-enforce]], [[runbooks/flip-detection-mode]]). Isolate/block runs **shadow-first** — log "would isolate host X" without doing it — until an operator flips to enforce. Same safety rail proven for reputation blocking.
- **Single outbound source of truth.** The push set is the *same* active-indicator set that already feeds EDL — no parallel "EDR indicator" table. One place to reason about what we're asserting to the world.

---

## Where the code would live (not built here)

Follows the documented service layout ([[architecture/services|services hub]], [[architecture/topology]]):

- **`services/edr/`** — new connector alongside [[architecture/services/ingestion]]. Two loops (push reconcile, pull poll) + an on-demand action dispatcher. One `vendor` adapter per EDR behind a common interface (`push_iocs`, `pull_detections`, `isolate`, `block_hash`).
- **Push source:** the active-indicator query already backing EDL.
- **Pull sink:** post to [[architecture/services/api]] alert/incident ingestion (same path `icap`/`sandbox` use to push verdicts).
- **Response trigger:** [[architecture/services/correlation]] enforcement path (the "push back" slot in `architecture/data-flow.md`).
- **Secrets** in k8s secret **`ti-secrets`** (⚠️ *not* `ti-platform-secret` — see [[incidents/2026-04-24-ti-platform-secret-misreference]]), following the `*_API_KEY` + `*_ENABLED` convention from `ingestion`:
  - `CORTEX_XDR_ENABLED`, `CORTEX_XDR_FQDN`, `CORTEX_XDR_API_KEY_ID`, `CORTEX_XDR_API_KEY`
  - `TREND_VISION_ONE_ENABLED`, `TREND_VISION_ONE_REGION`, `TREND_VISION_ONE_API_KEY`
- Service-to-`api` auth reuses the existing `X-API-Key` scheme (`frontend/src/lib/api.ts:1-22`).

---

## Phased rollout

| Phase | Scope | Risk | Gate |
|---|---|---|---|
| **1** | ① Outbound push (extends EDL to endpoint) | low — additive, no endpoint actions | per-vendor `*_ENABLED` toggle |
| **2** | ② Inbound pull → alerts/incidents | low — read-only ingest | toggle + poll interval |
| **3** | ③ Response actions (isolate / block-hash) | high — touches endpoints | `reputation_detection_mode` shadow → enforce |
| later | Frontend `/integrations` page (credentials, status, sync counts) | — | out of scope for this doc |

---

## Open questions / risks

- **Licensing & scopes** — Cortex IOC/response needs **Pro**; Trend needs the right **role scopes** on the key. Verify before build; degrade gracefully (fail-open) if a scope is missing.
- **Rate limits & batch sizes** — Trend caps imports at **2000 objects / 1 MB**; both throttle. The reconcile loop must chunk and back off.
- **IOC-type coverage gaps** — Cortex has **no URL type** (normalize to domain/hash); sender-email is Trend-only. Map per-vendor, drop unsupported types with a metric rather than erroring.
- **Feedback loops** — do **not** re-ingest our own pushed IOCs as "EDR detections" (dedupe on `source_name` / our-origin tag) or we'll amplify our own signal.
- **De-duplication vs. EDR-native intel** — EDRs already ship vendor IOCs; our push should be additive and clearly attributed (`comment`/`description` = TI platform) so analysts can tell ours apart.
- **Clock/format skew** — Cortex expiration is epoch-ms, Trend is ISO-8601; centralize the TTL computation and format per vendor.

---

## Verification markers (once built)

- Push: `edr connector: cortex pushed=N expired=M` / `trend pushed=N (chunk k/j)` per reconcile cycle.
- Pull: new alerts appear with `source_service=cortex_xdr` / `trend_vision_one` and populated MITRE fields.
- Response (shadow): `edr action shadow: would isolate endpoint=… (mode=shadow)` with **no** live call.
- `*_ENABLED=false` → connector logs `disabled, skipping` and makes zero outbound calls.

---

## What's next ([[milestones/M4-roadmap]])

- Build Phase 1 as `services/edr/` and add a `architecture/services/edr.md` service page once it ships (this doc stays as the design record).
- Register an EDR node in [[architecture/topology]] (External targets subgraph + service catalogue) when it's real.
- Frontend `/integrations` page + `lib/api.ts` helpers (mirror the `Feed`/`EDLConfig` patterns).
- Evaluate STIX/TAXII 2.1 export if a 3rd/4th EDR is requested.

Design decision recorded in [[decisions/2026-07-03-edr-integration-approach]].
See also: [[architecture/services/ingestion]], [[architecture/services/icap]], [[milestones/M2-enforce]], [[runbooks/flip-detection-mode]].

---

## Sources

- Cortex XDR REST API — *Insert Simple Indicators (JSON)*, *Working with IOCs*, *Get Incidents / Get Alerts Multi-Events*, *Isolate Endpoint* (`docs-cortex.paloaltonetworks.com`, `cortex-panw.stoplight.io`); auth model in *Get Started with APIs*.
- Trend Vision One Automation Center **v3.0** — *Authentication*, *Suspicious Object Management*, *Workbench Alerts*, *Response / Endpoint*, *Intelligence Reports* (`automation.trendmicro.com/xdr`); suspicious-object import limits (`success.trendmicro.com`, `docs.trendmicro.com`).
