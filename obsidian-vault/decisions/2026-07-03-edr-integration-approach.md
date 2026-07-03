# 2026-07-03 — EDR integration approach (Cortex XDR + Trend Vision One) #decision

**Status:** proposed

**Context:**
We want to extend enforcement from network appliances (firewalls/proxies via EDL + [[architecture/services/icap]]) to endpoints by integrating with EDRs — first Cortex XDR and Trend Vision One. Today the only outbound indicator channel is the pull-based, unauthenticated EDL text feed; EDRs expect an authenticated push to their IOC APIs, and they also offer detection feeds and response actions we could consume/drive. We need to decide the integration shape before building `services/edr/`. Full design in [[milestones/M5-edr-integration]].

**Options considered:**

1. **Native per-vendor REST IOC APIs** — one adapter per EDR calling its own indicator/suspicious-object, detection, and response endpoints.
2. **Generic STIX/TAXII 2.1 exporter** — stand up one TAXII collection and let each EDR subscribe; vendor-neutral, but IOC-push only (no per-IOC ack, no response actions), and Cortex's TAXII support is limited.
3. **Event-driven push** — call the EDR IOC API on every indicator write/expire.
4. **Periodic reconciliation push** — each cycle diff the desired active-IOC set against the EDR and add/expire, mirroring `ingestion`'s feed loop and the EDL rebuild.
5. **Response actions ungated** vs. **gated behind the existing `reputation_detection_mode`** (off/shadow/enforce).

**Decision:**
Build a per-vendor **native REST adapter** (option 1) with a **periodic reconciliation push** (option 4), reusing the **existing active-indicator/EDL set as the single outbound source of truth**, and **gate endpoint response actions behind `platform_settings.reputation_detection_mode`** (shadow-first). Keep Trend's STIX `intelligenceReports` route only as the bulk-import path. Copy the fail-open async client pattern from `ml/external_feeds.py:_gsb_check`.

**Consequences:**
- (+) Lowest latency, per-IOC validation/ack, and access to detections + response that STIX can't give.
- (+) Idempotent, restart-safe pushes; no API hammering on every write; no parallel "EDR indicator" store to keep in sync.
- (+) Response actions inherit the proven safety rail from [[milestones/M2-enforce]] — isolate/block runs shadow-first until an operator flips to enforce.
- (−) Per-vendor adapter code to maintain; each new EDR is new code, not just a new subscriber.
- (−) Must handle vendor asymmetries (Cortex has no native URL type; auth models differ; Trend caps imports at 2000 objects / 1 MB).

**Revisit when:**
- A **3rd/4th EDR** is requested → the per-adapter cost tips in favor of a shared **STIX/TAXII 2.1** export.
- A vendor ships a webhook/push for detections → replace the inbound **poll** loop with a subscription.
- Response actions prove reliable in enforce mode → consider auto-isolation policies driven by `correlation`.
