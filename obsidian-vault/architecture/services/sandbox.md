# sandbox #service

**Build:** `services/sandbox` (worker) + `services/sandbox/analysis` (per-file analysis container)
**Role:** Detonates suspicious files in isolated containers and returns a verdict.
**Memory:** 512 MB (worker)

## Inputs
- [[architecture/services/nats]] — subscribes to analysis requests
- [[architecture/services/api]] — file metadata
- VirusTotal (optional, if `VIRUSTOTAL_API_KEY`)

## Outputs
- [[architecture/services/postgres]] — verdict rows
- [[architecture/services/nats]] — publishes `sandbox.verdict.*`
- [[architecture/services/api]] — verdict push-back via HTTP
- [[architecture/services/redis]] (DB 5) — analysis queue, (DB 0) — progress for UI

## Engines
- `mock` — for dev
- VirusTotal API
- Local docker-in-docker dynamic analysis (`LOCAL_SANDBOX_DYNAMIC=true`) — uses `/var/run/docker.sock` to spin up `ti-sandbox-analysis` containers per file
- `SANDBOX_ANALYSIS_TIMEOUT` (default 120s) per file

## Called by
- [[architecture/services/icap]] — when ICAP detects a file download

## Storage
- `/sandbox-files` volume — shared with api for file pickup
