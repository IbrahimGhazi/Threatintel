# logserver #service

**Build:** `services/logserver`
**Role:** Syslog receiver. Banks' firewalls and network gear send logs here over UDP/TCP 514.
**External ports:** 514/udp, 514/tcp, 9514/http (also exposed on `ti-dmz`)
**Memory:** 256 MB

## Inputs (external)
- Firewall syslog (UDP 514)
- Firewall syslog (TCP 514)
- HTTP log endpoint (port 9514) for non-syslog sources

## Outputs
- [[architecture/services/api]] — POSTs parsed log batches via HTTP

## Networks
On both `ti-internal` and `ti-dmz`.

## Note
Doesn't write to NATS or Postgres directly — keeps responsibility narrow: receive → forward to API. The API decides what to do (store, parse, publish to NATS).
