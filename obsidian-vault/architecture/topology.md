# Full System Topology #service

The entire platform at one glance. Click any node to jump to its detailed note.

## High-level data flow

```mermaid
flowchart LR
    subgraph EXT[External Sources]
        FW[Firewall / Network Devices]
        WEB[Web Proxy]
        FEEDS[TI Feeds<br/>AbuseIPDB · OTX · ThreatFox<br/>MalwareBazaar · URLHaus · OpenPhish]
        VT[VirusTotal]
        ANALYST[Security Analyst]
    end

    subgraph EDGE[Edge Layer]
        LOGSERVER[logserver<br/>:514 syslog]
        ICAP[icap<br/>:1344]
        NGINX[nginx<br/>:80/:443]
    end

    subgraph PLATFORM[Platform Services]
        API[api<br/>REST]
        INGESTION[ingestion<br/>feed poller]
        ENRICHMENT[enrichment<br/>geoip/asn]
        CORRELATION[correlation<br/>rules + scorer + ML]
        SANDBOX[sandbox<br/>file analysis]
        LEARNER[learner<br/>nightly AE]
        FRONTEND[frontend<br/>Next.js]
    end

    subgraph DATA[Data Layer]
        PG[(postgres)]
        REDIS[(redis)]
        NATS{{NATS JetStream}}
    end

    FW -->|syslog UDP/TCP| LOGSERVER
    WEB -->|ICAP| ICAP
    ANALYST -->|HTTPS| NGINX

    LOGSERVER -->|HTTP| API
    ICAP -->|HTTP| API
    NGINX --> FRONTEND
    NGINX --> API
    FRONTEND --> API

    FEEDS -->|HTTPS poll| INGESTION
    VT -->|HTTPS| SANDBOX

    API --> PG
    API --> REDIS
    API --> NATS
    INGESTION --> PG
    INGESTION --> NATS
    ENRICHMENT --> PG
    ENRICHMENT --> REDIS
    ENRICHMENT --> NATS
    CORRELATION --> PG
    CORRELATION --> REDIS
    CORRELATION --> NATS
    CORRELATION -->|score lookups| API
    SANDBOX --> PG
    SANDBOX --> REDIS
    SANDBOX --> NATS
    SANDBOX -->|verdict| API
    ICAP --> REDIS
    ICAP -->|verdict| API

    LEARNER -->|read 7d logs<br/>write embeddings| PG
    CORRELATION -.->|read embeddings<br/>every 600s| PG

    classDef ext fill:#fef3c7,stroke:#92400e
    classDef edge fill:#dbeafe,stroke:#1e40af
    classDef plat fill:#dcfce7,stroke:#166534
    classDef data fill:#fce7f3,stroke:#9f1239
    class FW,WEB,FEEDS,VT,ANALYST ext
    class LOGSERVER,ICAP,NGINX edge
    class API,INGESTION,ENRICHMENT,CORRELATION,SANDBOX,LEARNER,FRONTEND plat
    class PG,REDIS,NATS data
```

## NATS subject map

```mermaid
flowchart LR
    LOGSERVER[[logserver]] --> APIA[api]
    APIA -->|publish| NATS{{NATS JetStream}}
    INGESTION[[ingestion]] -->|publish| NATS
    NATS -->|subscribe| ENRICHMENT[[enrichment]]
    NATS -->|subscribe| CORRELATION[[correlation]]
    ENRICHMENT -->|publish<br/>enriched| NATS
    SANDBOX[[sandbox]] -->|publish<br/>verdicts| NATS
    NATS -->|subscribe| SANDBOX

    classDef plat fill:#dcfce7,stroke:#166534
    classDef bus fill:#fce7f3,stroke:#9f1239
    class LOGSERVER,APIA,INGESTION,ENRICHMENT,CORRELATION,SANDBOX plat
    class NATS bus
```

## Redis database allocation #gotcha

| DB | Service | Purpose |
|----|---------|---------|
| 0 | [[architecture/services/api]] | sandbox progress + general cache |
| 1 | [[architecture/services/ingestion]] | feed dedup + rate-limit |
| 2 | [[architecture/services/enrichment]] | geoip cache |
| 3 | [[architecture/services/icap]] | verdict cache |
| 4 | [[architecture/services/correlation]] | dedup + leader election state |
| 5 | [[architecture/services/sandbox]] | analysis queue |

## Network segmentation

- **`ti-internal`** — all service-to-service traffic (postgres, redis, nats, internal HTTP)
- **`ti-dmz`** — only services with external exposure: nginx, icap, logserver

## Service catalogue

| Service | Layer | Note |
|---|---|---|
| [[architecture/services/postgres]] | data | primary store |
| [[architecture/services/redis]] | data | cache + dedup |
| [[architecture/services/nats]] | data | message bus |
| [[architecture/services/api]] | platform | REST surface |
| [[architecture/services/ingestion]] | platform | TI feed puller |
| [[architecture/services/enrichment]] | platform | geo/asn enrichment |
| [[architecture/services/correlation]] | platform | detection brain |
| [[architecture/services/sandbox]] | platform | file detonation |
| [[architecture/services/learner]] | platform | M3 nightly AE |
| [[architecture/services/icap]] | edge | web-proxy hook |
| [[architecture/services/logserver]] | edge | syslog receiver |
| [[architecture/services/frontend]] | edge | Next.js UI |
| [[architecture/services/nginx]] | edge | reverse proxy |
| [[architecture/services/prometheus]] | obs | metrics |
| [[architecture/services/grafana]] | obs | dashboards |

> See [[product/overview]] for the selling-deck-friendly version.
