"use client";

import { useState } from "react";
import { Copy, Check, Shield, Globe, Wifi, Activity, Server, Radio, ArrowRightLeft, Router } from "lucide-react";
import clsx from "clsx";

/* ── Shared helpers ──────────────────────────────────────────────────────── */

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={copy} className="absolute top-2 right-2 p-1.5 rounded text-text-muted hover:text-text-primary hover:bg-bg-elevated transition-colors">
      {copied ? <Check className="w-3.5 h-3.5 text-status-success" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

function CodeBlock({ code, lang = "text" }: { code: string; lang?: string }) {
  return (
    <div className="relative mt-2">
      <pre className="bg-bg-base border border-border rounded-lg p-4 text-xs font-mono text-text-secondary overflow-x-auto leading-relaxed">
        {code}
      </pre>
      <CopyButton text={code} />
    </div>
  );
}

function SectionNote({ icon: Icon, children }: { icon: React.ElementType; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 p-3 bg-bg-base border border-border rounded-lg">
      <Icon className="w-4 h-4 text-accent shrink-0 mt-0.5" />
      <p className="text-xs text-text-secondary leading-relaxed">{children}</p>
    </div>
  );
}

const PLATFORM_HOST = typeof window !== "undefined" ? window.location.hostname : "YOUR-TI-HOST";

const edlUrls = {
  "malicious-ips":    `http://${PLATFORM_HOST}/api/edl/feed/malicious-ips`,
  "malicious-domains":`http://${PLATFORM_HOST}/api/edl/feed/malicious-domains`,
  "malicious-urls":   `http://${PLATFORM_HOST}/api/edl/feed/malicious-urls`,
  "malicious-hashes": `http://${PLATFORM_HOST}/api/edl/feed/malicious-hashes`,
};

/* ── Page-level section tabs ─────────────────────────────────────────────── */

const SECTIONS = ["Threat Blocking", "Log Forwarding", "NetFlow", "ICAP Integration"] as const;
type Section = typeof SECTIONS[number];

/* ── Sub-tabs for threat-blocking vendors ────────────────────────────────── */

const BLOCKING_TABS = ["Palo Alto PAN-OS", "Fortinet FortiGate", "pfSense / OPNsense"] as const;
type BlockingTab = typeof BLOCKING_TABS[number];

/* ── Sub-tabs for log forwarding ────────────────────────────────────────── */

const LOG_FWD_TABS = ["Palo Alto PAN-OS", "Fortinet FortiGate", "pfSense / OPNsense", "Generic Syslog", "HTTP API"] as const;
type LogFwdTab = typeof LOG_FWD_TABS[number];

/* ── Sub-tabs for NetFlow ───────────────────────────────────────────────── */

const NETFLOW_TABS = ["Cisco IOS / IOS-XE", "Cisco Nexus (NX-OS)", "Cisco ASA", "Cisco Meraki", "Generic NetFlow"] as const;
type NetflowTab = typeof NETFLOW_TABS[number];

/* ── Sub-tabs for ICAP ──────────────────────────────────────────────────── */

const ICAP_TABS = ["Squid Proxy", "Bluecoat / Symantec", "Zscaler"] as const;
type IcapTab = typeof ICAP_TABS[number];

/* ── Main page ───────────────────────────────────────────────────────────── */

export default function FirewallPage() {
  const [section, setSection] = useState<Section>("Threat Blocking");
  const [blockingTab, setBlockingTab] = useState<BlockingTab>("Palo Alto PAN-OS");
  const [logFwdTab, setLogFwdTab] = useState<LogFwdTab>("Palo Alto PAN-OS");
  const [netflowTab, setNetflowTab] = useState<NetflowTab>("Cisco IOS / IOS-XE");
  const [icapTab, setIcapTab] = useState<IcapTab>("Squid Proxy");

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Firewall & Network Integration</h1>
        <p className="text-sm text-text-muted mt-1">
          Configure your firewalls, switches, and proxies to work with the TI platform &mdash;
          threat blocking, log forwarding, NetFlow export, and ICAP scanning.
        </p>
      </div>

      {/* ── Ingest Endpoints Summary ──────────────────────────────────────── */}
      <div className="card p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Server className="w-4 h-4 text-accent" />
          <h2 className="text-sm font-semibold text-text-primary">Platform Ingest Endpoints</h2>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {[
            { label: "Syslog (UDP)",  value: `${PLATFORM_HOST}:514/udp`,  desc: "RFC 3164 / 5424 / CEF" },
            { label: "Syslog (TCP)",  value: `${PLATFORM_HOST}:514/tcp`,  desc: "Stream-based syslog" },
            { label: "NetFlow (UDP)", value: `${PLATFORM_HOST}:2055/udp`, desc: "Cisco NetFlow v5 / v9" },
            { label: "HTTP Ingest",   value: `http://${PLATFORM_HOST}:9514/ingest`, desc: "JSON or plain-text POST" },
            { label: "ICAP Server",   value: `icap://${PLATFORM_HOST}:1344`, desc: "REQMOD + RESPMOD" },
          ].map((ep) => (
            <div key={ep.label} className="flex items-center gap-3 bg-bg-base border border-border rounded-lg px-3 py-2.5 relative">
              <div className="min-w-0 flex-1">
                <p className="text-xs font-medium text-text-primary">{ep.label}</p>
                <p className="text-xs font-mono text-accent truncate">{ep.value}</p>
                <p className="text-2xs text-text-muted">{ep.desc}</p>
              </div>
              <CopyButton text={ep.value} />
            </div>
          ))}
        </div>
      </div>

      {/* ── Section-level tabs ────────────────────────────────────────────── */}
      <div className="flex gap-2 flex-wrap">
        {SECTIONS.map((s) => {
          const icons: Record<Section, React.ElementType> = {
            "Threat Blocking": Shield,
            "Log Forwarding": ArrowRightLeft,
            "NetFlow": Activity,
            "ICAP Integration": Wifi,
          };
          const Icon = icons[s];
          return (
            <button
              key={s}
              onClick={() => setSection(s)}
              className={clsx(
                "flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-lg border transition-colors",
                section === s
                  ? "bg-accent/10 text-accent border-accent/30"
                  : "text-text-muted border-border hover:text-text-primary hover:border-text-muted"
              )}
            >
              <Icon className="w-3.5 h-3.5" />
              {s}
            </button>
          );
        })}
      </div>

      {/* ─────────────────────────────────────────────────────────────────── */}
      {/* SECTION: Threat Blocking                                          */}
      {/* ─────────────────────────────────────────────────────────────────── */}
      {section === "Threat Blocking" && (
        <div className="space-y-5">
          {/* EDL URL Reference */}
          <div className="card p-4 space-y-3">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-accent" />
              <h2 className="text-sm font-semibold text-text-primary">EDL Feed URLs</h2>
              <span className="badge bg-bg-elevated border-border text-text-muted text-2xs">Unauthenticated · Plain Text · Refreshed every 5 min</span>
            </div>
            <div className="grid grid-cols-1 gap-2">
              {Object.entries(edlUrls).map(([slug, url]) => (
                <div key={slug} className="flex items-center justify-between bg-bg-base border border-border rounded-lg px-3 py-2 relative">
                  <span className="text-xs font-mono text-text-muted mr-3 shrink-0">{slug}</span>
                  <span className="text-xs font-mono text-accent truncate flex-1">{url}</span>
                  <CopyButton text={url} />
                </div>
              ))}
            </div>
          </div>

          {/* Vendor tabs */}
          <div className="card overflow-hidden">
            <div className="flex border-b border-border overflow-x-auto">
              {BLOCKING_TABS.map((t) => (
                <button
                  key={t}
                  onClick={() => setBlockingTab(t)}
                  className={clsx(
                    "px-4 py-2.5 text-xs font-medium whitespace-nowrap transition-colors",
                    blockingTab === t
                      ? "text-accent border-b-2 border-accent bg-bg-surface"
                      : "text-text-muted hover:text-text-primary"
                  )}
                >
                  {t}
                </button>
              ))}
            </div>
            <div className="p-5 space-y-5">
              {blockingTab === "Palo Alto PAN-OS"    && <PanOS urls={edlUrls} />}
              {blockingTab === "Fortinet FortiGate"  && <FortiGate urls={edlUrls} />}
              {blockingTab === "pfSense / OPNsense"  && <PfSense urls={edlUrls} />}
            </div>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────────── */}
      {/* SECTION: Log Forwarding                                           */}
      {/* ─────────────────────────────────────────────────────────────────── */}
      {section === "Log Forwarding" && (
        <div className="space-y-5">
          <SectionNote icon={ArrowRightLeft}>
            Forward your firewall, switch, and endpoint logs to the TI platform for correlation, threat matching,
            baseline learning, and incident grouping. Supports <strong className="text-text-primary">Syslog UDP/TCP (port 514)</strong> with
            RFC 3164, RFC 5424, and CEF formats, plus an <strong className="text-text-primary">HTTP API (port 9514)</strong> for custom
            integrations.
          </SectionNote>

          <div className="card overflow-hidden">
            <div className="flex border-b border-border overflow-x-auto">
              {LOG_FWD_TABS.map((t) => (
                <button
                  key={t}
                  onClick={() => setLogFwdTab(t)}
                  className={clsx(
                    "px-4 py-2.5 text-xs font-medium whitespace-nowrap transition-colors",
                    logFwdTab === t
                      ? "text-accent border-b-2 border-accent bg-bg-surface"
                      : "text-text-muted hover:text-text-primary"
                  )}
                >
                  {t}
                </button>
              ))}
            </div>
            <div className="p-5 space-y-5">
              {logFwdTab === "Palo Alto PAN-OS" && <LogFwdPanOS host={PLATFORM_HOST} />}
              {logFwdTab === "Fortinet FortiGate" && <LogFwdFortiGate host={PLATFORM_HOST} />}
              {logFwdTab === "pfSense / OPNsense" && <LogFwdPfSense host={PLATFORM_HOST} />}
              {logFwdTab === "Generic Syslog" && <LogFwdGeneric host={PLATFORM_HOST} />}
              {logFwdTab === "HTTP API" && <LogFwdHTTP host={PLATFORM_HOST} />}
            </div>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────────── */}
      {/* SECTION: NetFlow                                                   */}
      {/* ─────────────────────────────────────────────────────────────────── */}
      {section === "NetFlow" && (
        <div className="space-y-5">
          <SectionNote icon={Activity}>
            Export NetFlow from your Cisco switches and routers to the TI platform on{" "}
            <strong className="text-text-primary">UDP port 2055</strong>. The platform parses{" "}
            <strong className="text-text-primary">NetFlow v5 and v9</strong> and feeds the flow records into the
            correlation engine for traffic analysis, anomaly detection, and attack chain discovery.
            Extracted fields include source/destination IPs, ports, protocols, byte counts, TCP flags,
            interface indexes, and flow duration.
          </SectionNote>

          <div className="card overflow-hidden">
            <div className="flex border-b border-border overflow-x-auto">
              {NETFLOW_TABS.map((t) => (
                <button
                  key={t}
                  onClick={() => setNetflowTab(t)}
                  className={clsx(
                    "px-4 py-2.5 text-xs font-medium whitespace-nowrap transition-colors",
                    netflowTab === t
                      ? "text-accent border-b-2 border-accent bg-bg-surface"
                      : "text-text-muted hover:text-text-primary"
                  )}
                >
                  {t}
                </button>
              ))}
            </div>
            <div className="p-5 space-y-5">
              {netflowTab === "Cisco IOS / IOS-XE"   && <NetflowIOS host={PLATFORM_HOST} />}
              {netflowTab === "Cisco Nexus (NX-OS)"   && <NetflowNXOS host={PLATFORM_HOST} />}
              {netflowTab === "Cisco ASA"              && <NetflowASA host={PLATFORM_HOST} />}
              {netflowTab === "Cisco Meraki"           && <NetflowMeraki host={PLATFORM_HOST} />}
              {netflowTab === "Generic NetFlow"        && <NetflowGeneric host={PLATFORM_HOST} />}
            </div>
          </div>

          {/* NetFlow fields reference */}
          <div className="card p-4 space-y-3">
            <h3 className="text-sm font-semibold text-text-primary">Parsed Flow Fields</h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-1">
              {[
                "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                "bytes_sent", "bytes_received", "packets", "tcp_flags",
                "input_interface", "output_interface", "flow_duration",
                "src_as", "dst_as", "nexthop", "device_ip",
              ].map((f) => (
                <span key={f} className="text-xs font-mono text-text-muted py-0.5">{f}</span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────────── */}
      {/* SECTION: ICAP Integration                                         */}
      {/* ─────────────────────────────────────────────────────────────────── */}
      {section === "ICAP Integration" && (
        <div className="space-y-5">
          <SectionNote icon={Wifi}>
            The TI platform runs an ICAP server on <strong className="text-text-primary">port 1344</strong> supporting
            REQMOD (block outbound requests to malicious domains/IPs) and RESPMOD (block downloads matching
            known malicious file hashes). Configure your web proxy to forward traffic through ICAP for
            real-time threat inspection.
          </SectionNote>

          <div className="card overflow-hidden">
            <div className="flex border-b border-border overflow-x-auto">
              {ICAP_TABS.map((t) => (
                <button
                  key={t}
                  onClick={() => setIcapTab(t)}
                  className={clsx(
                    "px-4 py-2.5 text-xs font-medium whitespace-nowrap transition-colors",
                    icapTab === t
                      ? "text-accent border-b-2 border-accent bg-bg-surface"
                      : "text-text-muted hover:text-text-primary"
                  )}
                >
                  {t}
                </button>
              ))}
            </div>
            <div className="p-5 space-y-5">
              {icapTab === "Squid Proxy"            && <IcapSquid host={PLATFORM_HOST} />}
              {icapTab === "Bluecoat / Symantec"    && <IcapBluecoat host={PLATFORM_HOST} />}
              {icapTab === "Zscaler"                && <IcapZscaler host={PLATFORM_HOST} />}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   THREAT BLOCKING COMPONENTS
   ════════════════════════════════════════════════════════════════════════════ */

function PanOS({ urls }: { urls: Record<string, string> }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary">
        In PAN-OS, add each feed as an <strong className="text-text-primary">External Dynamic List</strong> under
        Objects &rarr; External Dynamic Lists.
      </p>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">1. Create EDL for malicious IPs</p>
        <CodeBlock code={`Objects -> External Dynamic Lists -> Add
  Name:         TI-Malicious-IPs
  Type:         IP Address
  Source:       ${urls["malicious-ips"]}
  Repeat:       Five Minute
  Exceptions:   (none)

Security Policy -> Add Rule:
  Source:  any
  Dest:    TI-Malicious-IPs  [or as source for outbound]
  Action:  Deny
  Log:     Yes`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">2. Create EDL for malicious domains (DNS Sinkhole)</p>
        <CodeBlock code={`Objects -> External Dynamic Lists -> Add
  Name:   TI-Malicious-Domains
  Type:   Domain
  Source: ${urls["malicious-domains"]}
  Repeat: Five Minute

Anti-Spyware Profile -> DNS Signatures -> Sinkhole:
  External Dynamic List: TI-Malicious-Domains
  Action: sinkhole`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">3. URL filtering for malicious URLs</p>
        <CodeBlock code={`Objects -> External Dynamic Lists -> Add
  Name:   TI-Malicious-URLs
  Type:   URL
  Source: ${urls["malicious-urls"]}
  Repeat: Five Minute

URL Filtering Profile -> Block List:
  Add EDL: TI-Malicious-URLs`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">4. File blocking with hash EDL (PAN-OS 10.1+)</p>
        <CodeBlock code={`Objects -> External Dynamic Lists -> Add
  Name:   TI-Malicious-Hashes
  Type:   Predefined IP  (use as custom File Blocking profile source)
  Source: ${urls["malicious-hashes"]}

File Blocking Profile -> Wildfire Analysis -> Block matching hashes`} />
      </div>
    </div>
  );
}

function FortiGate({ urls }: { urls: Record<string, string> }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary">
        FortiGate consumes threat feeds as <strong className="text-text-primary">External Connector</strong> objects
        under Security Fabric &rarr; Fabric Connectors &rarr; Threat Feeds.
      </p>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">CLI -- Create threat feed connectors</p>
        <CodeBlock code={`config system external-resource
    edit "TI-Malicious-IPs"
        set type ip
        set resource "${urls["malicious-ips"]}"
        set refresh-rate 5
        set status enable
    next
    edit "TI-Malicious-Domains"
        set type domain
        set resource "${urls["malicious-domains"]}"
        set refresh-rate 5
        set status enable
    next
    edit "TI-Malicious-URLs"
        set type malware
        set resource "${urls["malicious-urls"]}"
        set refresh-rate 5
        set status enable
    next
end`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">GUI -- Use in firewall policy</p>
        <CodeBlock code={`Policy & Objects -> Firewall Policy -> Create New
  Source:      all
  Destination: TI-Malicious-IPs   (select the threat feed object)
  Action:      DENY
  Log:         All Sessions

Repeat for outbound (source = TI-Malicious-IPs, destination = all)`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">DNS Filter for malicious domains</p>
        <CodeBlock code={`Security Profiles -> DNS Filter -> Create/Edit
  External IP Block List: TI-Malicious-Domains
  Action: Block`} />
      </div>
    </div>
  );
}

function PfSense({ urls }: { urls: Record<string, string> }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary">
        Use <strong className="text-text-primary">pfBlockerNG</strong> (pfSense) or
        <strong className="text-text-primary"> URL Tables</strong> (OPNsense) to consume the IP/domain feeds.
      </p>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">pfSense -- pfBlockerNG IP Feed</p>
        <CodeBlock code={`Firewall -> pfBlockerNG -> IP -> IPv4 -> Add
  Name:        TI_Malicious_IPs
  Description: TI Platform - Known malicious IPs

  Source Definitions:
    Header/Label: TI-Malicious-IPs
    URL/File:     ${urls["malicious-ips"]}
    Format:       Auto
    State:        ON

  Action:     Deny Both (or Deny Inbound / Deny Outbound)
  Update Frequency: Every 1 hour`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">pfSense -- pfBlockerNG DNSBL (Domain Feed)</p>
        <CodeBlock code={`Firewall -> pfBlockerNG -> DNSBL -> Add
  Name:       TI_Malicious_Domains

  Source Definitions:
    Header:  TI-Domains
    URL:     ${urls["malicious-domains"]}
    Format:  Auto (one domain per line)
    State:   ON

  Action: Unbound -> NXDOMAIN (sinkhole)`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">OPNsense -- Firewall &rarr; Aliases &rarr; URL Table</p>
        <CodeBlock code={`Firewall -> Aliases -> Add
  Name:    TI_Bad_IPs
  Type:    URL Table (IPs)
  Content: ${urls["malicious-ips"]}
  Refresh: 300

Firewall -> Rules -> WAN -> Add
  Action:      Block
  Destination: TI_Bad_IPs`} />
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   LOG FORWARDING COMPONENTS
   ════════════════════════════════════════════════════════════════════════════ */

function LogFwdPanOS({ host }: { host: string }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary">
        Configure PAN-OS to forward TRAFFIC and THREAT logs via syslog to the TI platform.
        The platform auto-detects Palo Alto CSV format and extracts zones, users, NAT translations,
        applications, and actions.
      </p>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">1. Create Syslog Server Profile</p>
        <CodeBlock code={`Device -> Server Profiles -> Syslog -> Add
  Name:       TI-Platform
  Syslog Server:
    Name:      TI-Platform
    Server:    ${host}
    Transport: UDP
    Port:      514
    Format:    BSD
    Facility:  LOG_USER`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">2. Configure Log Forwarding Profile</p>
        <CodeBlock code={`Objects -> Log Forwarding -> Add
  Name:  TI-Forward-All

  Match List:
    Name:     Traffic-Logs
    Log Type: traffic
    Filter:   All Logs
    Syslog:   TI-Platform

    Name:     Threat-Logs
    Log Type: threat
    Filter:   All Logs
    Syslog:   TI-Platform

    Name:     URL-Logs
    Log Type: url
    Filter:   All Logs
    Syslog:   TI-Platform`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">3. Apply to Security Policies</p>
        <CodeBlock code={`Policies -> Security -> [Select Rule] -> Actions
  Log Setting:
    Log at Session Start: Yes (optional - high volume)
    Log at Session End:   Yes
    Log Forwarding:       TI-Forward-All

Commit changes.`} />
      </div>
    </div>
  );
}

function LogFwdFortiGate({ host }: { host: string }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary">
        Configure FortiGate to forward logs in <strong className="text-text-primary">CEF format</strong> for best
        field extraction, or standard syslog for compatibility.
      </p>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">CLI -- Configure syslog forwarding</p>
        <CodeBlock code={`config log syslogd setting
    set status enable
    set server "${host}"
    set port 514
    set mode udp
    set facility local7
    set format cef         # CEF recommended; or "default" for native format
end

# Enable logging for all traffic
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
    set multicast-traffic enable
    set sniffer-traffic enable
    set anomaly enable
    set dns enable
end`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">GUI -- Log & Report &rarr; Log Settings</p>
        <CodeBlock code={`Log & Report -> Log Settings -> Remote Logging
  Send Logs to Syslog:  Enable
  IP Address/FQDN:      ${host}
  Port:                 514
  Minimum Log Level:    Information
  Log Format:           CEF (Common Event Format)`} />
      </div>
    </div>
  );
}

function LogFwdPfSense({ host }: { host: string }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary">
        pfSense and OPNsense can forward firewall filter logs via syslog.
      </p>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">pfSense -- Status &rarr; System Logs &rarr; Settings</p>
        <CodeBlock code={`Status -> System Logs -> Settings

Remote Logging Options:
  Enable Remote Logging:  Yes
  Source Address:          Any
  IP Protocol:            IPv4

  Remote Log Servers:
    Server 1:  ${host}:514

  Remote Syslog Contents:
    [x] Firewall Events
    [x] System Events
    [x] DNS Events
    [x] DHCP Events

Save and Apply.`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">OPNsense -- System &rarr; Settings &rarr; Logging / Targets</p>
        <CodeBlock code={`System -> Settings -> Logging / Targets -> Add

  Transport:    UDP(4)
  Hostname:     ${host}
  Port:         514
  Facility:     (default)
  Level:        Informational and above
  Applications: filter, suricata, unbound

Save and Apply.`} />
      </div>
    </div>
  );
}

function LogFwdGeneric({ host }: { host: string }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary">
        Any device that supports syslog can forward logs to the TI platform. The platform auto-detects
        RFC 3164, RFC 5424, and CEF formats and extracts source/destination IPs, ports, protocols, and actions.
      </p>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">rsyslog -- Forward all logs</p>
        <CodeBlock code={`# /etc/rsyslog.d/ti-platform.conf

# Forward all facility/severity via UDP
*.* @${host}:514

# Or via TCP (more reliable, recommended for high volume)
*.* @@${host}:514

# Restart rsyslog
sudo systemctl restart rsyslog`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">syslog-ng -- Forward firewall logs</p>
        <CodeBlock code={`# /etc/syslog-ng/conf.d/ti-platform.conf

destination d_ti_platform {
    udp("${host}" port(514));
};

log {
    source(s_local);
    destination(d_ti_platform);
};`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Test syslog connectivity</p>
        <CodeBlock code={`# Send a test syslog message
echo "<14>Test message from $(hostname)" | nc -u -w1 ${host} 514

# Verify it appears in the TI platform Logs page`} />
      </div>
    </div>
  );
}

function LogFwdHTTP({ host }: { host: string }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary">
        For devices or scripts that don&rsquo;t support syslog, use the HTTP ingest API on port 9514.
        Accepts JSON or plain-text log lines.
      </p>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">JSON ingest (single log)</p>
        <CodeBlock code={`curl -X POST http://${host}:9514/ingest \\
  -H "Content-Type: application/json" \\
  -d '{
    "source_type": "firewall",
    "source_name": "fw-edge-01",
    "source_ip":   "10.0.1.1",
    "raw_log":     "Jun 14 12:00:00 fw-edge-01 kernel: DROP IN=eth0 SRC=203.0.113.5 DST=10.0.1.100 PROTO=TCP DPT=22"
  }'`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Plain-text ingest</p>
        <CodeBlock code={`# Send a raw syslog line via HTTP
curl -X POST http://${host}:9514/ingest \\
  -H "Content-Type: text/plain" \\
  -d '<14>Jun 14 12:00:00 router01 %ASA-4-106023: Deny tcp src outside:203.0.113.5/443 dst inside:10.0.1.50/80'`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Supported source_type values</p>
        <div className="flex flex-wrap gap-2 mt-2">
          {["firewall", "proxy", "edr", "email", "web_gw", "syslog", "netflow"].map((t) => (
            <span key={t} className="text-2xs font-mono px-2 py-0.5 bg-bg-base border border-border rounded text-text-muted">{t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   NETFLOW COMPONENTS
   ════════════════════════════════════════════════════════════════════════════ */

function NetflowIOS({ host }: { host: string }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary">
        Configure <strong className="text-text-primary">NetFlow v5 or v9</strong> on Cisco IOS / IOS-XE routers and
        Layer 3 switches (Catalyst 3750, 3850, 9000 series, ISR routers).
      </p>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">NetFlow v5 -- Traditional Flow Export (IOS)</p>
        <CodeBlock code={`! Enable NetFlow on the interface(s) you want to monitor
interface GigabitEthernet0/0
 ip flow ingress
 ip flow egress
!
interface GigabitEthernet0/1
 ip flow ingress
 ip flow egress
!
! Configure the flow export destination
ip flow-export version 5
ip flow-export destination ${host} 2055
ip flow-export source Loopback0
!
! Set the active/inactive flow timers
ip flow-cache timeout active 1
ip flow-cache timeout inactive 15`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Flexible NetFlow (NetFlow v9) -- IOS-XE / Catalyst 9000</p>
        <CodeBlock code={`! Define a flow record
flow record TI-RECORD
 match ipv4 source address
 match ipv4 destination address
 match ipv4 protocol
 match transport source-port
 match transport destination-port
 collect interface input
 collect interface output
 collect counter bytes long
 collect counter packets long
 collect transport tcp flags
 collect timestamp sys-uptime first
 collect timestamp sys-uptime last
!
! Define the flow exporter
flow exporter TI-EXPORT
 destination ${host}
 transport udp 2055
 source Loopback0
 export-protocol netflow-v9
 template data timeout 60
!
! Define the flow monitor
flow monitor TI-MONITOR
 record TI-RECORD
 exporter TI-EXPORT
 cache timeout active 60
 cache timeout inactive 15
!
! Apply to interfaces
interface GigabitEthernet1/0/1
 ip flow monitor TI-MONITOR input
 ip flow monitor TI-MONITOR output
!
interface GigabitEthernet1/0/2
 ip flow monitor TI-MONITOR input
 ip flow monitor TI-MONITOR output`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Verify NetFlow is exporting</p>
        <CodeBlock code={`show ip flow export
show ip cache flow
show flow monitor TI-MONITOR statistics
show flow exporter TI-EXPORT statistics`} />
      </div>
    </div>
  );
}

function NetflowNXOS({ host }: { host: string }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary">
        Configure NetFlow on Cisco Nexus switches (NX-OS 7000, 9000 series) using the
        <strong className="text-text-primary"> Flexible NetFlow</strong> infrastructure.
      </p>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">NX-OS Flexible NetFlow Configuration</p>
        <CodeBlock code={`! Enable the NetFlow feature
feature netflow
!
! Define a flow record
flow record TI-RECORD
  match ipv4 source address
  match ipv4 destination address
  match ipv4 protocol
  match transport source-port
  match transport destination-port
  collect counter bytes long
  collect counter packets long
  collect transport tcp flags
!
! Define the flow exporter
flow exporter TI-EXPORT
  destination ${host}
  transport udp 2055
  source mgmt0
  version 9
    template data timeout 60
!
! Define the flow monitor
flow monitor TI-MONITOR
  record TI-RECORD
  exporter TI-EXPORT
  cache timeout active 60
  cache timeout inactive 15
!
! Apply to interfaces or VLANs
interface Ethernet1/1
  ip flow monitor TI-MONITOR input
  ip flow monitor TI-MONITOR output
!
interface Vlan100
  ip flow monitor TI-MONITOR input
  ip flow monitor TI-MONITOR output`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Verify on NX-OS</p>
        <CodeBlock code={`show flow exporter TI-EXPORT
show flow monitor TI-MONITOR cache
show flow monitor TI-MONITOR statistics`} />
      </div>
    </div>
  );
}

function NetflowASA({ host }: { host: string }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary">
        Cisco ASA exports flow data using <strong className="text-text-primary">NSEL (NetFlow Security Event Logging)</strong>,
        which is based on NetFlow v9 with ASA-specific extensions.
      </p>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">ASA NSEL (NetFlow v9) Configuration</p>
        <CodeBlock code={`! Define the flow export destination
flow-export destination inside ${host} 2055
!
! Set the template refresh and timeouts
flow-export template timeout-rate 1
flow-export active refresh-interval 60
flow-export delay flow-create 10
!
! Define a class map to capture all traffic
policy-map global_policy
 class class-default
  flow-export event-type all destination ${host}
!
! Apply the policy
service-policy global_policy global
!
! Optionally export specific event types:
! flow-export event-type flow-create      (new connections)
! flow-export event-type flow-teardown    (closed connections)
! flow-export event-type flow-denied      (denied connections)`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Verify on ASA</p>
        <CodeBlock code={`show flow-export counters
show running-config flow-export`} />
      </div>
    </div>
  );
}

function NetflowMeraki({ host }: { host: string }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary">
        Cisco Meraki MX appliances support <strong className="text-text-primary">NetFlow v9 export</strong> configured
        through the Meraki Dashboard.
      </p>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Meraki Dashboard Configuration</p>
        <CodeBlock code={`Network-wide -> General -> Reporting

  NetFlow:
    Toggle:          Enabled
    Collector IP:    ${host}
    Collector Port:  2055

  NetFlow Version:   v9

Save Changes.

Note: NetFlow export on Meraki is per-network.
Repeat for each network/site that you want to monitor.`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Supported Meraki Models</p>
        <div className="flex flex-wrap gap-2 mt-2">
          {["MX64", "MX67", "MX68", "MX84", "MX100", "MX250", "MX450", "vMX"].map((m) => (
            <span key={m} className="text-2xs font-mono px-2 py-0.5 bg-bg-base border border-border rounded text-text-muted">{m}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

function NetflowGeneric({ host }: { host: string }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary">
        Any device that supports NetFlow v5 or v9 export can send flows to the TI platform.
        Configure your exporter to send UDP datagrams to <strong className="text-text-primary">{host}:2055</strong>.
      </p>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Requirements</p>
        <CodeBlock code={`Protocol:    UDP
Port:        2055
Version:     NetFlow v5 or NetFlow v9 (RFC 3954)
Destination: ${host}

Recommended export settings:
  Active timeout:    60 seconds
  Inactive timeout:  15 seconds
  Template refresh:  60 seconds (v9 only)

Minimum required fields for correlation:
  - Source IP / Destination IP
  - Source Port / Destination Port
  - Protocol
  - Byte count
  - Packet count`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Test with softflowd (Linux)</p>
        <CodeBlock code={`# Install softflowd (generates NetFlow from packet capture)
sudo apt install softflowd

# Export NetFlow v5 from a network interface
sudo softflowd -i eth0 -n ${host}:2055 -v 5

# Or export v9
sudo softflowd -i eth0 -n ${host}:2055 -v 9

# Send a test using nflow-generator
nflow-generator -t ${host} -p 2055`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Verify flows are being received</p>
        <CodeBlock code={`# Check the TI platform logserver logs for NetFlow activity:
docker compose logs logserver | grep -i netflow

# Expected output:
# NetFlow UDP listener on :2055
# NetFlow: 24 flow records from 192.168.3.1`} />
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   ICAP COMPONENTS
   ════════════════════════════════════════════════════════════════════════════ */

function IcapSquid({ host }: { host: string }) {
  return (
    <div className="space-y-4">
      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">squid.conf -- ICAP configuration</p>
        <CodeBlock code={`# -- ICAP ------------------------------------------------
icap_enable on
icap_send_client_ip on
icap_send_client_username on
icap_client_username_header X-Authenticated-User

# TI Platform REQMOD - check outbound HTTP requests
icap_service ti_reqmod reqmod_precache bypass=1 \\
    icap://${host}:1344/reqmod

adaptation_access ti_reqmod allow all

# TI Platform RESPMOD - scan downloaded content
icap_service ti_respmod respmod_precache bypass=1 \\
    icap://${host}:1344/respmod

adaptation_access ti_respmod allow all

# Log denied requests
access_log /var/log/squid/access.log squid`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Test ICAP connectivity</p>
        <CodeBlock code={`# Test OPTIONS request
curl -v --request OPTIONS icap://${host}:1344/reqmod

# Using c-icap-client (install c-icap-utils)
c-icap-client -s ${host} -p 1344 -i /etc/passwd -o /dev/null -req http://test.com/ -v`} />
      </div>
    </div>
  );
}

function IcapBluecoat({ host }: { host: string }) {
  return (
    <div className="space-y-4">
      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Blue Coat / Symantec ProxySG -- ICAP Service</p>
        <CodeBlock code={`Configuration -> External Services -> ICAP

  Service Name:   TI-Platform-REQMOD
  ICAP URI:       icap://${host}:1344/reqmod
  Method:         REQMOD
  Bypass:         Enabled (fail open)
  Connection Timeout: 30s

  Service Name:   TI-Platform-RESPMOD
  ICAP URI:       icap://${host}:1344/respmod
  Method:         RESPMOD
  Bypass:         Enabled
  Max Response Time: 30s`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Apply via Policy (Visual Policy Manager)</p>
        <CodeBlock code={`Web Access Layer -> Add Rule
  Source:  Any
  Dest:    Any
  Action:  ICAP Request Service: TI-Platform-REQMOD
           ICAP Response Service: TI-Platform-RESPMOD`} />
      </div>
    </div>
  );
}

function IcapZscaler({ host }: { host: string }) {
  return (
    <div className="space-y-4">
      <SectionNote icon={Shield}>
        Zscaler does not support ICAP natively. Use EDL feeds via Custom URL Category and Firewall IP Groups instead.
      </SectionNote>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Custom URL Category (Malicious URLs + Domains)</p>
        <CodeBlock code={`Administration -> URL Categories -> Add Custom Category
  Name:    TI-Malicious-URLs
  Type:    Custom
  URLs:    Import from  ${edlUrls["malicious-urls"]}
  Action:  Block

Administration -> URL Categories -> Add Custom Category
  Name:    TI-Malicious-Domains
  Type:    Custom
  URLs:    Import from  ${edlUrls["malicious-domains"]}
  Action:  Block`} />
      </div>

      <div className="space-y-1">
        <p className="text-xs font-medium text-text-primary">Firewall IP Group (Malicious IPs)</p>
        <CodeBlock code={`Policy -> Firewall -> IP Source/Destination Groups
  Name:    TI-Malicious-IPs
  Source:  ${edlUrls["malicious-ips"]}

Policy -> Firewall -> Firewall Rules -> Add
  Source:      Any
  Destination: TI-Malicious-IPs
  Action:      Block and Log`} />
      </div>
    </div>
  );
}
