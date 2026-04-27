"use client";

/**
 * System page — live node / per-pod resource metrics (pulled from the
 * Kubernetes API + metrics-server via /system/metrics), platform settings,
 * and in-cluster management-interface hints.
 */

import { useState, useEffect, useCallback, useMemo } from "react";
import {
  Activity,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Server,
  Database,
  Cpu,
  Save,
  Loader2,
  Settings,
  HardDrive,
  MemoryStick,
  Network,
  Boxes,
  Clock,
  ArrowDownCircle,
  ArrowUpCircle,
  RefreshCw,
  Gauge,
} from "lucide-react";
import clsx from "clsx";

// ── API ─────────────────────────────────────────────────────────────────────

const API = process.env.NEXT_PUBLIC_API_URL ?? "/api";
const KEY = process.env.NEXT_PUBLIC_API_KEY ?? "";
function hdrs(): Record<string, string> {
  return { "Content-Type": "application/json", "X-API-Key": KEY };
}

// ── Types ───────────────────────────────────────────────────────────────────

interface MemBlock {
  total: number;
  used: number;
  available?: number;
  percent: number;
}
interface DiskBlock {
  total: number;
  used: number;
  free: number;
  percent: number;
}
interface SwapBlock {
  total: number;
  used: number;
  percent: number;
}
interface HostMetrics {
  cpu_count: number;
  cpu_percent: number;
  load_average: [number, number, number];
  memory: MemBlock;
  swap: SwapBlock;
  disk: DiskBlock;
  uptime_seconds: number;
}
interface ContainerMem {
  used: number;
  limit: number;
  percent: number;
}
interface ContainerNet {
  rx_bytes: number;
  tx_bytes: number;
}
interface ContainerIO {
  read_bytes: number;
  write_bytes: number;
}
interface ContainerMetrics {
  name: string;
  service: string;
  state: string;
  status: string;
  cpu_percent: number;
  memory: ContainerMem;
  network: ContainerNet;
  block_io: ContainerIO;
}
interface SystemMetrics {
  host: HostMetrics;
  containers: ContainerMetrics[];
  collected_at: number;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function fmtBytes(b: number): string {
  if (b <= 0) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), u.length - 1);
  return `${(b / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

function fmtUptime(s: number): string {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function pctColor(v: number): string {
  if (v < 50) return "#10b981";
  if (v < 80) return "#f59e0b";
  return "#ef4444";
}

function pctClass(v: number): string {
  if (v < 50) return "text-status-success";
  if (v < 80) return "text-status-warning";
  return "text-severity-critical";
}

function barBg(v: number): string {
  if (v < 50) return "bg-status-success";
  if (v < 80) return "bg-status-warning";
  return "bg-severity-critical";
}

// ── Service display map ─────────────────────────────────────────────────────

// Keys match the `service` field emitted by the backend, which is derived
// from the pod label `app.kubernetes.io/name` (or, for subchart pods, the
// pod-name stem). See services/api/app/routers/metrics.py:_derive_slug().
const SVC_INFO: Record<string, { label: string; desc: string; icon: any }> = {
  api:         { label: "API Server",         desc: "FastAPI backend (Deployment)",              icon: Server },
  frontend:    { label: "Frontend",           desc: "Next.js web application (Deployment)",      icon: Server },
  ingestion:   { label: "Ingestion",          desc: "Feed polling — singleton + Lease",          icon: ArrowDownCircle },
  enrichment:  { label: "Enrichment",         desc: "GeoIP / WHOIS / ASN — HPA + KEDA",          icon: Activity },
  correlation: { label: "Correlation",        desc: "Log → alert pipeline — singleton + Lease",  icon: Activity },
  sandbox:     { label: "Sandbox Dispatcher", desc: "Spawns Jobs into ti-sandbox-jobs (gvisor)", icon: HardDrive },
  icap:        { label: "ICAP Server",        desc: "HTTP inspection (Service :1344)",           icon: Server },
  logserver:   { label: "Log Server",         desc: "Syslog/CEF receiver (Service :514)",        icon: Network },
  postgresql:  { label: "PostgreSQL",         desc: "StatefulSet — primary datastore",           icon: Database },
  redis:       { label: "Redis",              desc: "StatefulSet — cache & EDL acceleration",    icon: Cpu },
  nats:        { label: "NATS JetStream",     desc: "StatefulSet — inter-service message bus",   icon: Activity },
  "nats-box":  { label: "NATS Box",           desc: "NATS CLI utility pod",                      icon: Activity },
  prometheus:  { label: "Prometheus",         desc: "Metrics collection (kube-prometheus-stack)", icon: Gauge },
  grafana:     { label: "Grafana",            desc: "Dashboards & visualization",                icon: Activity },
};

const STATE_CFG: Record<string, { label: string; dot: string; text: string }> = {
  running:    { label: "Running",    dot: "bg-status-success",     text: "text-status-success" },
  exited:     { label: "Exited",     dot: "bg-severity-critical",  text: "text-severity-critical" },
  created:    { label: "Created",    dot: "bg-text-muted",         text: "text-text-muted" },
  paused:     { label: "Paused",     dot: "bg-status-warning",     text: "text-status-warning" },
  restarting: { label: "Restarting", dot: "bg-status-warning",     text: "text-status-warning" },
  dead:       { label: "Dead",       dot: "bg-severity-critical",  text: "text-severity-critical" },
  removing:   { label: "Removing",   dot: "bg-text-muted",         text: "text-text-muted" },
};
const DEFAULT_STATE_CFG = { label: "Unknown", dot: "bg-text-muted", text: "text-text-muted" };

// ── Circular gauge SVG ──────────────────────────────────────────────────────

function CircularGauge({
  value,
  label,
  detail,
  size = 128,
}: {
  value: number;
  label: string;
  detail: string;
  size?: number;
}) {
  const stroke = 7;
  const r = (size - stroke) / 2;
  const C = 2 * Math.PI * r;
  const offset = C * (1 - Math.min(value, 100) / 100);
  const color = pctColor(value);

  return (
    <div className="flex flex-col items-center gap-1.5">
      <svg width={size} height={size} className="drop-shadow-sm">
        {/* track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="currentColor"
          strokeWidth={stroke}
          className="text-border opacity-60"
        />
        {/* value arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={C}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
        {/* label */}
        <text
          x={size / 2}
          y={size / 2 - 6}
          textAnchor="middle"
          dominantBaseline="central"
          fill="currentColor"
          className="text-text-primary"
          fontSize={22}
          fontWeight={700}
        >
          {value.toFixed(1)}%
        </text>
        <text
          x={size / 2}
          y={size / 2 + 16}
          textAnchor="middle"
          dominantBaseline="central"
          fill="currentColor"
          className="text-text-muted"
          fontSize={11}
        >
          {label}
        </text>
      </svg>
      <p className="text-xs text-text-muted text-center leading-tight">
        {detail}
      </p>
    </div>
  );
}

// ── Mini progress bar ───────────────────────────────────────────────────────

function MiniBar({ pct, className }: { pct: number; className?: string }) {
  return (
    <div
      className={clsx(
        "h-1.5 rounded-full bg-border/50 overflow-hidden",
        className,
      )}
    >
      <div
        className={clsx("h-full rounded-full transition-all duration-500", barBg(pct))}
        style={{ width: `${Math.min(pct, 100)}%` }}
      />
    </div>
  );
}

// ── Retention options ───────────────────────────────────────────────────────

const RETENTION_OPTIONS = [
  { value: 1, label: "1 day" },
  { value: 7, label: "7 days" },
  { value: 30, label: "30 days" },
  { value: 90, label: "90 days" },
];

// ═════════════════════════════════════════════════════════════════════════════
// Page component
// ═════════════════════════════════════════════════════════════════════════════

export default function SystemPage() {
  // ── Metrics state ───────────────────────────────────────────────────────
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [metricsOk, setMetricsOk] = useState(true);
  const [metricsLoading, setMetricsLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  // ── Settings state ──────────────────────────────────────────────────────
  const [retention, setRetention] = useState(30);
  const [savedRetention, setSavedRetention] = useState(30);
  const [loadingSettings, setLoadingSettings] = useState(true);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);

  // ── Fetch metrics (5 s poll) ────────────────────────────────────────────
  useEffect(() => {
    let active = true;
    const poll = async () => {
      try {
        const r = await fetch(`${API}/system/metrics`, { headers: hdrs() });
        if (!r.ok) throw new Error(`${r.status}`);
        if (active) {
          setMetrics(await r.json());
          setMetricsOk(true);
          setLastRefresh(new Date());
        }
      } catch {
        if (active) setMetricsOk(false);
      }
      if (active) setMetricsLoading(false);
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, []);

  // ── Fetch settings ──────────────────────────────────────────────────────
  const fetchSettings = useCallback(async () => {
    try {
      setLoadingSettings(true);
      const r = await fetch(`${API}/system/settings`, { headers: hdrs() });
      if (!r.ok) throw new Error(`${r.status}`);
      const d: Record<string, string> = await r.json();
      const days = parseInt(d.log_retention_days ?? "30", 10);
      const v = RETENTION_OPTIONS.some((o) => o.value === days) ? days : 30;
      setRetention(v);
      setSavedRetention(v);
    } catch {
      /* keep defaults */
    } finally {
      setLoadingSettings(false);
    }
  }, []);
  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  // ── Clear feedback ──────────────────────────────────────────────────────
  useEffect(() => {
    if (!feedback) return;
    const t = setTimeout(() => setFeedback(null), 4000);
    return () => clearTimeout(t);
  }, [feedback]);

  const handleSave = async () => {
    setSaving(true);
    setFeedback(null);
    try {
      const r = await fetch(`${API}/system/settings/retention`, {
        method: "PATCH",
        headers: hdrs(),
        body: JSON.stringify({ log_retention_days: retention }),
      });
      if (!r.ok) throw new Error(await r.text().catch(() => `HTTP ${r.status}`));
      setSavedRetention(retention);
      setFeedback({ type: "success", message: "Settings saved successfully." });
    } catch (e: any) {
      setFeedback({
        type: "error",
        message: `Failed to save: ${e.message ?? e}`,
      });
    } finally {
      setSaving(false);
    }
  };
  const hasChanges = retention !== savedRetention;

  // ── Derived ─────────────────────────────────────────────────────────────
  const host = metrics?.host;
  const containers = metrics?.containers ?? [];
  const running = containers.filter((c) => c.state === "running").length;

  // ── Render ──────────────────────────────────────────────────────────────
  return (
    <div className="space-y-5">
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text-primary">
            System Overview
          </h1>
          <p className="text-sm text-text-muted mt-0.5">
            Resource utilization, service health & platform settings
          </p>
        </div>
        {lastRefresh && (
          <div className="hidden sm:flex items-center gap-1.5 text-xs text-text-muted">
            <RefreshCw className="w-3 h-3" />
            <span>
              {lastRefresh.toLocaleTimeString()}
            </span>
          </div>
        )}
      </div>

      {/* ── Host resource gauges ────────────────────────────────────────── */}
      {metricsLoading && !metrics ? (
        <div className="card p-8 flex items-center justify-center gap-2 text-text-muted text-sm">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading system metrics...
        </div>
      ) : !metricsOk && !metrics ? (
        <div className="card p-6 border-l-2 border-l-status-warning">
          <div className="flex items-center gap-2 text-status-warning text-sm">
            <AlertTriangle className="w-4 h-4" />
            Unable to reach the metrics endpoint. Ensure the API pod is
            running and has RBAC for the in-cluster Kubernetes API.
          </div>
        </div>
      ) : host ? (
        <div className="card p-6">
          <div className="flex items-center gap-2 mb-5">
            <Server className="w-4 h-4 text-text-muted" />
            <h2 className="text-sm font-semibold text-text-primary">
              Node Resources
            </h2>
            <span className="text-2xs text-text-muted ml-auto">
              Node · {host.cpu_count} CPU{host.cpu_count > 1 ? "s" : ""}
              {" \u00B7 "}
              Uptime {fmtUptime(host.uptime_seconds)}
            </span>
          </div>

          {/* Gauges row */}
          <div className="grid grid-cols-3 gap-4 sm:gap-8 justify-items-center">
            <CircularGauge
              value={host.cpu_percent}
              label="CPU"
              detail={`Load ${host.load_average.map((v) => v.toFixed(2)).join(" / ")}`}
            />
            <CircularGauge
              value={host.memory.percent}
              label="Memory"
              detail={`${fmtBytes(host.memory.used)} / ${fmtBytes(host.memory.total)}`}
            />
            <CircularGauge
              value={host.disk.percent}
              label="Disk"
              detail={`${fmtBytes(host.disk.used)} / ${fmtBytes(host.disk.total)}`}
            />
          </div>

          {/* Swap bar (only if swap exists) */}
          {host.swap.total > 0 && (
            <div className="mt-5 pt-4 border-t border-border">
              <div className="flex items-center justify-between text-xs mb-1.5">
                <span className="text-text-muted">Swap</span>
                <span className={pctClass(host.swap.percent)}>
                  {fmtBytes(host.swap.used)} / {fmtBytes(host.swap.total)} ({host.swap.percent}%)
                </span>
              </div>
              <MiniBar pct={host.swap.percent} />
            </div>
          )}
        </div>
      ) : null}

      {/* ── Pod metrics ─────────────────────────────────────────────────── */}
      {containers.length > 0 && (
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Boxes className="w-4 h-4 text-text-muted" />
            <h2 className="text-sm font-semibold text-text-primary">
              Pod Resources
            </h2>
            <span className="ml-auto text-xs text-text-muted">
              {running}/{containers.length} running
            </span>
          </div>

          {/* Table */}
          <div className="overflow-x-auto -mx-5 px-5">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left">
                  <th className="pb-2 pr-4 text-xs font-medium text-text-muted">
                    Workload
                  </th>
                  <th className="pb-2 pr-4 text-xs font-medium text-text-muted">
                    Phase
                  </th>
                  <th className="pb-2 pr-4 text-xs font-medium text-text-muted text-right w-20">
                    CPU
                  </th>
                  <th className="pb-2 pr-4 text-xs font-medium text-text-muted w-44">
                    Memory
                  </th>
                  <th className="pb-2 pr-4 text-xs font-medium text-text-muted text-right hidden lg:table-cell">
                    Net RX
                  </th>
                  <th className="pb-2 text-xs font-medium text-text-muted text-right hidden lg:table-cell">
                    Net TX
                  </th>
                </tr>
              </thead>
              <tbody>
                {containers.map((c) => {
                  const info = SVC_INFO[c.service] ?? {
                    label: c.service,
                    desc: "",
                    icon: Activity,
                  };
                  const st = STATE_CFG[c.state] ?? DEFAULT_STATE_CFG;
                  const Icon = info.icon;

                  return (
                    <tr
                      key={c.name}
                      className="border-b border-border/50 last:border-0"
                    >
                      {/* Service */}
                      <td className="py-2.5 pr-4">
                        <div className="flex items-center gap-2">
                          <Icon className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
                          <div className="min-w-0">
                            <p className="text-sm font-medium text-text-primary truncate">
                              {info.label}
                            </p>
                            {info.desc && (
                              <p className="text-2xs text-text-muted truncate hidden sm:block">
                                {info.desc}
                              </p>
                            )}
                          </div>
                        </div>
                      </td>

                      {/* State badge */}
                      <td className="py-2.5 pr-4">
                        <div className="flex items-center gap-1.5">
                          <div
                            className={clsx(
                              "w-1.5 h-1.5 rounded-full flex-shrink-0",
                              st.dot,
                              c.state === "running" && "animate-pulse",
                            )}
                          />
                          <span className={clsx("text-xs", st.text)}>
                            {st.label}
                          </span>
                        </div>
                      </td>

                      {/* CPU */}
                      <td className="py-2.5 pr-4 text-right tabular-nums">
                        <span className={pctClass(c.cpu_percent)}>
                          {c.state === "running"
                            ? `${c.cpu_percent.toFixed(1)}%`
                            : "\u2014"}
                        </span>
                      </td>

                      {/* Memory */}
                      <td className="py-2.5 pr-4">
                        {c.state === "running" ? (
                          <div>
                            <div className="flex items-center justify-between text-xs mb-1">
                              <span className="text-text-muted">
                                {fmtBytes(c.memory.used)}
                              </span>
                              <span className="text-text-muted">
                                {fmtBytes(c.memory.limit)}
                              </span>
                            </div>
                            <MiniBar pct={c.memory.percent} />
                          </div>
                        ) : (
                          <span className="text-xs text-text-muted">
                            {"\u2014"}
                          </span>
                        )}
                      </td>

                      {/* Net RX */}
                      <td className="py-2.5 pr-4 text-right text-xs text-text-muted tabular-nums hidden lg:table-cell">
                        {c.state === "running"
                          ? fmtBytes(c.network.rx_bytes)
                          : "\u2014"}
                      </td>

                      {/* Net TX */}
                      <td className="py-2.5 text-right text-xs text-text-muted tabular-nums hidden lg:table-cell">
                        {c.state === "running"
                          ? fmtBytes(c.network.tx_bytes)
                          : "\u2014"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Platform Settings ───────────────────────────────────────────── */}
      <div className="card p-5">
        <div className="flex items-center gap-2 mb-5">
          <Settings className="w-4 h-4 text-text-muted" strokeWidth={1.75} />
          <h2 className="text-sm font-semibold text-text-primary">
            Platform Settings
          </h2>
        </div>

        {loadingSettings ? (
          <div className="flex items-center gap-2 text-text-muted text-sm py-4">
            <Loader2 className="w-4 h-4 animate-spin" />
            Loading settings...
          </div>
        ) : (
          <div className="space-y-5">
            {/* Log Retention */}
            <div className="flex flex-col sm:flex-row sm:items-center gap-3">
              <div className="flex-1 min-w-0">
                <label
                  htmlFor="log-retention"
                  className="block text-sm font-medium text-text-primary"
                >
                  Log Retention
                </label>
                <p className="text-xs text-text-muted mt-0.5">
                  Logs older than this will be purged automatically on the next
                  cleanup cycle.
                </p>
              </div>
              <select
                id="log-retention"
                value={retention}
                onChange={(e) => setRetention(Number(e.target.value))}
                className="w-full sm:w-40 rounded-md border border-border bg-bg-elevated
                           text-sm text-text-primary px-3 py-2
                           focus:outline-none focus:ring-1 focus:ring-accent"
              >
                {RETENTION_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Feedback */}
            {feedback && (
              <div
                className={clsx(
                  "text-sm px-3 py-2 rounded-md",
                  feedback.type === "success"
                    ? "bg-status-success/10 text-status-success"
                    : "bg-severity-critical/10 text-severity-critical",
                )}
              >
                {feedback.message}
              </div>
            )}

            {/* Save */}
            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={handleSave}
                disabled={saving || !hasChanges}
                className={clsx(
                  "inline-flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors",
                  hasChanges && !saving
                    ? "bg-accent text-white hover:bg-accent/90"
                    : "bg-bg-elevated text-text-muted border border-border cursor-not-allowed",
                )}
              >
                {saving ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Save className="w-4 h-4" />
                )}
                {saving ? "Saving..." : "Save"}
              </button>
              {hasChanges && !saving && (
                <span className="text-xs text-text-muted">Unsaved changes</span>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── Management Interfaces ───────────────────────────────────────── */}
      <div className="card p-5">
        <h2 className="text-sm font-semibold text-text-primary mb-4">
          Management Interfaces
        </h2>
        <p className="text-xs text-text-muted mb-4">
          These are in-cluster Services. Port-forward from a workstation with
          <code className="mx-1 px-1.5 py-0.5 rounded bg-bg-elevated font-mono">kubectl</code>
          access, or expose via Ingress in
          <code className="mx-1 px-1.5 py-0.5 rounded bg-bg-elevated font-mono">values-prod.yaml</code>.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[
            {
              label: "Grafana",
              desc: "Dashboards & visualization",
              cmd: "kubectl -n ti port-forward svc/ti-grafana 3000:80",
            },
            {
              label: "Prometheus",
              desc: "Raw metrics and alerts",
              cmd: "kubectl -n ti port-forward svc/ti-kube-prometheus-stack-prometheus 9090",
            },
            {
              label: "NATS Monitor",
              desc: "JetStream / message-bus status",
              cmd: "kubectl -n ti port-forward svc/ti-nats 8222",
            },
          ].map(({ label, desc, cmd }) => (
            <div
              key={label}
              className="card p-4"
            >
              <p className="text-sm font-medium text-text-primary">{label}</p>
              <p className="text-xs text-text-muted mt-0.5">{desc}</p>
              <p className="text-2xs text-accent font-mono mt-2 break-all">{cmd}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
