"use client";

import { useState, useMemo } from "react";
import useSWR from "swr";
import { Bell, CheckCircle, XCircle, Clock, Filter, AlertTriangle, Search, X, TrendingDown, BarChart2, Shield, ChevronDown, ChevronRight, Layers } from "lucide-react";
import { getAlerts, acknowledgeAlert, resolveAlert, getAlertContext, getAlertsTimeline, getIncidents, getIncident, resolveIncident, type Alert, type AlertContext, type AlertTimeline, type Incident, type IncidentDetail } from "@/lib/api";
import Link from "next/link";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { Badge } from "@/components/ui/badge";
import { formatDistanceToNow, parseISO, format } from "date-fns";
import clsx from "clsx";

const STATUS_CONFIG: Record<string, { label: string; className: string }> = {
  open:            { label: "Open",          className: "text-severity-high bg-severity-high/10 border-severity-high/25" },
  acknowledged:    { label: "Acknowledged",  className: "text-severity-medium bg-severity-medium/10 border-severity-medium/25" },
  resolved:        { label: "Resolved",      className: "text-status-success bg-status-success/10 border-status-success/25" },
  false_positive:  { label: "False Positive", className: "text-text-muted bg-bg-elevated border-border" },
};

// ── Inline sparkline chart (no extra deps) ────────────────────────────────────

function AlertsTimelineChart({ timeline }: { timeline?: AlertTimeline }) {
  const [chartDays, setChartDays] = useState(7);
  const { data, isLoading } = useSWR(
    ["alerts-timeline", chartDays],
    () => getAlertsTimeline({ days: chartDays, interval: chartDays <= 2 ? "hour" : "day" }),
    { refreshInterval: 60000 }
  );

  const used = timeline ?? data;

  const buckets = useMemo(() => {
    if (!used?.by_severity) return [];
    const map: Record<string, Record<string, number>> = {};
    for (const p of used.by_severity) {
      if (!map[p.bucket]) map[p.bucket] = {};
      map[p.bucket][p.severity] = (map[p.bucket][p.severity] ?? 0) + p.count;
    }
    return Object.entries(map)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([bucket, sev]) => ({
        bucket,
        label: new Date(bucket).toLocaleDateString("en", { month: "short", day: "numeric", hour: chartDays <= 2 ? "2-digit" : undefined }),
        total: Object.values(sev).reduce((s, v) => s + v, 0),
        critical: sev.critical ?? 0,
        high:     sev.high     ?? 0,
        medium:   sev.medium   ?? 0,
        low:      sev.low      ?? 0,
      }));
  }, [used, chartDays]);

  const maxVal = Math.max(...buckets.map(b => b.total), 1);

  const SEV_COLORS: Record<string, string> = {
    critical: "#ef4444",
    high:     "#f97316",
    medium:   "#eab308",
    low:      "#22c55e",
  };

  return (
    <div className="card p-5 mb-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <BarChart2 className="w-4 h-4 text-accent" />
          <span className="text-sm font-semibold text-text-primary">Alerts Over Time</span>
        </div>
        <div className="flex gap-1">
          {[1, 7, 14, 30].map(d => (
            <button
              key={d}
              onClick={() => setChartDays(d)}
              className={`text-2xs px-2 py-1 rounded border transition-colors ${
                chartDays === d
                  ? "bg-accent/10 text-accent border-accent/30"
                  : "text-text-muted border-border hover:text-text-primary"
              }`}
            >{d === 1 ? "24h" : `${d}d`}</button>
          ))}
        </div>
      </div>

      {isLoading && !used ? (
        <div className="h-28 flex items-center justify-center text-text-muted text-xs">Loading…</div>
      ) : buckets.length === 0 ? (
        <div className="h-28 flex items-center justify-center text-text-muted text-xs">No alert data for this period</div>
      ) : (
        <>
          <div className="flex items-end gap-1 h-28 overflow-x-auto pb-1">
            {buckets.map(b => (
              <div key={b.bucket} className="flex flex-col items-center gap-0.5 flex-1 min-w-[18px] group relative">
                <div
                  className="w-full rounded-sm flex flex-col-reverse overflow-hidden transition-all"
                  style={{ height: `${Math.round((b.total / maxVal) * 100)}px`, minHeight: b.total > 0 ? "2px" : "0" }}
                >
                  {(["low","medium","high","critical"] as const).map(s => (
                    b[s] > 0 && (
                      <div
                        key={s}
                        style={{ height: `${Math.round((b[s] / b.total) * 100)}%`, backgroundColor: SEV_COLORS[s] }}
                      />
                    )
                  ))}
                </div>
                {/* tooltip */}
                <div className="absolute bottom-full mb-1 left-1/2 -translate-x-1/2 hidden group-hover:flex flex-col bg-bg-overlay border border-border rounded px-2 py-1 text-2xs whitespace-nowrap z-10 shadow-lg">
                  <span className="font-semibold">{b.label}</span>
                  <span>Total: {b.total}</span>
                  {b.critical > 0 && <span className="text-red-400">Critical: {b.critical}</span>}
                  {b.high > 0     && <span className="text-orange-400">High: {b.high}</span>}
                  {b.medium > 0   && <span className="text-yellow-400">Medium: {b.medium}</span>}
                  {b.low > 0      && <span className="text-green-400">Low: {b.low}</span>}
                </div>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-3 mt-2 flex-wrap">
            {Object.entries(SEV_COLORS).map(([s, c]) => (
              <span key={s} className="flex items-center gap-1 text-2xs text-text-muted">
                <span className="w-2.5 h-2.5 rounded-sm inline-block" style={{ backgroundColor: c }} />
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </span>
            ))}
            <span className="ml-auto text-2xs text-text-muted flex items-center gap-1">
              <TrendingDown className="w-3 h-3" />
              Accepting tuning suggestions reduces alert volume
            </span>
          </div>
        </>
      )}
    </div>
  );
}

// ── Incident Status Config ────────────────────────────────────────────────────

const INCIDENT_STATUS_CONFIG: Record<string, { label: string; className: string }> = {
  open:          { label: "Open",          className: "text-severity-high bg-severity-high/10 border-severity-high/25" },
  investigating: { label: "Investigating", className: "text-severity-medium bg-severity-medium/10 border-severity-medium/25" },
  resolved:      { label: "Resolved",      className: "text-status-success bg-status-success/10 border-status-success/25" },
  closed:        { label: "Closed",        className: "text-text-muted bg-bg-elevated border-border" },
};

// ── Expanded Incident Card ────────────────────────────────────────────────────

function IncidentCard({ incident }: { incident: Incident }) {
  const [expanded, setExpanded] = useState(false);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [resolving, setResolving] = useState(false);

  const handleToggle = async () => {
    if (!expanded && !detail) {
      setLoadingDetail(true);
      try {
        const d = await getIncident(incident.id);
        setDetail(d);
      } catch {
        // fail silently
      } finally {
        setLoadingDetail(false);
      }
    }
    setExpanded(!expanded);
  };

  const handleResolve = async (e: React.MouseEvent) => {
    e.stopPropagation();
    setResolving(true);
    try {
      await resolveIncident(incident.id);
    } finally {
      setResolving(false);
    }
  };

  const timeRange = (() => {
    try {
      const first = parseISO(incident.first_seen);
      const last = parseISO(incident.last_seen);
      return `${format(first, "MMM d HH:mm")} - ${format(last, "HH:mm")}`;
    } catch {
      return "";
    }
  })();

  return (
    <div
      className={clsx(
        "card border-l-2",
        incident.severity === "critical" ? "border-l-severity-critical" :
        incident.severity === "high"     ? "border-l-severity-high" :
        incident.severity === "medium"   ? "border-l-severity-medium" :
        "border-l-severity-low"
      )}
    >
      {/* Incident header */}
      <button
        onClick={handleToggle}
        className="w-full p-5 text-left flex items-start gap-4"
      >
        <div className="flex-shrink-0 mt-0.5">
          {expanded
            ? <ChevronDown className="w-4 h-4 text-text-muted" />
            : <ChevronRight className="w-4 h-4 text-text-muted" />
          }
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-2 flex-wrap">
            <SeverityBadge severity={incident.severity} />
            <span className={clsx(
              "badge border",
              INCIDENT_STATUS_CONFIG[incident.status]?.className
            )}>
              {INCIDENT_STATUS_CONFIG[incident.status]?.label ?? incident.status}
            </span>
            {incident.attack_type && (
              <Badge variant="secondary" className="text-xs">
                {incident.attack_type}
              </Badge>
            )}
            <Badge variant="outline" className="text-xs">
              {incident.total_events} alert{incident.total_events !== 1 ? "s" : ""}
            </Badge>
          </div>
          <h3 className="text-sm font-semibold text-text-primary">{incident.title}</h3>
          {incident.description && (
            <p className="text-xs text-text-muted mt-1 line-clamp-2">{incident.description}</p>
          )}
          <div className="flex items-center gap-4 mt-2 flex-wrap">
            {incident.source_ip && (
              <span className="text-2xs text-text-muted flex items-center gap-1">
                <Shield className="w-3 h-3" />
                {incident.source_ip}
              </span>
            )}
            {timeRange && (
              <span className="text-2xs text-text-muted flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {timeRange}
              </span>
            )}
            {incident.mitre_tactics.length > 0 && (
              <div className="flex gap-1 flex-wrap">
                {incident.mitre_tactics.map((t, i) => (
                  <span key={i} className="text-2xs px-1.5 py-0.5 rounded bg-accent/10 text-accent border border-accent/20">
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {(incident.status === "open" || incident.status === "investigating") && (
            <button
              onClick={handleResolve}
              disabled={resolving}
              className="btn text-xs bg-status-success/15 text-status-success border border-status-success/30 hover:bg-status-success/25 px-2 py-1 h-auto"
            >
              {resolving ? <LoadingSpinner size="sm" /> : "Resolve All"}
            </button>
          )}
        </div>
      </button>

      {/* Expanded alert list */}
      {expanded && (
        <div className="border-t border-border px-5 pb-4 pt-3">
          {loadingDetail ? (
            <div className="flex justify-center py-6">
              <LoadingSpinner />
            </div>
          ) : detail?.alerts && detail.alerts.length > 0 ? (
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-text-muted mb-2">
                Evidence ({detail.alerts.length} alerts)
              </h4>
              {detail.alerts.map((alert) => (
                <div
                  key={alert.id}
                  className={clsx(
                    "p-3 rounded-md border-l-2 bg-bg-elevated/50 border border-border",
                    alert.severity === "critical" ? "border-l-severity-critical" :
                    alert.severity === "high"     ? "border-l-severity-high" :
                    alert.severity === "medium"   ? "border-l-severity-medium" :
                    "border-l-severity-low"
                  )}
                >
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <SeverityBadge severity={alert.severity} />
                    <span className={clsx(
                      "badge border text-2xs",
                      STATUS_CONFIG[alert.status]?.className
                    )}>
                      {STATUS_CONFIG[alert.status]?.label ?? alert.status}
                    </span>
                    {alert.rule_name && (
                      <span className="text-2xs text-text-muted">
                        {alert.rule_name.replace(/_/g, " ")}
                      </span>
                    )}
                  </div>
                  <Link href={`/alerts/${alert.id}`} className="block">
                    <span className="text-xs font-medium text-text-primary hover:text-primary hover:underline">
                      {alert.title}
                    </span>
                  </Link>
                  <div className="flex items-center gap-3 mt-1 text-2xs text-text-muted">
                    {alert.indicator_value && (
                      <span className="mono-value text-accent">{alert.indicator_value}</span>
                    )}
                    <span>
                      {formatDistanceToNow(parseISO(alert.created_at), { addSuffix: true })}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-text-muted text-center py-4">No alert details available</p>
          )}
        </div>
      )}
    </div>
  );
}

// ── Incidents Panel ──────────────────────────────────────────────────────────

function IncidentsPanel() {
  const [incStatus, setIncStatus] = useState("open");
  const [incSeverity, setIncSeverity] = useState("");

  const { data, isLoading, error } = useSWR(
    ["incidents", incStatus, incSeverity],
    () => getIncidents({
      status: incStatus || undefined,
      severity: incSeverity || undefined,
      limit: 50,
    }),
    { refreshInterval: 15000 }
  );

  const incidents = data?.items ?? [];

  return (
    <div className="space-y-4">
      {/* Incident filters */}
      <div className="card p-4 flex flex-wrap gap-3">
        <div className="flex gap-2">
          {["open", "investigating", "resolved", ""].map((s) => (
            <button
              key={s}
              onClick={() => setIncStatus(s)}
              className={clsx(
                "btn text-xs",
                incStatus === s ? "btn-primary" : "btn-ghost"
              )}
            >
              {s === "" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
        <select
          value={incSeverity}
          onChange={(e) => setIncSeverity(e.target.value)}
          className="ti-input text-xs ml-auto"
        >
          <option value="">All Severities</option>
          {["critical", "high", "medium", "low"].map((s) => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
      </div>

      {/* Incident list */}
      {isLoading ? (
        <div className="card flex items-center justify-center py-16">
          <LoadingSpinner />
        </div>
      ) : error ? (
        <div className="card flex items-center justify-center py-16 gap-2 text-text-muted text-sm">
          <AlertTriangle className="w-4 h-4 text-severity-high" />
          Failed to load incidents
        </div>
      ) : incidents.length === 0 ? (
        <div className="card flex flex-col items-center justify-center py-16 gap-3">
          <CheckCircle className="w-8 h-8 text-status-success" />
          <p className="text-sm text-text-muted">
            No {incStatus || ""} incidents
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {incidents.map((inc) => (
            <IncidentCard key={inc.id} incident={inc} />
          ))}
        </div>
      )}
    </div>
  );
}

export default function AlertsPage() {
  const [viewMode, setViewMode] = useState<"alerts" | "incidents">("alerts");
  const [status, setStatus] = useState("open");
  const [severity, setSev]  = useState("");
  const [search, setSearch] = useState("");
  const [acting, setActing] = useState<string | null>(null);

  const { data, isLoading, error, mutate } = useSWR(
    ["alerts", status, severity],
    () => getAlerts({ status: status || undefined, severity: severity || undefined, limit: 100 }),
    { refreshInterval: 15000 }
  );

  const handleAck = async (id: string) => {
    setActing(id);
    try {
      await acknowledgeAlert(id, "analyst");
      mutate();
    } finally {
      setActing(null);
    }
  };

  const handleResolve = async (id: string) => {
    setActing(id);
    try {
      await resolveAlert(id);
      mutate();
    } finally {
      setActing(null);
    }
  };

  const allAlerts = data?.items ?? [];

  // Client-side search filter across title, description, indicator_value, rule_name
  const alerts = search.trim()
    ? allAlerts.filter((a: Alert) => {
        const q = search.toLowerCase();
        return (
          a.title?.toLowerCase().includes(q) ||
          a.description?.toLowerCase().includes(q) ||
          a.indicator_value?.toLowerCase().includes(q) ||
          a.rule_name?.toLowerCase().includes(q) ||
          a.source_service?.toLowerCase().includes(q)
        );
      })
    : allAlerts;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text-primary">
            {viewMode === "alerts" ? "Alerts" : "Incidents"}
          </h1>
          <p className="text-sm text-text-muted mt-0.5">
            {viewMode === "alerts"
              ? (data
                  ? search
                    ? `${alerts.length} of ${data.total} ${status || "total"} alerts`
                    : `${data.total} ${status || "total"} alerts`
                  : "Security alerts and detections")
              : "Related alerts grouped into security incidents"
            }
          </p>
        </div>
        {/* View mode toggle */}
        <div className="flex rounded-md border border-border overflow-hidden">
          <button
            onClick={() => setViewMode("alerts")}
            className={clsx(
              "flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors",
              viewMode === "alerts"
                ? "bg-accent/15 text-accent"
                : "text-text-muted hover:text-text-primary hover:bg-bg-elevated"
            )}
          >
            <Bell className="w-3.5 h-3.5" />
            Alerts
          </button>
          <button
            onClick={() => setViewMode("incidents")}
            className={clsx(
              "flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors border-l border-border",
              viewMode === "incidents"
                ? "bg-accent/15 text-accent"
                : "text-text-muted hover:text-text-primary hover:bg-bg-elevated"
            )}
          >
            <Layers className="w-3.5 h-3.5" />
            Incidents
          </button>
        </div>
      </div>

      {viewMode === "incidents" ? (
        <IncidentsPanel />
      ) : (
      <>
      {/* Timeline chart */}
      <AlertsTimelineChart />

      {/* Filters */}
      <div className="card p-4 flex flex-wrap gap-3">
        <div className="flex gap-2">
          {["open", "acknowledged", "resolved", ""].map((s) => (
            <button
              key={s}
              onClick={() => setStatus(s)}
              className={clsx(
                "btn text-xs",
                status === s ? "btn-primary" : "btn-ghost"
              )}
            >
              {s === "" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted pointer-events-none" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            type="text"
            placeholder="Search title, IP, rule, indicator…"
            className="ti-input w-full pl-9 pr-8 py-1.5 text-xs"
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary transition-colors"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <select
          value={severity}
          onChange={(e) => setSev(e.target.value)}
          className="ti-input text-xs"
        >
          <option value="">All Severities</option>
          {["critical", "high", "medium", "low"].map((s) => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
      </div>

      {/* Alert list */}
      <div className="space-y-3">
        {isLoading ? (
          <div className="card flex items-center justify-center py-16">
            <LoadingSpinner />
          </div>
        ) : error ? (
          <div className="card flex items-center justify-center py-16 gap-2 text-text-muted text-sm">
            <AlertTriangle className="w-4 h-4 text-severity-high" />
            Failed to load alerts
          </div>
        ) : alerts.length === 0 ? (
          <div className="card flex flex-col items-center justify-center py-16 gap-3">
            <CheckCircle className="w-8 h-8 text-status-success" />
            <p className="text-sm text-text-muted">
              {search ? `No alerts matching "${search}"` : `No ${status} alerts`}
            </p>
            {search && (
              <button onClick={() => setSearch("")} className="btn-ghost text-xs">
                Clear search
              </button>
            )}
          </div>
        ) : (
          alerts.map((alert: Alert) => (
            <div
              key={alert.id}
              className={clsx(
                "card p-5 border-l-2",
                alert.severity === "critical" ? "border-l-severity-critical" :
                alert.severity === "high"     ? "border-l-severity-high" :
                alert.severity === "medium"   ? "border-l-severity-medium" :
                "border-l-severity-low"
              )}
            >
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-2">
                    <SeverityBadge severity={alert.severity} />
                    <span className={clsx(
                      "badge border",
                      STATUS_CONFIG[alert.status]?.className
                    )}>
                      {STATUS_CONFIG[alert.status]?.label ?? alert.status}
                    </span>
{alert.rule_name && (
                      <Badge variant="secondary" className="text-xs">
                        {alert.rule_name.replace(/_/g, " ")}
                      </Badge>
                    )}
                    {(alert.context as AlertContext)?.attack_type ? (
                      <Badge variant="outline" className="text-xs">
                        {String((alert.context as AlertContext).attack_type).replace(/_/g, " ")}
                      </Badge>
                    ) : null}
                    {Array.isArray((alert.context as AlertContext)?.stages) && ((alert.context as AlertContext).stages?.length ?? 0) > 1 ? (
                      <Badge variant="ghost" className="text-xs">
                        {(alert.context as AlertContext).stages?.length || 1} stages
                      </Badge>
                    ) : null}
                  </div>

                  <Link href={`/alerts/${alert.id}`} className="block">
                    <h3 className="text-sm font-semibold text-text-primary hover:text-primary hover:underline transition-colors line-clamp-2">{alert.title}</h3>
                  </Link>

                  {alert.description && (
                    <p className="text-xs text-text-muted mt-1 whitespace-pre-wrap line-clamp-2">
                      {alert.description}
                    </p>
                  )}

                  {alert.indicator_value && (
                    <div className="mt-2 flex items-center gap-2">
                      <span className="text-2xs text-text-muted">Indicator:</span>
                      <span className="mono-value text-xs text-accent">
                        {alert.indicator_value}
                      </span>
                    </div>
                  )}

                  <div className="flex items-center gap-4 mt-2 text-2xs text-text-muted">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {formatDistanceToNow(parseISO(alert.created_at), { addSuffix: true })}
                    </span>
                    <span>{alert.source_service}</span>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 flex-shrink-0 ml-auto">
                  {alert.status === "open" && (
                    <>
                      <button
                        onClick={() => handleAck(alert.id)}
                        disabled={acting === alert.id}
                        className="btn-ghost text-xs px-2 py-1 h-auto border border-border hover:bg-accent"
                      >
                        {acting === alert.id ? <LoadingSpinner size="sm" /> : "Ack"}
                      </button>
                      <button
                        onClick={() => handleResolve(alert.id)}
                        disabled={acting === alert.id}
                        className="btn text-xs bg-status-success/15 text-status-success border border-status-success/30 hover:bg-status-success/25 px-2 py-1 h-auto"
                      >
                        Resolve
                      </button>
                    </>
                  )}
                  <Link 
                    href={`/alerts/${alert.id}`} 
                    className="btn-ghost text-xs px-2 py-1 h-auto hover:bg-accent text-primary hover:text-primary/90"
                  >
                    View
                  </Link>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
      </>
      )}
    </div>
  );
}
