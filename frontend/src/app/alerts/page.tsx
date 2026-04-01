"use client";

import { useState } from "react";
import useSWR from "swr";
import { Bell, CheckCircle, XCircle, Clock, Filter, AlertTriangle, Search, X } from "lucide-react";
import { getAlerts, acknowledgeAlert, resolveAlert, getAlertContext, type Alert, type AlertContext } from "@/lib/api";
import Link from "next/link";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { Badge } from "@/components/ui/badge";
import { formatDistanceToNow, parseISO } from "date-fns";
import clsx from "clsx";

const STATUS_CONFIG: Record<string, { label: string; className: string }> = {
  open:            { label: "Open",          className: "text-severity-high bg-severity-high/10 border-severity-high/25" },
  acknowledged:    { label: "Acknowledged",  className: "text-severity-medium bg-severity-medium/10 border-severity-medium/25" },
  resolved:        { label: "Resolved",      className: "text-status-success bg-status-success/10 border-status-success/25" },
  false_positive:  { label: "False Positive", className: "text-text-muted bg-bg-elevated border-border" },
};

export default function AlertsPage() {
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
          <h1 className="text-xl font-semibold text-text-primary">Alerts</h1>
          <p className="text-sm text-text-muted mt-0.5">
            {data
              ? search
                ? `${alerts.length} of ${data.total} ${status || "total"} alerts`
                : `${data.total} ${status || "total"} alerts`
              : "Security alerts and detections"}
          </p>
        </div>
      </div>

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
    </div>
  );
}
