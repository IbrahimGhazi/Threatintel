// @ts-nocheck
"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import useSWR from "swr";
import { ArrowLeft, ExternalLink, Loader2, AlertTriangle, ShieldCheck, Terminal, Check, X, Edit2, ChevronDown, ChevronUp } from "lucide-react";
import Link from "next/link";
import { formatDistanceToNow, parseISO } from "date-fns";
import clsx from "clsx";

import {
  getAlertContext, whitelistFromAlert, getRecommendations,
  approveRecommendation, editRecommendation, ignoreRecommendation,
  type CreateWhitelistBody, type Recommendation,
} from "@/lib/api";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { IncidentTimeline } from "@/components/charts/IncidentTimeline";
import { IncidentEventTimeline } from "@/components/incidents/IncidentEventTimeline";
import { IncidentMITRECard } from "@/components/incidents/IncidentMITRECard";
import { IncidentStageProgress } from "@/components/incidents/IncidentStageProgress";
import { IncidentSummaryCards } from "@/components/incidents/IncidentSummaryCards";

const STATUS_CLASSES: Record<string, string> = {
  open:           "text-severity-high bg-severity-high/10 border-severity-high/25",
  acknowledged:   "text-severity-medium bg-severity-medium/10 border-severity-medium/25",
  resolved:       "text-status-success bg-status-success/10 border-status-success/25",
  false_positive: "text-text-muted bg-bg-elevated border-border",
};

const STATUS_LABELS: Record<string, string> = {
  open: "Open", acknowledged: "Acknowledged",
  resolved: "Resolved", false_positive: "False Positive",
};

export default function AlertDetailPage() {
  const params   = useParams();
  const alertId  = params.id as string;
  const [showWhitelist, setShowWhitelist] = useState(false);
  const [wlType, setWlType] = useState("ip");
  const [wlValue, setWlValue] = useState("");
  const [wlScope, setWlScope] = useState("");
  const [wlReason, setWlReason] = useState("");
  const [wlSubmitting, setWlSubmitting] = useState(false);
  const [wlDone, setWlDone] = useState(false);

  // Recommendations state
  const [recEdit, setRecEdit] = useState<Record<string, string>>({});      // id → edit draft
  const [recEditMode, setRecEditMode] = useState<Record<string, boolean>>({}); // id → editing?
  const [recBusy, setRecBusy] = useState<Record<string, boolean>>({});
  const [showHistory, setShowHistory] = useState(false);

  const { data, isLoading, error, mutate } = useSWR(
    alertId ? `/alerts/${alertId}/context` : null,
    () => getAlertContext(alertId),
  );

  const { data: recsData, mutate: mutateRecs } = useSWR(
    alertId ? `/recommendations?alert_id=${alertId}` : null,
    () => getRecommendations({ alert_id: alertId, limit: 50 }),
  );

  const pendingRecs = (recsData?.items ?? []).filter(r => r.status === "pending" || r.status === "edited");
  const historyRecs = (recsData?.items ?? []).filter(r => r.status === "approved" || r.status === "ignored");

  const handleApprove = async (rec: Recommendation) => {
    setRecBusy(b => ({ ...b, [rec.id]: true }));
    try {
      const editedConfig = recEdit[rec.id];
      await approveRecommendation(rec.id, { analyst: "analyst", ...(editedConfig ? { edited_config: editedConfig } : {}) });
      mutateRecs();
    } finally {
      setRecBusy(b => ({ ...b, [rec.id]: false }));
      setRecEditMode(m => ({ ...m, [rec.id]: false }));
    }
  };

  const handleIgnore = async (id: string) => {
    setRecBusy(b => ({ ...b, [id]: true }));
    try {
      await ignoreRecommendation(id);
      mutateRecs();
    } finally {
      setRecBusy(b => ({ ...b, [id]: false }));
    }
  };

  const handleSaveEdit = async (rec: Recommendation) => {
    const draft = recEdit[rec.id] ?? "";
    if (!draft.trim()) return;
    setRecBusy(b => ({ ...b, [rec.id]: true }));
    try {
      await editRecommendation(rec.id, draft);
      mutateRecs();
      setRecEditMode(m => ({ ...m, [rec.id]: false }));
    } finally {
      setRecBusy(b => ({ ...b, [rec.id]: false }));
    }
  };

  const handleWhitelist = async () => {
    if (!wlValue.trim()) return;
    setWlSubmitting(true);
    try {
      const body: CreateWhitelistBody = {
        entry_type: wlType,
        value: wlValue.trim(),
        scope_rule: wlScope || null,
        reason: wlReason || null,
        created_by: "analyst",
        source_alert_id: alertId,
      };
      await whitelistFromAlert(alertId, body);
      setWlDone(true);
      mutate();
    } finally {
      setWlSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="w-6 h-6 animate-spin text-text-muted" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center min-h-[400px] gap-2 text-text-muted text-sm">
        <AlertTriangle className="w-5 h-5 text-severity-high" />
        Alert not found
      </div>
    );
  }

  const { alert, context: ctx } = data;

  const tw = ctx.time_window;
  const timeWindow = tw && typeof tw === "object"
    ? (tw as { start: string; end: string; duration_seconds: number })
    : null;

  return (
    <div className="space-y-5">

      {/* ── Breadcrumb ──────────────────────────────────────── */}
      <div className="flex items-center gap-2 text-sm text-text-muted">
        <Link href="/alerts" className="flex items-center gap-1 hover:text-text-primary transition-colors">
          <ArrowLeft className="w-3.5 h-3.5" />
          Alerts
        </Link>
        <span>/</span>
        <span className="text-text-primary font-medium truncate max-w-xs">{alert.title}</span>
      </div>

      {/* ── Header ──────────────────────────────────────────── */}
      <div className="card p-5">
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
          <div className="space-y-2 flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={alert.severity} />
              <span className={clsx("badge border text-xs", STATUS_CLASSES[alert.status] ?? "badge")}>
                {STATUS_LABELS[alert.status] ?? alert.status}
              </span>
              {ctx.attack_type && (
                <span className="badge bg-bg-elevated border-border text-text-secondary text-xs">
                  {String(ctx.attack_type).replace(/_/g, " ")}
                </span>
              )}
              {alert.rule_name && (
                <span className="badge bg-accent/10 border-accent/20 text-accent text-xs font-mono">
                  {alert.rule_name}
                </span>
              )}
            </div>

            <h1 className="text-lg font-bold text-text-primary leading-snug">
              {alert.title}
            </h1>

            <div className="flex flex-wrap items-center gap-3 text-xs text-text-muted">
              <span>Detected {formatDistanceToNow(parseISO(alert.created_at), { addSuffix: true })}</span>
              {timeWindow && (
                <>
                  <Separator orientation="vertical" className="h-3" />
                  <span>{(timeWindow.duration_seconds / 60) | 0}m window</span>
                </>
              )}
              {ctx.event_count && (
                <>
                  <Separator orientation="vertical" className="h-3" />
                  <span>{ctx.event_count as number} events correlated</span>
                </>
              )}
            </div>
          </div>
        </div>

        {ctx.recommended_action && (
          <div className="mt-4 p-3 rounded-lg bg-bg-elevated border border-border text-xs text-text-secondary leading-relaxed">
            <span className="font-semibold text-text-primary">Recommended action: </span>
            {String(ctx.recommended_action)}
          </div>
        )}

        {/* Whitelist button */}
        {alert.status !== "false_positive" && !wlDone && (
          <div className="mt-4">
            <button
              onClick={() => {
                // Pre-fill value from alert context
                const srcIp = ctx.source_ip ? String(ctx.source_ip) : "";
                setWlValue(srcIp);
                setWlType(srcIp ? "ip" : "rule_name");
                setWlScope(alert.rule_name || "");
                setShowWhitelist(!showWhitelist);
              }}
              className="btn btn-ghost text-xs flex items-center gap-1.5 border border-border hover:bg-bg-elevated"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              Whitelist &amp; Dismiss
            </button>
          </div>
        )}

        {wlDone && (
          <div className="mt-4 p-3 rounded-lg bg-status-success/10 border border-status-success/30 text-xs text-status-success">
            Alert marked as false positive and whitelist entry created.
          </div>
        )}

        {/* Whitelist form */}
        {showWhitelist && !wlDone && (
          <div className="mt-4 p-4 rounded-lg bg-bg-elevated border border-accent/30 space-y-3">
            <h3 className="text-sm font-semibold text-text-primary">Add to Whitelist</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-text-muted mb-1">Type</label>
                <select value={wlType} onChange={(e) => setWlType(e.target.value)} className="ti-input text-xs w-full">
                  <option value="ip">IP Address</option>
                  <option value="cidr">CIDR Range</option>
                  <option value="hostname">Hostname</option>
                  <option value="rule_name">Rule Name</option>
                  <option value="indicator_value">Indicator Value</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-text-muted mb-1">Value</label>
                <input
                  type="text"
                  value={wlValue}
                  onChange={(e) => setWlValue(e.target.value)}
                  className="ti-input text-xs w-full"
                  placeholder="Enter value to whitelist..."
                />
              </div>
              <div>
                <label className="block text-xs text-text-muted mb-1">Scope Rule (optional)</label>
                <input
                  type="text"
                  value={wlScope}
                  onChange={(e) => setWlScope(e.target.value)}
                  className="ti-input text-xs w-full"
                  placeholder="Restrict to specific rule..."
                />
              </div>
              <div>
                <label className="block text-xs text-text-muted mb-1">Reason</label>
                <input
                  type="text"
                  value={wlReason}
                  onChange={(e) => setWlReason(e.target.value)}
                  className="ti-input text-xs w-full"
                  placeholder="e.g., Internal scanner..."
                />
              </div>
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleWhitelist}
                disabled={wlSubmitting || !wlValue.trim()}
                className="btn btn-primary text-xs"
              >
                {wlSubmitting ? "Saving..." : "Whitelist & Mark False Positive"}
              </button>
              <button onClick={() => setShowWhitelist(false)} className="btn btn-ghost text-xs">
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Summary KPI cards ───────────────────────────────── */}
      <IncidentSummaryCards context={ctx} alertSeverity={alert.severity} />

      {/* ── Attack progression ──────────────────────────────── */}
      {Array.isArray(ctx.stages) && ctx.stages.length > 0 && (
        <IncidentStageProgress
          stages={ctx.stages as string[]}
          progression={ctx.stage_progression as string[] | Record<string, unknown>[]}
        />
      )}

      {/* ── Timeline chart ──────────────────────────────────── */}
      {Array.isArray(ctx.event_chain) && ctx.event_chain.length > 0 && timeWindow && (
        <div className="card p-5">
          <div className="mb-4">
            <h2 className="text-sm font-semibold text-text-primary">Attack timeline</h2>
            <p className="text-xs text-text-muted mt-1">
              Visual distribution of correlated events across the detection window
            </p>
          </div>
          <IncidentTimeline
            events={ctx.event_chain as Parameters<typeof IncidentTimeline>[0]["events"]}
            timeWindow={timeWindow}
            height={220}
          />
        </div>
      )}

      {/* ── MITRE ATT&CK ────────────────────────────────────── */}
      <IncidentMITRECard mappings={ctx.mitre_attack as Parameters<typeof IncidentMITRECard>[0]["mappings"]} />

      {/* ── Event chain ─────────────────────────────────────── */}
      <IncidentEventTimeline
        events={ctx.event_chain as Parameters<typeof IncidentEventTimeline>[0]["events"]}
      />

      {/* ── Related raw logs ────────────────────────────────── */}
      {Array.isArray(ctx.related_logs) && ctx.related_logs.length > 0 &&
        typeof (ctx.related_logs as unknown[])[0] === "object" && (
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-text-primary">
                Related log entries ({(ctx.related_logs as unknown[]).length})
              </h2>
              <p className="text-xs text-text-muted mt-1">Raw source logs that triggered or contributed to this incident</p>
            </div>
          </div>
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-bg-elevated">
                  <th className="text-left py-2.5 px-4 text-text-muted font-medium w-20">ID</th>
                  <th className="text-left py-2.5 px-4 text-text-muted font-medium w-28">Source</th>
                  <th className="text-left py-2.5 px-4 text-text-muted font-medium">Log</th>
                  <th className="text-left py-2.5 px-4 text-text-muted font-medium w-20">TI Hit</th>
                </tr>
              </thead>
              <tbody>
                {(ctx.related_logs as Array<{
                  id: string; source_type: string; source_ip: string | null;
                  raw_log: string | null; processed_at: string | null; is_malicious: boolean;
                }>).slice(0, 15).map((log) => (
                  <tr key={log.id} className="border-b border-border last:border-0 hover:bg-bg-elevated/50">
                    <td className="py-2.5 px-4 font-mono text-text-muted truncate">{log.id.slice(-8)}</td>
                    <td className="py-2.5 px-4 text-text-secondary">{log.source_type}</td>
                    <td className="py-2.5 px-4 max-w-md">
                      <span className="font-mono text-text-muted line-clamp-2 break-all">
                        {log.raw_log || "[no content]"}
                      </span>
                    </td>
                    <td className="py-2.5 px-4">
                      <Badge variant={log.is_malicious ? "destructive" : "default"}>
                        {log.is_malicious ? "Yes" : "No"}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {(ctx.related_logs as unknown[]).length > 15 && (
              <p className="py-3 text-center text-xs text-text-muted">
                Showing 15 of {(ctx.related_logs as unknown[]).length} logs
              </p>
            )}
          </div>
        </div>
      )}

      {/* ── Response Recommendations ────────────────────────── */}
      {recsData && recsData.total > 0 && (
        <div className="card p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-accent" />
            <h2 className="text-sm font-semibold text-text-primary">
              Response Recommendations
            </h2>
            <span className="ml-auto badge bg-accent/10 border-accent/20 text-accent text-xs">
              {pendingRecs.length} pending
            </span>
          </div>

          {pendingRecs.length === 0 && (
            <p className="text-xs text-text-muted italic">All recommendations have been actioned.</p>
          )}

          {pendingRecs.map((rec) => (
            <div key={rec.id} className="rounded-lg border border-border bg-bg-elevated p-4 space-y-3">
              <div className="flex flex-wrap items-start gap-2">
                <span className="badge bg-accent/10 border-accent/20 text-accent text-2xs font-mono">
                  {rec.rec_type.replace(/_/g, " ")}
                </span>
                <span className="badge bg-bg-surface border-border text-text-muted text-2xs">
                  {rec.device_type.replace(/_/g, " ")}
                </span>
                {rec.status === "edited" && (
                  <span className="badge bg-status-warning/15 border-status-warning/30 text-status-warning text-2xs">
                    edited
                  </span>
                )}
                <span className="ml-auto text-2xs text-text-muted">{rec.id.slice(-8)}</span>
              </div>

              <div>
                <p className="text-xs font-semibold text-text-primary">{rec.title}</p>
                <p className="text-xs text-text-secondary mt-0.5 leading-relaxed">{rec.description}</p>
              </div>

              {/* Config block */}
              {!recEditMode[rec.id] ? (
                <pre className="rounded bg-bg-surface border border-border p-3 text-2xs font-mono text-text-secondary overflow-x-auto whitespace-pre-wrap break-all">
                  {rec.edited_config ?? rec.config_example ?? ""}
                </pre>
              ) : (
                <textarea
                  className="ti-input text-2xs font-mono w-full min-h-[120px] resize-y"
                  value={recEdit[rec.id] ?? rec.edited_config ?? rec.config_example ?? ""}
                  onChange={(e) => setRecEdit(r => ({ ...r, [rec.id]: e.target.value }))}
                />
              )}

              <div className="flex flex-wrap gap-2">
                {recEditMode[rec.id] ? (
                  <>
                    <button
                      onClick={() => handleSaveEdit(rec)}
                      disabled={recBusy[rec.id]}
                      className="btn btn-primary text-xs flex items-center gap-1.5"
                    >
                      <Check className="w-3 h-3" />
                      {recBusy[rec.id] ? "Saving..." : "Save edit"}
                    </button>
                    <button
                      onClick={() => setRecEditMode(m => ({ ...m, [rec.id]: false }))}
                      className="btn btn-ghost text-xs"
                    >
                      Cancel
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      onClick={() => handleApprove(rec)}
                      disabled={recBusy[rec.id]}
                      className="btn btn-primary text-xs flex items-center gap-1.5"
                    >
                      <Check className="w-3 h-3" />
                      {recBusy[rec.id] ? "Approving..." : "Approve"}
                    </button>
                    <button
                      onClick={() => {
                        setRecEdit(r => ({ ...r, [rec.id]: rec.edited_config ?? rec.config_example ?? "" }));
                        setRecEditMode(m => ({ ...m, [rec.id]: true }));
                      }}
                      className="btn btn-ghost text-xs flex items-center gap-1.5 border border-border"
                    >
                      <Edit2 className="w-3 h-3" />
                      Edit config
                    </button>
                    <button
                      onClick={() => handleIgnore(rec.id)}
                      disabled={recBusy[rec.id]}
                      className="btn btn-ghost text-xs flex items-center gap-1.5 text-text-muted"
                    >
                      <X className="w-3 h-3" />
                      Ignore
                    </button>
                  </>
                )}
              </div>
            </div>
          ))}

          {/* History */}
          {historyRecs.length > 0 && (
            <div>
              <button
                onClick={() => setShowHistory(h => !h)}
                className="flex items-center gap-1.5 text-xs text-text-muted hover:text-text-secondary"
              >
                {showHistory ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                {historyRecs.length} actioned recommendation{historyRecs.length !== 1 ? "s" : ""}
              </button>
              {showHistory && (
                <div className="mt-3 space-y-2">
                  {historyRecs.map((rec) => (
                    <div key={rec.id} className="rounded-lg border border-border/50 bg-bg-elevated/50 p-3 opacity-70">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={clsx(
                          "badge text-2xs",
                          rec.status === "approved"
                            ? "bg-status-success/15 border-status-success/30 text-status-success"
                            : "bg-text-muted/10 border-text-muted/30 text-text-muted"
                        )}>
                          {rec.status}
                        </span>
                        <span className="text-xs text-text-secondary font-medium">{rec.title}</span>
                        <span className="ml-auto text-2xs text-text-muted font-mono">{rec.device_type}</span>
                      </div>
                      {rec.approved_by && (
                        <p className="text-2xs text-text-muted mt-1">by {rec.approved_by}</p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Affected hosts ──────────────────────────────────── */}
      {Array.isArray(ctx.affected_hosts) && (ctx.affected_hosts as string[]).filter(Boolean).length > 0 && (
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-text-primary mb-3">Affected infrastructure</h2>
          <div className="flex flex-wrap gap-2">
            {(ctx.affected_hosts as string[]).filter(Boolean).map((host, i) => (
              <span key={i} className="badge bg-bg-elevated border-border text-text-secondary font-mono text-xs">
                {host}
              </span>
            ))}
          </div>
          {ctx.source_ip && (
            <div className="mt-3 flex items-center gap-2 text-xs text-text-muted">
              <span>Origin:</span>
              <code className="font-mono text-accent bg-accent/10 px-1.5 py-0.5 rounded">
                {String(ctx.source_ip)}
              </code>
            </div>
          )}
        </div>
      )}

    </div>
  );
}