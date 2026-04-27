// @ts-nocheck
"use client";
/**
 * Indicator Investigation Page – detailed view for a single indicator.
 * Shows enrichment data, sources, associated alerts, toggle active state,
 * and triggered alerts section.
 */
import { useState } from "react";
import { useParams } from "next/navigation";
import useSWR from "swr";
import Link from "next/link";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import {
  ChevronLeft, Globe, Hash, Link2, Shield, Clock,
  Database, Tag, AlertTriangle, CheckCircle, XCircle,
  Power, Loader2, ShieldAlert,
} from "lucide-react";
import { formatDistanceToNow, format, parseISO } from "date-fns";
import clsx from "clsx";
import {
  getIndicator, markFalsePositive, toggleIndicatorActive, deleteIndicator,
  getIndicatorAlerts, type Indicator, type Alert,
} from "@/lib/api";

function Section({ title, icon: Icon, children }: {
  title: string; icon: any; children: React.ReactNode;
}) {
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 mb-4 pb-3 border-b border-border">
        <Icon className="w-4 h-4 text-text-muted" strokeWidth={1.75} />
        <h2 className="text-sm font-semibold text-text-primary">{title}</h2>
      </div>
      {children}
    </div>
  );
}

function FieldRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start gap-4 py-2 border-b border-border/50 last:border-0">
      <span className="text-2xs text-text-muted uppercase tracking-wide font-semibold w-28 flex-shrink-0 pt-0.5">
        {label}
      </span>
      <span className="text-sm text-text-primary font-mono break-all flex-1">{value}</span>
    </div>
  );
}

function EnrichmentData({ enrichment }: { enrichment: Record<string, any> }) {
  if (!enrichment || Object.keys(enrichment).length === 0) {
    return (
      <p className="text-sm text-text-muted italic">No enrichment data available</p>
    );
  }

  return (
    <div className="space-y-4">
      {Object.entries(enrichment).map(([module, data]) => (
        <div key={module}>
          <h3 className="text-2xs text-text-muted uppercase tracking-wider font-semibold mb-2">
            {module.toUpperCase()}
          </h3>
          <div className="bg-bg-elevated rounded-md p-3 space-y-1">
            {Object.entries(data as Record<string, any>).map(([k, v]) => (
              <div key={k} className="flex gap-3 text-xs">
                <span className="text-text-muted w-24 flex-shrink-0 font-mono">{k}</span>
                <span className="text-text-primary font-mono break-all">
                  {typeof v === "object" ? JSON.stringify(v) : String(v ?? "—")}
                </span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

const SEV_CLASSES: Record<string, string> = {
  critical: "text-severity-critical",
  high:     "text-severity-high",
  medium:   "text-severity-medium",
  low:      "text-severity-low",
  info:     "text-text-muted",
};

export default function IndicatorDetailPage() {
  const params      = useParams();
  const indicatorId = params.id as string;

  const { data: indicator, isLoading, error, mutate } = useSWR(
    indicatorId ? `/indicators/${indicatorId}` : null,
    () => getIndicator(indicatorId),
  );

  const { data: alertsData } = useSWR(
    indicatorId ? `/indicators/${indicatorId}/alerts` : null,
    () => getIndicatorAlerts(indicatorId, { limit: 20 }),
  );

  const [toggling, setToggling]   = useState(false);
  const [fpBusy, setFpBusy]       = useState(false);

  const handleToggle = async () => {
    setToggling(true);
    try {
      await toggleIndicatorActive(indicatorId);
      mutate();
    } finally {
      setToggling(false);
    }
  };

  const handleFP = async () => {
    setFpBusy(true);
    try {
      await markFalsePositive(indicatorId);
      mutate();
    } finally {
      setFpBusy(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="w-6 h-6 animate-spin text-text-muted" />
      </div>
    );
  }

  if (error || !indicator) {
    return (
      <div className="flex items-center justify-center min-h-[400px] gap-2 text-text-muted text-sm">
        <AlertTriangle className="w-5 h-5 text-severity-high" />
        Indicator not found
      </div>
    );
  }

  const firstSeen = indicator.first_seen ? parseISO(indicator.first_seen) : null;
  const lastSeen  = indicator.last_seen  ? parseISO(indicator.last_seen)  : null;

  return (
    <div className="space-y-5 max-w-5xl">
      {/* Breadcrumb */}
      <Link
        href="/indicators"
        className="inline-flex items-center gap-1 text-xs text-text-muted hover:text-text-secondary transition-colors"
      >
        <ChevronLeft className="w-3.5 h-3.5" />
        Indicators
      </Link>

      {/* Header */}
      <div className="card p-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-2 flex-wrap">
              <span className="badge bg-bg-elevated border-border text-accent font-mono text-xs">
                {indicator.type.toUpperCase()}
              </span>
              <SeverityBadge severity={indicator.severity} />
              {indicator.false_positive && (
                <span className="badge bg-status-success/15 border-status-success/30 text-status-success">
                  False Positive
                </span>
              )}
              {!indicator.active && (
                <span className="badge bg-text-muted/15 border-text-muted/30 text-text-muted">
                  Inactive
                </span>
              )}
            </div>
            <p className="font-mono text-base text-text-primary break-all leading-relaxed">
              {indicator.value}
            </p>
          </div>

          {/* Confidence gauge */}
          <div className="text-center flex-shrink-0">
            <div className="relative w-16 h-16">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
                <circle cx="18" cy="18" r="14" fill="none" stroke="#1e2d42" strokeWidth="3" />
                <circle
                  cx="18" cy="18" r="14"
                  fill="none"
                  stroke={indicator.confidence >= 70 ? "#f04060" : indicator.confidence >= 50 ? "#f0a830" : "#50a0f0"}
                  strokeWidth="3"
                  strokeDasharray={`${indicator.confidence * 0.88} 88`}
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-sm font-bold font-mono text-text-primary">
                  {indicator.confidence}
                </span>
              </div>
            </div>
            <p className="text-2xs text-text-muted mt-1">Confidence</p>
          </div>
        </div>

        {/* Meta row */}
        <div className="flex flex-wrap gap-x-6 gap-y-2 mt-4 pt-4 border-t border-border">
          <div className="flex items-center gap-2 text-xs text-text-muted">
            <Clock className="w-3.5 h-3.5" />
            <span>First seen: </span>
            <span className="text-text-secondary">
              {firstSeen ? format(firstSeen, "MMM d, yyyy HH:mm") : "—"}
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs text-text-muted">
            <Clock className="w-3.5 h-3.5" />
            <span>Last seen: </span>
            <span className="text-text-secondary">
              {lastSeen ? formatDistanceToNow(lastSeen, { addSuffix: true }) : "—"}
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs text-text-muted">
            <Database className="w-3.5 h-3.5" />
            <span>{(indicator.sources ?? []).length} source(s)</span>
          </div>
        </div>

        {/* Active toggle */}
        <div className="mt-4 pt-4 border-t border-border flex items-center gap-3">
          <button
            onClick={handleToggle}
            disabled={toggling}
            className={clsx(
              "btn text-xs flex items-center gap-1.5 border",
              indicator.active
                ? "btn-ghost border-status-warning/40 text-status-warning hover:bg-status-warning/10"
                : "btn-ghost border-status-success/40 text-status-success hover:bg-status-success/10"
            )}
          >
            <Power className="w-3.5 h-3.5" />
            {toggling ? "Updating..." : indicator.active ? "Disable indicator" : "Enable indicator"}
          </button>
          <span className="text-2xs text-text-muted">
            {indicator.active
              ? "Active — being matched against incoming logs"
              : "Inactive — not matched against incoming logs"}
          </span>
        </div>
      </div>

      {/* Content grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Enrichment */}
        <Section title="Enrichment Data" icon={Globe}>
          <EnrichmentData enrichment={indicator.enrichment ?? {}} />
        </Section>

        {/* Sources */}
        <Section title="Intelligence Sources" icon={Database}>
          {(indicator.sources ?? []).length === 0 ? (
            <p className="text-sm text-text-muted italic">No source data</p>
          ) : (
            <ul className="space-y-3">
              {indicator.sources.map((source, i) => (
                <li key={i} className="flex items-start gap-3 p-3 bg-bg-elevated rounded-md">
                  <div className="w-8 h-8 rounded-md bg-accent/15 border border-accent/25
                                  flex items-center justify-center flex-shrink-0 text-xs font-bold text-accent">
                    {source.source_name.slice(0, 2).toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-text-primary">{source.source_name}</p>
                    <p className="text-2xs text-text-muted capitalize">{source.source_category?.replace("_", " ")}</p>
                    <div className="flex gap-3 mt-1 text-2xs text-text-muted">
                      <span>Confidence: {source.confidence}%</span>
                      {source.last_seen && (
                        <span>
                          Last seen: {formatDistanceToNow(parseISO(source.last_seen), { addSuffix: true })}
                        </span>
                      )}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Section>

        {/* Tags */}
        <Section title="Tags" icon={Tag}>
          {(indicator.tags ?? []).length === 0 ? (
            <p className="text-sm text-text-muted italic">No tags</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {indicator.tags.map((tag) => (
                <span key={tag} className="badge bg-bg-elevated border-border text-text-secondary">
                  {tag}
                </span>
              ))}
            </div>
          )}
        </Section>

        {/* Actions */}
        <Section title="Analyst Actions" icon={Shield}>
          <div className="space-y-3">
            {!indicator.false_positive ? (
              <button
                onClick={handleFP}
                disabled={fpBusy}
                className="btn-danger w-full justify-center text-xs"
              >
                <XCircle className="w-3.5 h-3.5" />
                {fpBusy ? "Marking..." : "Mark as False Positive"}
              </button>
            ) : (
              <div className="flex items-center gap-2 text-xs text-status-success p-3 bg-status-success/10 rounded-md border border-status-success/25">
                <CheckCircle className="w-4 h-4" />
                Marked as false positive
              </div>
            )}

            <Link
              href={`/indicators?q=${encodeURIComponent(indicator.value)}`}
              className="btn btn-ghost w-full justify-center text-xs"
            >
              <Link2 className="w-3.5 h-3.5" />
              Find Related Indicators
            </Link>
          </div>
        </Section>
      </div>

      {/* ── Triggered Alerts ─────────────────────────────────── */}
      <div className="card p-5">
        <div className="flex items-center gap-2 mb-4 pb-3 border-b border-border">
          <ShieldAlert className="w-4 h-4 text-text-muted" strokeWidth={1.75} />
          <h2 className="text-sm font-semibold text-text-primary">Triggered Alerts</h2>
          {alertsData && (
            <span className="ml-auto badge bg-bg-elevated border-border text-text-muted text-xs">
              {alertsData.total}
            </span>
          )}
        </div>

        {!alertsData ? (
          <p className="text-xs text-text-muted italic">Loading...</p>
        ) : alertsData.total === 0 ? (
          <p className="text-xs text-text-muted italic">No alerts triggered by this indicator.</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-bg-elevated">
                  <th className="text-left py-2.5 px-4 text-text-muted font-medium">Title</th>
                  <th className="text-left py-2.5 px-4 text-text-muted font-medium w-20">Severity</th>
                  <th className="text-left py-2.5 px-4 text-text-muted font-medium w-24">Status</th>
                  <th className="text-left py-2.5 px-4 text-text-muted font-medium w-32">When</th>
                </tr>
              </thead>
              <tbody>
                {alertsData.items.map((alert: Alert) => (
                  <tr key={alert.id} className="border-b border-border last:border-0 hover:bg-bg-elevated/50">
                    <td className="py-2.5 px-4">
                      <Link
                        href={`/alerts/${alert.id}`}
                        className="text-text-primary hover:text-accent transition-colors"
                      >
                        {alert.title}
                      </Link>
                      {alert.rule_name && (
                        <span className="ml-2 font-mono text-text-muted text-2xs">{alert.rule_name}</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className={clsx("font-medium capitalize", SEV_CLASSES[alert.severity] ?? "text-text-muted")}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 capitalize text-text-secondary">{alert.status.replace("_", " ")}</td>
                    <td className="py-2.5 px-4 text-text-muted">
                      {alert.created_at
                        ? formatDistanceToNow(parseISO(alert.created_at), { addSuffix: true })
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {alertsData.total > 20 && (
              <p className="py-3 text-center text-xs text-text-muted">
                Showing 20 of {alertsData.total} alerts
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
