"use client";

import { useState } from "react";
import useSWR from "swr";
import {
  Sliders,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  TrendingUp,
  Shield,
  RotateCcw,
  Activity,
  ChevronRight,
  Info,
  Zap,
  Database,
  RefreshCw,
  Settings,
  Save,
} from "lucide-react";
import {
  getTuningStats,
  getTuningSuggestions,
  acceptSuggestion,
  rejectSuggestion,
  getAdaptiveChanges,
  revertChange,
  getBehavioralBaselines,
  getTuningConfig,
  updateTuningConfig,
  type TuningSuggestion,
  type AdaptiveRuleChange,
  type BehavioralBaseline,
  type TuningStats,
  type TuningConfig,
} from "@/lib/api";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { Badge } from "@/components/ui/badge";
import { formatDistanceToNow, parseISO, differenceInHours } from "date-fns";
import clsx from "clsx";

// ── Types / constants ─────────────────────────────────────────────────────────

type Tab = "suggestions" | "changes" | "baselines";

const CATEGORY_LABELS: Record<string, string> = {
  dns:              "DNS",
  port_scan:        "Port Scan",
  auth:             "Auth",
  connection:       "Connection",
  lateral_movement: "Lateral Movement",
  c2:               "C2 / Beaconing",
  unknown:          "General",
};

const SUGGESTION_TYPE_LABELS: Record<string, string> = {
  increase_threshold: "Increase Threshold",
  add_allowlist:      "Add to Allowlist",
  suppress_rule:      "Suppress Rule",
  adjust_window:      "Adjust Window",
};

const CATEGORY_COLORS: Record<string, string> = {
  dns:              "text-cyan-400 bg-cyan-500/10 border-cyan-500/25",
  port_scan:        "text-amber-400 bg-amber-500/10 border-amber-500/25",
  auth:             "text-purple-400 bg-purple-500/10 border-purple-500/25",
  connection:       "text-blue-400 bg-blue-500/10 border-blue-500/25",
  lateral_movement: "text-teal-400 bg-teal-500/10 border-teal-500/25",
  c2:               "text-red-400 bg-red-500/10 border-red-500/25",
};

// ── Confidence bar ────────────────────────────────────────────────────────────

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color =
    pct >= 85 ? "bg-severity-high"
    : pct >= 60 ? "bg-severity-medium"
    : "bg-severity-low";
  const label =
    pct >= 85 ? "High"
    : pct >= 60 ? "Medium"
    : "Low";
  const labelColor =
    pct >= 85 ? "text-severity-high"
    : pct >= 60 ? "text-severity-medium"
    : "text-severity-low";

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-2xs">
        <span className="text-text-muted">Confidence</span>
        <span className={clsx("font-semibold font-mono", labelColor)}>
          {pct}% <span className="font-normal opacity-70">({label})</span>
        </span>
      </div>
      <div className="h-1.5 bg-bg-overlay rounded-full overflow-hidden">
        <div
          className={clsx("h-full rounded-full transition-all duration-300", color)}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

// ── Auto-apply countdown ──────────────────────────────────────────────────────

function AutoApplyBadge({ autoApplyAt }: { autoApplyAt?: string }) {
  if (!autoApplyAt) return null;
  const date = parseISO(autoApplyAt);
  const hoursLeft = differenceInHours(date, new Date());

  if (hoursLeft <= 0) {
    return (
      <span className="inline-flex items-center gap-1 text-2xs px-2 py-0.5 rounded border bg-severity-high/10 text-severity-high border-severity-high/25">
        <Zap className="w-2.5 h-2.5" />
        Auto-apply imminent
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1 text-2xs px-2 py-0.5 rounded border bg-severity-medium/10 text-severity-medium border-severity-medium/25">
      <Clock className="w-2.5 h-2.5" />
      Auto-apply in {hoursLeft}h
    </span>
  );
}

// ── Suggestion card ───────────────────────────────────────────────────────────

function SuggestionCard({
  s,
  onAccept,
  onReject,
  acting,
}: {
  s: TuningSuggestion;
  onAccept: (id: string) => void;
  onReject: (id: string) => void;
  acting: string | null;
}) {
  const catColor = CATEGORY_COLORS[s.category] ?? "text-text-muted bg-bg-elevated border-border";
  const statusBorder =
    s.status === "auto_applied" ? "border-l-status-running"
    : s.status === "accepted"   ? "border-l-status-success"
    : s.status === "rejected"   ? "border-l-border-strong"
    : "border-l-severity-medium";

  const suggested = s.suggested_value as Record<string, unknown> | undefined;
  const current   = s.current_value   as Record<string, unknown> | undefined;

  return (
    <div className={clsx("card p-5 border-l-2", statusBorder)}>
      {/* Header */}
      <div className="flex items-start justify-between gap-3 flex-wrap mb-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={clsx("badge border text-2xs", catColor)}>
            {CATEGORY_LABELS[s.category] ?? s.category}
          </span>
          <Badge variant="secondary" className="text-2xs">
            {SUGGESTION_TYPE_LABELS[s.suggestion_type] ?? s.suggestion_type}
          </Badge>
          {s.status !== "pending" && (
            <span
              className={clsx(
                "badge border text-2xs",
                s.status === "auto_applied" && "bg-status-running/10 text-status-running border-status-running/25",
                s.status === "accepted"     && "bg-status-success/10 text-status-success border-status-success/25",
                s.status === "rejected"     && "bg-bg-elevated text-text-muted border-border",
              )}
            >
              {s.status === "auto_applied" ? "Auto-Applied" : s.status.charAt(0).toUpperCase() + s.status.slice(1)}
            </span>
          )}
          {s.status === "pending" && <AutoApplyBadge autoApplyAt={s.auto_apply_at} />}
        </div>
        <span className="text-2xs text-text-muted flex items-center gap-1">
          <Clock className="w-3 h-3" />
          {formatDistanceToNow(parseISO(s.created_at), { addSuffix: true })}
        </span>
      </div>

      {/* Title */}
      <h3 className="text-sm font-semibold text-text-primary mb-1">
        {SUGGESTION_TYPE_LABELS[s.suggestion_type] ?? s.suggestion_type}:{" "}
        <span className="text-accent font-mono">{s.rule_name.replace(/_/g, " ")}</span>
      </h3>

      {/* Entity */}
      {s.entity_value && (
        <p className="text-2xs text-text-muted mb-2">
          {s.entity_type && <span className="capitalize">{s.entity_type}: </span>}
          <span className="font-mono text-text-secondary">{s.entity_value}</span>
        </p>
      )}

      {/* Rationale */}
      <p className="text-xs text-text-secondary mb-4 leading-relaxed">{s.rationale}</p>

      {/* Threshold comparison */}
      {(current?.threshold !== undefined || suggested?.threshold !== undefined) && (
        <div className="flex items-center gap-4 mb-4 p-3 bg-bg-elevated/60 rounded-md border border-border/50">
          <div className="text-center">
            <p className="text-2xs text-text-muted mb-0.5">Current</p>
            <p className="font-mono text-sm font-semibold text-text-primary">
              {current?.threshold !== undefined ? String(current.threshold) : "—"}
            </p>
          </div>
          <ChevronRight className="w-4 h-4 text-text-muted flex-shrink-0" />
          <div className="text-center">
            <p className="text-2xs text-text-muted mb-0.5">Suggested</p>
            <p className="font-mono text-sm font-semibold text-status-success">
              {suggested?.threshold !== undefined ? String(suggested.threshold) : "—"}
            </p>
            {suggested?.basis !== undefined && (
              <p className="text-2xs text-text-muted mt-0.5">
                ({String(suggested.basis).replace(/_/g, " ")})
              </p>
            )}
          </div>
          <div className="ml-auto text-center">
            <p className="text-2xs text-text-muted mb-0.5">Triggers</p>
            <p className="font-mono text-sm font-semibold text-severity-medium">
              {s.trigger_count}×
            </p>
          </div>
        </div>
      )}

      {/* Confidence bar */}
      <div className="mb-4">
        <ConfidenceBar value={s.confidence} />
      </div>

      {/* Actions */}
      {s.status === "pending" && (
        <div className="flex items-center gap-2 justify-end">
          <button
            onClick={() => onReject(s.id)}
            disabled={acting === s.id}
            className="btn text-xs h-auto py-1.5 px-3 bg-bg-elevated border border-border text-text-secondary hover:text-severity-high hover:border-severity-high/40"
          >
            {acting === s.id ? <LoadingSpinner size="sm" /> : (
              <><XCircle className="w-3.5 h-3.5" /> Reject</>
            )}
          </button>
          <button
            onClick={() => onAccept(s.id)}
            disabled={acting === s.id}
            className="btn text-xs h-auto py-1.5 px-3 bg-status-success/10 text-status-success border border-status-success/30 hover:bg-status-success/20"
          >
            {acting === s.id ? <LoadingSpinner size="sm" /> : (
              <><CheckCircle className="w-3.5 h-3.5" /> Accept</>
            )}
          </button>
        </div>
      )}
    </div>
  );
}

// ── Change row ────────────────────────────────────────────────────────────────

function ChangeRow({
  c,
  onRevert,
  acting,
}: {
  c: AdaptiveRuleChange;
  onRevert: (id: string) => void;
  acting: string | null;
}) {
  return (
    <div className="card p-4 flex items-start gap-4">
      <div className="w-8 h-8 rounded-lg bg-status-running/10 border border-status-running/25 flex items-center justify-center flex-shrink-0">
        {c.reverted_at
          ? <RotateCcw className="w-3.5 h-3.5 text-text-muted" />
          : <Zap className="w-3.5 h-3.5 text-status-running" />
        }
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap mb-1">
          <span className="text-sm font-semibold text-text-primary font-mono">
            {c.rule_name.replace(/_/g, " ")}
          </span>
          <Badge variant="secondary" className="text-2xs">
            {c.change_type.replace(/_/g, " ")}
          </Badge>
          {c.reverted_at && (
            <span className="badge border bg-bg-elevated text-text-muted border-border text-2xs">
              Reverted
            </span>
          )}
        </div>
        {c.entity_value && (
          <p className="text-2xs text-text-muted font-mono mb-1">{c.entity_value}</p>
        )}
        {c.reason && (
          <p className="text-xs text-text-secondary">{c.reason}</p>
        )}
        <div className="flex items-center gap-3 mt-1.5 text-2xs text-text-muted">
          <span>By: {c.applied_by}</span>
          <span>{formatDistanceToNow(parseISO(c.created_at), { addSuffix: true })}</span>
        </div>
      </div>

      {!c.reverted_at && (
        <button
          onClick={() => onRevert(c.id)}
          disabled={acting === c.id}
          className="btn-ghost text-2xs px-2 py-1 h-auto border border-border hover:border-severity-high/40 hover:text-severity-high flex-shrink-0"
        >
          {acting === c.id ? <LoadingSpinner size="sm" /> : (
            <><RotateCcw className="w-3 h-3" /> Revert</>
          )}
        </button>
      )}
    </div>
  );
}

// ── Baseline row ──────────────────────────────────────────────────────────────

function BaselineRow({ b }: { b: BehavioralBaseline }) {
  const catColor = CATEGORY_COLORS[b.category] ?? "text-text-muted bg-bg-elevated border-border";
  const maturity =
    b.sample_count >= 200 ? { label: "Stable",   color: "text-status-success" }
    : b.sample_count >= 50  ? { label: "Building", color: "text-severity-medium" }
    : { label: "Learning", color: "text-text-muted" };

  return (
    <div className="card p-4">
      <div className="flex items-center justify-between gap-3 flex-wrap mb-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className={clsx("badge border text-2xs flex-shrink-0", catColor)}>
            {CATEGORY_LABELS[b.category] ?? b.category}
          </span>
          <span className="text-xs font-mono text-text-primary truncate">{b.metric}</span>
        </div>
        <span className={clsx("text-2xs font-medium", maturity.color)}>
          {maturity.label} ({b.sample_count} samples)
        </span>
      </div>

      <p className="text-2xs text-text-muted font-mono mb-3">
        {b.entity_type}: {b.entity_value}
      </p>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Mean",   value: b.mean?.toFixed(2) },
          { label: "Std Dev", value: b.std_dev?.toFixed(2) },
          { label: "Min",    value: b.min_observed?.toFixed(2) ?? "—" },
          { label: "p95",    value: b.p95?.toFixed(2) ?? "—" },
        ].map(({ label, value }) => (
          <div key={label} className="bg-bg-elevated/50 rounded-md p-2 text-center">
            <p className="text-2xs text-text-muted mb-0.5">{label}</p>
            <p className="text-sm font-mono font-semibold text-text-primary">{value}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Stats header ──────────────────────────────────────────────────────────────

function StatsHeader({ stats }: { stats?: TuningStats }) {
  const cards = [
    {
      label: "Pending",
      value: stats?.pending ?? 0,
      icon: Clock,
      color: "text-severity-medium",
      bg: "bg-severity-medium/10 border-severity-medium/20",
    },
    {
      label: "Auto-Applied",
      value: stats?.auto_applied ?? 0,
      icon: Zap,
      color: "text-status-running",
      bg: "bg-status-running/10 border-status-running/20",
    },
    {
      label: "Baselines",
      value: stats?.baselines_total ?? 0,
      icon: Database,
      color: "text-accent",
      bg: "bg-accent/10 border-accent/20",
    },
    {
      label: "Changes",
      value: stats?.changes_total ?? 0,
      icon: Activity,
      color: "text-status-success",
      bg: "bg-status-success/10 border-status-success/20",
    },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {cards.map(({ label, value, icon: Icon, color, bg }) => (
        <div key={label} className="card p-4 flex items-center gap-3">
          <div className={clsx("w-9 h-9 rounded-lg border flex items-center justify-center flex-shrink-0", bg)}>
            <Icon className={clsx("w-4 h-4", color)} />
          </div>
          <div>
            <p className="text-xl font-bold font-mono text-text-primary leading-none">{value}</p>
            <p className="text-2xs text-text-muted mt-0.5">{label}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Review window settings ────────────────────────────────────────────────────

function ReviewWindowSettings({ config, onSaved }: { config?: TuningConfig; onSaved: () => void }) {
  const current = config ? parseInt(config.auto_apply_delay_hours.value, 10) : 24;
  const [hours, setHours] = useState<number>(current);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved]   = useState(false);

  // Keep local state in sync when config loads
  if (config && hours === 24 && current !== 24) setHours(current);

  const dirty = hours !== current;

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateTuningConfig({ auto_apply_delay_hours: hours });
      onSaved();
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      // ignore — SWR will re-fetch
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card p-4 flex flex-col sm:flex-row sm:items-center gap-4">
      <div className="flex items-center gap-2 flex-shrink-0">
        <Settings className="w-4 h-4 text-accent" />
        <span className="text-sm font-medium text-text-primary">Review window</span>
      </div>

      <div className="flex items-center gap-3 flex-1">
        <input
          type="range"
          min={1}
          max={168}
          step={1}
          value={hours}
          onChange={(e) => setHours(Number(e.target.value))}
          className="flex-1 accent-accent h-1.5 cursor-pointer"
        />
        <div className="flex items-center gap-1 w-24 flex-shrink-0">
          <input
            type="number"
            min={1}
            max={168}
            value={hours}
            onChange={(e) => setHours(Math.min(168, Math.max(1, Number(e.target.value))))}
            className="w-16 text-center text-sm font-mono bg-bg-elevated border border-border rounded px-2 py-1 text-text-primary focus:outline-none focus:border-accent"
          />
          <span className="text-xs text-text-muted">h</span>
        </div>
      </div>

      <button
        onClick={handleSave}
        disabled={!dirty || saving}
        className={clsx(
          "btn text-xs h-auto py-1.5 px-3 flex items-center gap-1.5 flex-shrink-0 transition-all",
          saved
            ? "bg-status-success/10 text-status-success border border-status-success/30"
            : dirty
            ? "bg-accent/10 text-accent border border-accent/30 hover:bg-accent/20"
            : "btn-ghost opacity-50 cursor-not-allowed",
        )}
      >
        {saving ? <LoadingSpinner size="sm" /> : saved ? <CheckCircle className="w-3.5 h-3.5" /> : <Save className="w-3.5 h-3.5" />}
        {saved ? "Saved" : "Apply"}
      </button>

      <p className="text-2xs text-text-muted sm:hidden">
        {hours === 1 ? "1 hour" : `${hours} hours`} before auto-applying high-confidence suggestions
      </p>
    </div>
  );
}

// ── Safeguards info box ───────────────────────────────────────────────────────

function SafeguardsNote({ delayHours }: { delayHours: number }) {
  return (
    <div className="card p-4 flex gap-3 border-l-2 border-l-accent/50">
      <Shield className="w-4 h-4 text-accent flex-shrink-0 mt-0.5" />
      <div className="text-xs text-text-secondary space-y-1">
        <p className="font-semibold text-text-primary">Adaptive tuning safeguards</p>
        <ul className="space-y-0.5 list-disc list-inside text-text-muted">
          <li>Critical-severity alerts are never automatically suppressed</li>
          <li>Signature-based and threat-intelligence rules are protected</li>
          <li>Every change is logged and reversible via the Changes tab</li>
          <li>Auto-apply requires ≥ 85 % confidence and a {delayHours} h review window</li>
        </ul>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function TuningPage() {
  const [tab, setTab] = useState<Tab>("suggestions");
  const [statusFilter, setStatusFilter] = useState("pending");
  const [actingSuggestion, setActingSuggestion] = useState<string | null>(null);
  const [actingChange, setActingChange] = useState<string | null>(null);

  // Data fetching
  const { data: config, mutate: mutateConfig } = useSWR(
    "tuning-config",
    () => getTuningConfig(),
    { refreshInterval: 60000 },
  );

  const { data: stats, mutate: mutateStats } = useSWR(
    "tuning-stats",
    () => getTuningStats(),
    { refreshInterval: 30000 },
  );

  const { data: suggestionsData, isLoading: loadingSuggestions, mutate: mutateSuggestions } = useSWR(
    ["tuning-suggestions", statusFilter],
    () => getTuningSuggestions({ status: statusFilter || undefined, limit: 50 }),
    { refreshInterval: 30000 },
  );

  const { data: changesData, isLoading: loadingChanges, mutate: mutateChanges } = useSWR(
    tab === "changes" ? "tuning-changes" : null,
    () => getAdaptiveChanges({ limit: 50 }),
    { refreshInterval: 30000 },
  );

  const { data: baselinesData, isLoading: loadingBaselines } = useSWR(
    tab === "baselines" ? "tuning-baselines" : null,
    () => getBehavioralBaselines({ limit: 100 }),
    { refreshInterval: 60000 },
  );

  // Handlers
  const handleAccept = async (id: string) => {
    setActingSuggestion(id);
    try {
      await acceptSuggestion(id);
      mutateSuggestions();
      mutateStats();
    } finally {
      setActingSuggestion(null);
    }
  };

  const handleReject = async (id: string) => {
    setActingSuggestion(id);
    try {
      await rejectSuggestion(id);
      mutateSuggestions();
      mutateStats();
    } finally {
      setActingSuggestion(null);
    }
  };

  const handleRevert = async (id: string) => {
    setActingChange(id);
    try {
      await revertChange(id);
      mutateChanges();
      mutateStats();
    } finally {
      setActingChange(null);
    }
  };

  const pendingCount = stats?.pending ?? 0;

  return (
    <div className="space-y-5 max-w-5xl">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-semibold text-text-primary flex items-center gap-2">
          <Sliders className="w-5 h-5 text-accent" />
          Adaptive Rule Tuning
        </h1>
        <p className="text-sm text-text-muted mt-0.5">
          Behavioral baseline learning and automatic rule optimization
        </p>
      </div>

      {/* Stats */}
      <StatsHeader stats={stats} />

      {/* Review window control */}
      <ReviewWindowSettings config={config} onSaved={mutateConfig} />

      {/* Safeguards note */}
      <SafeguardsNote delayHours={config ? parseInt(config.auto_apply_delay_hours.value, 10) : 24} />

      {/* Tabs */}
      <div className="card p-1 flex gap-1">
        {(
          [
            { id: "suggestions", label: "Suggestions", count: pendingCount },
            { id: "changes",     label: "Applied Changes" },
            { id: "baselines",   label: "Baselines" },
          ] as { id: Tab; label: string; count?: number }[]
        ).map(({ id, label, count }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={clsx(
              "flex-1 flex items-center justify-center gap-1.5 px-4 py-2 rounded text-sm font-medium transition-colors",
              tab === id
                ? "bg-accent/10 text-accent border border-accent/20"
                : "text-text-secondary hover:text-text-primary hover:bg-bg-elevated",
            )}
          >
            {label}
            {count !== undefined && count > 0 && (
              <span className="w-5 h-5 rounded-full bg-severity-medium text-bg-base text-2xs font-bold flex items-center justify-center">
                {count > 9 ? "9+" : count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── Tab: Suggestions ── */}
      {tab === "suggestions" && (
        <div className="space-y-4">
          {/* Status filter */}
          <div className="flex gap-2 flex-wrap">
            {[
              { value: "pending",      label: "Pending" },
              { value: "auto_applied", label: "Auto-Applied" },
              { value: "accepted",     label: "Accepted" },
              { value: "rejected",     label: "Rejected" },
              { value: "",             label: "All" },
            ].map(({ value, label }) => (
              <button
                key={value}
                onClick={() => setStatusFilter(value)}
                className={clsx(
                  "btn text-xs h-auto py-1.5 px-3",
                  statusFilter === value ? "btn-primary" : "btn-ghost",
                )}
              >
                {label}
              </button>
            ))}
          </div>

          {loadingSuggestions ? (
            <div className="card flex items-center justify-center py-16">
              <LoadingSpinner size="lg" />
            </div>
          ) : !suggestionsData?.items.length ? (
            <div className="card flex flex-col items-center justify-center py-16 gap-3">
              <CheckCircle className="w-10 h-10 text-status-success/60" />
              <p className="text-sm text-text-muted">
                {statusFilter === "pending"
                  ? "No pending suggestions — detection rules are well-tuned."
                  : `No ${statusFilter} suggestions.`}
              </p>
              <p className="text-xs text-text-muted max-w-sm text-center">
                Suggestions appear here when behavioral rules fire repeatedly for the
                same host or user without confirmed malicious activity.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {suggestionsData.items.map((s) => (
                <SuggestionCard
                  key={s.id}
                  s={s}
                  onAccept={handleAccept}
                  onReject={handleReject}
                  acting={actingSuggestion}
                />
              ))}
              {suggestionsData.total > suggestionsData.items.length && (
                <p className="text-xs text-text-muted text-center">
                  Showing {suggestionsData.items.length} of {suggestionsData.total} suggestions
                </p>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Tab: Applied Changes ── */}
      {tab === "changes" && (
        <div className="space-y-3">
          {loadingChanges ? (
            <div className="card flex items-center justify-center py-16">
              <LoadingSpinner size="lg" />
            </div>
          ) : !changesData?.items.length ? (
            <div className="card flex flex-col items-center justify-center py-16 gap-3">
              <Activity className="w-10 h-10 text-text-muted/40" />
              <p className="text-sm text-text-muted">No applied changes yet.</p>
              <p className="text-xs text-text-muted max-w-sm text-center">
                This audit log records every rule adjustment made by analysts or
                automatically applied by the system.
              </p>
            </div>
          ) : (
            <>
              <div className="card p-3 flex items-center gap-2 text-xs text-text-secondary border-l-2 border-l-status-running/50">
                <Info className="w-3.5 h-3.5 text-accent flex-shrink-0" />
                All changes shown below can be reverted. Reverted changes reset the
                originating suggestion to pending so analysts can re-evaluate.
              </div>
              {changesData.items.map((c) => (
                <ChangeRow
                  key={c.id}
                  c={c}
                  onRevert={handleRevert}
                  acting={actingChange}
                />
              ))}
              {changesData.total > changesData.items.length && (
                <p className="text-xs text-text-muted text-center">
                  Showing {changesData.items.length} of {changesData.total} changes
                </p>
              )}
            </>
          )}
        </div>
      )}

      {/* ── Tab: Baselines ── */}
      {tab === "baselines" && (
        <div className="space-y-3">
          <div className="card p-3 flex items-center gap-2 text-xs text-text-secondary border-l-2 border-l-accent/50">
            <TrendingUp className="w-3.5 h-3.5 text-accent flex-shrink-0" />
            Baselines are built from live log data using Welford&apos;s online algorithm.
            Anomaly detection activates after 20 samples. Mean ± 3σ defines normal range.
          </div>

          {loadingBaselines ? (
            <div className="card flex items-center justify-center py-16">
              <LoadingSpinner size="lg" />
            </div>
          ) : !baselinesData?.items.length ? (
            <div className="card flex flex-col items-center justify-center py-16 gap-3">
              <Database className="w-10 h-10 text-text-muted/40" />
              <p className="text-sm text-text-muted">No baselines built yet.</p>
              <p className="text-xs text-text-muted max-w-sm text-center">
                Baselines build automatically as the system processes logs through
                the correlation engine. Check back after ingesting log data.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {baselinesData.items.map((b, i) => (
                <BaselineRow key={`${b.entity_type}-${b.entity_value}-${b.metric}-${i}`} b={b} />
              ))}
              {baselinesData.total > baselinesData.items.length && (
                <p className="text-xs text-text-muted text-center">
                  Showing {baselinesData.items.length} of {baselinesData.total} baselines
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
