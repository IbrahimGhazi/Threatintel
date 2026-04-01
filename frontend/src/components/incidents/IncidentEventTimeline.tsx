import { Clock3, ArrowRight, FileText, Shield, Activity } from "lucide-react";
import { format } from "date-fns";
import clsx from "clsx";
import type { IncidentEvent } from "@/lib/api";

/* ── stage → colour mapping (shared with IncidentTimeline) ── */
const STAGE_COLORS: Record<string, { bg: string; border: string; text: string; dot: string; glow: string }> = {
  "reconnaissance":        { bg: "bg-blue-500/10",    border: "border-blue-500/30",    text: "text-blue-400",    dot: "bg-blue-400",    glow: "shadow-[0_0_8px_rgba(96,165,250,0.5)]" },
  "initial access":        { bg: "bg-amber-500/10",   border: "border-amber-500/30",   text: "text-amber-400",   dot: "bg-amber-400",   glow: "shadow-[0_0_8px_rgba(251,191,36,0.5)]" },
  "execution":             { bg: "bg-indigo-500/10",  border: "border-indigo-500/30",  text: "text-indigo-400",  dot: "bg-indigo-400",  glow: "shadow-[0_0_8px_rgba(129,140,248,0.5)]" },
  "persistence":           { bg: "bg-purple-500/10",  border: "border-purple-500/30",  text: "text-purple-400",  dot: "bg-purple-400",  glow: "shadow-[0_0_8px_rgba(192,132,252,0.5)]" },
  "privilege escalation":  { bg: "bg-pink-500/10",    border: "border-pink-500/30",    text: "text-pink-400",    dot: "bg-pink-400",    glow: "shadow-[0_0_8px_rgba(244,114,182,0.5)]" },
  "defense evasion":       { bg: "bg-rose-500/10",    border: "border-rose-500/30",    text: "text-rose-400",    dot: "bg-rose-400",    glow: "shadow-[0_0_8px_rgba(251,113,133,0.5)]" },
  "credential access":     { bg: "bg-emerald-500/10", border: "border-emerald-500/30", text: "text-emerald-400", dot: "bg-emerald-400", glow: "shadow-[0_0_8px_rgba(52,211,153,0.5)]" },
  "discovery":             { bg: "bg-cyan-500/10",    border: "border-cyan-500/30",    text: "text-cyan-400",    dot: "bg-cyan-400",    glow: "shadow-[0_0_8px_rgba(34,211,238,0.5)]" },
  "lateral movement":      { bg: "bg-teal-500/10",    border: "border-teal-500/30",    text: "text-teal-400",    dot: "bg-teal-400",    glow: "shadow-[0_0_8px_rgba(45,212,191,0.5)]" },
  "collection":            { bg: "bg-amber-500/10",   border: "border-amber-500/30",   text: "text-amber-400",   dot: "bg-amber-400",   glow: "shadow-[0_0_8px_rgba(251,191,36,0.5)]" },
  "command and control":   { bg: "bg-red-500/10",     border: "border-red-500/30",     text: "text-red-400",     dot: "bg-red-400",     glow: "shadow-[0_0_8px_rgba(248,113,113,0.5)]" },
  "exfiltration":          { bg: "bg-fuchsia-500/10", border: "border-fuchsia-500/30", text: "text-fuchsia-400", dot: "bg-fuchsia-400", glow: "shadow-[0_0_8px_rgba(232,121,249,0.5)]" },
  "impact":                { bg: "bg-gray-500/10",    border: "border-gray-500/30",    text: "text-gray-400",    dot: "bg-gray-400",    glow: "shadow-[0_0_8px_rgba(156,163,175,0.5)]" },
  "threat intelligence match": { bg: "bg-red-500/10", border: "border-red-500/30",     text: "text-red-400",     dot: "bg-red-400",     glow: "shadow-[0_0_8px_rgba(248,113,113,0.5)]" },
};
const DEFAULT_COLORS = { bg: "bg-accent/10", border: "border-accent/30", text: "text-accent", dot: "bg-accent", glow: "shadow-[0_0_8px_rgba(0,196,204,0.5)]" };

function getStageColors(stage: string) {
  return STAGE_COLORS[stage.toLowerCase().trim()] || DEFAULT_COLORS;
}

/* ── outcome status styling ─────────────────────────────────── */
function getOutcomeStyle(outcome: string) {
  const o = outcome.toLowerCase();
  if (["success", "allow", "allowed", "accept", "accepted"].includes(o))
    return { bg: "bg-emerald-500/10", border: "border-emerald-500/30", text: "text-emerald-400", dot: "bg-emerald-400" };
  if (["failed", "fail", "denied", "deny", "blocked", "dropped", "error"].includes(o))
    return { bg: "bg-red-500/10", border: "border-red-500/30", text: "text-red-400", dot: "bg-red-400" };
  if (["timeout", "reset", "refused"].includes(o))
    return { bg: "bg-amber-500/10", border: "border-amber-500/30", text: "text-amber-400", dot: "bg-amber-400" };
  return { bg: "bg-bg-base", border: "border-border", text: "text-text-muted", dot: "bg-text-muted" };
}

interface IncidentEventTimelineProps {
  events?: IncidentEvent[];
}

function formatTimestamp(value?: string) {
  if (!value) return "Unknown time";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return format(date, "MMM d, yyyy HH:mm:ss");
}

function formatTime(value?: string) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return format(date, "HH:mm:ss.SSS");
}

function getOutcome(event: IncidentEvent) {
  if (typeof event.outcome === "string" && event.outcome.length > 0) return event.outcome;
  if (typeof event.status === "string" && event.status.length > 0) return event.status;
  return "unknown";
}

export function IncidentEventTimeline({ events }: IncidentEventTimelineProps) {
  if (!Array.isArray(events) || events.length === 0) {
    return (
      <div className="card p-5">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-text-muted" />
          <h2 className="text-sm font-semibold text-text-primary">Event chain</h2>
        </div>
        <p className="text-xs text-text-muted mt-1">
          No correlated event chain was provided for this alert.
        </p>
      </div>
    );
  }

  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-accent/10 border border-accent/20 flex items-center justify-center">
            <Activity className="w-3.5 h-3.5 text-accent" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-text-primary">Event chain</h2>
            <p className="text-2xs text-text-muted">
              Ordered timeline of related activity across the incident
            </p>
          </div>
        </div>
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-accent/10 border border-accent/20 text-accent text-2xs font-mono font-medium">
          {events.length} events
        </span>
      </div>

      <div className="relative">
        {events.map((event, index) => {
          const stageColor = event.stage ? getStageColors(event.stage) : DEFAULT_COLORS;
          const outcome = getOutcome(event);
          const outcomeStyle = getOutcomeStyle(outcome);
          const isLast = index === events.length - 1;

          return (
            <div key={`${event.log_id ?? event.timestamp ?? "event"}-${index}`} className="flex gap-4 group">
              {/* timeline spine */}
              <div className="flex flex-col items-center relative">
                {/* connector line above */}
                {index > 0 && (
                  <div className={clsx("w-px h-4", stageColor.dot, "opacity-30")} />
                )}
                {/* stage-colored dot with glow */}
                <div className={clsx(
                  "relative w-4 h-4 rounded-full border-2 border-bg-base ring-2 flex-shrink-0 transition-transform group-hover:scale-125",
                  stageColor.dot,
                  stageColor.glow,
                )}>
                  {/* inner pulse */}
                  <span className={clsx("absolute inset-0 rounded-full animate-ping opacity-20", stageColor.dot)} style={{ animationDuration: "3s" }} />
                </div>
                {/* connector line below */}
                {!isLast && (
                  <div className={clsx("w-px flex-1 min-h-[16px]", stageColor.dot, "opacity-20")} />
                )}
              </div>

              {/* event card */}
              <div className={clsx(
                "flex-1 rounded-xl border p-4 mb-3 transition-all group-hover:border-opacity-60",
                stageColor.bg,
                stageColor.border,
                "group-hover:shadow-lg group-hover:shadow-black/10",
              )}>
                {/* header row */}
                <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
                  <div className="flex flex-wrap items-center gap-2">
                    {event.stage && (
                      <span className={clsx(
                        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-2xs font-semibold uppercase tracking-wide border",
                        stageColor.bg, stageColor.border, stageColor.text,
                      )}>
                        <span className={clsx("w-1.5 h-1.5 rounded-full", stageColor.dot)} />
                        {event.stage}
                      </span>
                    )}
                    {event.action && (
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-2xs font-medium border bg-bg-base border-border text-text-secondary capitalize">
                        {event.action}
                      </span>
                    )}
                    <span className={clsx(
                      "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-2xs font-medium border capitalize",
                      outcomeStyle.bg, outcomeStyle.border, outcomeStyle.text,
                    )}>
                      <span className={clsx("w-1.5 h-1.5 rounded-full", outcomeStyle.dot)} />
                      {outcome}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-2xs text-text-muted">
                    <span className="font-mono text-text-secondary">{formatTime(event.timestamp)}</span>
                    <div className="flex items-center gap-1">
                      <Clock3 className="w-3 h-3" />
                      {formatTimestamp(event.timestamp)}
                    </div>
                  </div>
                </div>

                {/* summary */}
                <p className="text-sm font-medium text-text-primary mb-3 leading-snug">
                  {event.summary || "Correlated event"}
                </p>

                {/* detail cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2.5">
                  <div className="rounded-lg bg-bg-base/80 border border-border/60 p-3">
                    <p className="text-2xs uppercase tracking-wider text-text-muted mb-1.5 font-semibold">Network path</p>
                    <div className="flex items-center gap-2 text-text-secondary font-mono text-xs break-all">
                      <span className="text-text-primary font-semibold">{event.source_ip || "?"}</span>
                      <ArrowRight className={clsx("w-3.5 h-3.5 flex-shrink-0", stageColor.text)} />
                      <span className="text-text-primary font-semibold">{event.destination_ip || "?"}</span>
                    </div>
                    {event.destination_port !== undefined && event.destination_port !== null && (
                      <p className={clsx("text-2xs mt-1.5 font-mono", stageColor.text)}>
                        :{event.destination_port}
                      </p>
                    )}
                  </div>

                  <div className="rounded-lg bg-bg-base/80 border border-border/60 p-3">
                    <p className="text-2xs uppercase tracking-wider text-text-muted mb-1.5 font-semibold">Execution</p>
                    <p className="text-xs text-text-primary font-medium">{event.program || "Unknown process"}</p>
                    <p className="text-2xs text-text-muted mt-1.5 font-mono">
                      {event.hostname || "Unknown host"}
                    </p>
                  </div>

                  <div className="rounded-lg bg-bg-base/80 border border-border/60 p-3">
                    <p className="text-2xs uppercase tracking-wider text-text-muted mb-1.5 font-semibold">Reference</p>
                    <div className="flex items-center gap-2 text-xs text-text-secondary font-mono break-all">
                      <FileText className={clsx("w-3.5 h-3.5 flex-shrink-0", stageColor.text)} />
                      <span className="truncate">{event.log_id || "No log id"}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
