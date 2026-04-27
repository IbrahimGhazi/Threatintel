"use client";

import { useMemo } from "react";
import { Clock, AlertTriangle, ChevronRight } from "lucide-react";
import clsx from "clsx";
import { format } from "date-fns";

/* ── stage → colour mapping ───────────────────────────────── */
const STAGE_COLORS: Record<string, { bg: string; border: string; text: string; dot: string; glow: string }> = {
  "reconnaissance":        { bg: "bg-blue-500/10",    border: "border-blue-500/30",    text: "text-blue-400",    dot: "bg-blue-400",    glow: "shadow-[0_0_6px_rgba(96,165,250,0.4)]" },
  "initial access":        { bg: "bg-amber-500/10",   border: "border-amber-500/30",   text: "text-amber-400",   dot: "bg-amber-400",   glow: "shadow-[0_0_6px_rgba(251,191,36,0.4)]" },
  "execution":             { bg: "bg-indigo-500/10",  border: "border-indigo-500/30",  text: "text-indigo-400",  dot: "bg-indigo-400",  glow: "shadow-[0_0_6px_rgba(129,140,248,0.4)]" },
  "persistence":           { bg: "bg-purple-500/10",  border: "border-purple-500/30",  text: "text-purple-400",  dot: "bg-purple-400",  glow: "shadow-[0_0_6px_rgba(192,132,252,0.4)]" },
  "privilege escalation":  { bg: "bg-pink-500/10",    border: "border-pink-500/30",    text: "text-pink-400",    dot: "bg-pink-400",    glow: "shadow-[0_0_6px_rgba(244,114,182,0.4)]" },
  "defense evasion":       { bg: "bg-rose-500/10",    border: "border-rose-500/30",    text: "text-rose-400",    dot: "bg-rose-400",    glow: "shadow-[0_0_6px_rgba(251,113,133,0.4)]" },
  "credential access":     { bg: "bg-emerald-500/10", border: "border-emerald-500/30", text: "text-emerald-400", dot: "bg-emerald-400", glow: "shadow-[0_0_6px_rgba(52,211,153,0.4)]" },
  "discovery":             { bg: "bg-cyan-500/10",    border: "border-cyan-500/30",    text: "text-cyan-400",    dot: "bg-cyan-400",    glow: "shadow-[0_0_6px_rgba(34,211,238,0.4)]" },
  "lateral movement":      { bg: "bg-teal-500/10",    border: "border-teal-500/30",    text: "text-teal-400",    dot: "bg-teal-400",    glow: "shadow-[0_0_6px_rgba(45,212,191,0.4)]" },
  "collection":            { bg: "bg-amber-500/10",   border: "border-amber-500/30",   text: "text-amber-400",   dot: "bg-amber-400",   glow: "shadow-[0_0_6px_rgba(251,191,36,0.4)]" },
  "command and control":   { bg: "bg-red-500/10",     border: "border-red-500/30",     text: "text-red-400",     dot: "bg-red-400",     glow: "shadow-[0_0_6px_rgba(248,113,113,0.4)]" },
  "exfiltration":          { bg: "bg-fuchsia-500/10", border: "border-fuchsia-500/30", text: "text-fuchsia-400", dot: "bg-fuchsia-400", glow: "shadow-[0_0_6px_rgba(232,121,249,0.4)]" },
  "impact":                { bg: "bg-gray-500/10",    border: "border-gray-500/30",    text: "text-gray-400",    dot: "bg-gray-400",    glow: "shadow-[0_0_6px_rgba(156,163,175,0.4)]" },
  "threat intelligence match": { bg: "bg-red-500/10", border: "border-red-500/30",     text: "text-red-400",     dot: "bg-red-400",     glow: "shadow-[0_0_6px_rgba(248,113,113,0.4)]" },
};

const DEFAULT_COLORS = { bg: "bg-accent/10", border: "border-accent/30", text: "text-accent", dot: "bg-accent", glow: "shadow-[0_0_6px_rgba(0,196,204,0.4)]" };

function getStageColors(stage: string) {
  const key = stage.toLowerCase().trim();
  return STAGE_COLORS[key] || DEFAULT_COLORS;
}

/* ── status badge ────────────────────────────────────────── */
function StatusDot({ status }: { status?: string }) {
  const s = (status || "").toLowerCase();
  if (s === "success" || s === "allow" || s === "allowed" || s === "accept" || s === "accepted")
    return <span className="w-1.5 h-1.5 rounded-full bg-status-success inline-block" />;
  if (s === "failed" || s === "fail" || s === "denied" || s === "deny" || s === "blocked" || s === "dropped" || s === "error")
    return <span className="w-1.5 h-1.5 rounded-full bg-severity-critical inline-block" />;
  if (s === "timeout" || s === "reset" || s === "refused")
    return <span className="w-1.5 h-1.5 rounded-full bg-severity-medium inline-block" />;
  return <span className="w-1.5 h-1.5 rounded-full bg-text-muted inline-block" />;
}

/* ── interfaces ──────────────────────────────────────────── */
interface IncidentEvent {
  timestamp: string;
  stage: string;
  summary: string;
  source_ip?: string;
  destination_ip?: string;
  destination_port?: number | string | null;
  status?: string;
  log_id: string;
}

interface IncidentTimelineProps {
  events: IncidentEvent[];
  timeWindow: { start: string; end: string; duration_seconds: number };
  height?: number;
  className?: string;
}

/* ── component ───────────────────────────────────────────── */
export function IncidentTimeline({
  events,
  timeWindow,
  height = 220,
  className,
}: IncidentTimelineProps) {
  const startMs = new Date(timeWindow.start).getTime();
  const endMs = new Date(timeWindow.end).getTime();
  const durationMs = Math.max(endMs - startMs, 1);

  /* stage legend (unique) */
  const stageList = useMemo(() => {
    const seen = new Set<string>();
    return events
      .map((e) => e.stage)
      .filter((s) => {
        if (!s || seen.has(s)) return false;
        seen.add(s);
        return true;
      });
  }, [events]);

  /* position each event on a 0-100 scale */
  const positioned = useMemo(
    () =>
      events.map((ev, i) => {
        const t = new Date(ev.timestamp).getTime();
        const pct = durationMs > 1 ? ((t - startMs) / durationMs) * 100 : (i / Math.max(events.length - 1, 1)) * 100;
        return { ...ev, pct: Math.max(0, Math.min(100, pct)) };
      }),
    [events, startMs, durationMs],
  );

  if (!events?.length) {
    return (
      <div className="flex items-center justify-center text-text-muted text-sm" style={{ height }}>
        No timeline data available
      </div>
    );
  }

  /* ── horizontal timeline bar ───────────────────────── */
  return (
    <div className={clsx("space-y-4", className)}>
      {/* stage legend */}
      <div className="flex flex-wrap gap-2">
        {stageList.map((stage) => {
          const c = getStageColors(stage);
          const count = events.filter((e) => e.stage === stage).length;
          return (
            <span
              key={stage}
              className={clsx("inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-2xs font-medium border", c.bg, c.border, c.text)}
            >
              <span className={clsx("w-1.5 h-1.5 rounded-full", c.dot)} />
              {stage}
              <span className="opacity-60">({count})</span>
            </span>
          );
        })}
      </div>

      {/* timeline track */}
      <div className="relative" style={{ height: height - 50 }}>
        {/* background grid lines */}
        <div className="absolute inset-0 flex">
          {[0, 25, 50, 75, 100].map((pct) => (
            <div
              key={pct}
              className="absolute top-0 bottom-0 w-px bg-border/50"
              style={{ left: `${pct}%` }}
            />
          ))}
        </div>

        {/* time axis labels */}
        <div className="absolute -bottom-5 left-0 right-0 flex justify-between text-2xs text-text-muted font-mono">
          <span>{format(new Date(timeWindow.start), "HH:mm:ss")}</span>
          <span>{format(new Date(timeWindow.end), "HH:mm:ss")}</span>
        </div>

        {/* swimlanes per stage */}
        {stageList.map((stage, laneIdx) => {
          const c = getStageColors(stage);
          const laneEvents = positioned.filter((e) => e.stage === stage);
          const laneHeight = Math.max(28, (height - 70) / stageList.length);
          const yOffset = laneIdx * laneHeight;

          return (
            <div key={stage} className="absolute left-0 right-0" style={{ top: yOffset, height: laneHeight }}>
              {/* lane background stripe */}
              <div className={clsx("absolute inset-0 rounded", laneIdx % 2 === 0 ? "bg-bg-elevated/30" : "bg-transparent")} />
              {/* lane label */}
              <span className={clsx("absolute left-1 top-0.5 text-2xs font-medium opacity-50 capitalize truncate max-w-[100px]", c.text)}>
                {stage}
              </span>

              {/* event dots */}
              {laneEvents.map((ev, i) => (
                <div
                  key={`${ev.log_id}-${i}`}
                  className="absolute group"
                  style={{
                    left: `${ev.pct}%`,
                    top: "50%",
                    transform: "translate(-50%, -50%)",
                  }}
                >
                  {/* pulse ring */}
                  <span className={clsx("absolute inset-[-4px] rounded-full opacity-0 group-hover:opacity-100 transition-opacity", c.bg, c.border, "border")} />
                  {/* dot */}
                  <span className={clsx("relative block w-2.5 h-2.5 rounded-full ring-2 ring-bg-base cursor-pointer transition-transform group-hover:scale-150", c.dot, c.glow)} />

                  {/* tooltip on hover */}
                  <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-3 hidden group-hover:block z-50 animate-fade-in pointer-events-none">
                    <div className="bg-bg-overlay border border-border rounded-lg shadow-card p-3 min-w-[240px] max-w-[320px]">
                      <div className="flex items-center gap-2 mb-1.5">
                        <span className={clsx("w-2 h-2 rounded-full", c.dot)} />
                        <span className={clsx("text-2xs font-semibold uppercase tracking-wide", c.text)}>{ev.stage}</span>
                      </div>
                      <p className="text-xs font-medium text-text-primary mb-2 leading-snug">{ev.summary || "Correlated event"}</p>
                      <div className="space-y-1 text-2xs text-text-muted">
                        <div className="flex items-center gap-1.5">
                          <Clock className="w-3 h-3" />
                          {format(new Date(ev.timestamp), "HH:mm:ss.SSS")}
                        </div>
                        {ev.source_ip && ev.destination_ip && (
                          <div className="flex items-center gap-1 font-mono">
                            {ev.source_ip}
                            <ChevronRight className="w-3 h-3" />
                            {ev.destination_ip}
                            {ev.destination_port ? `:${ev.destination_port}` : ""}
                          </div>
                        )}
                        {ev.status && (
                          <div className="flex items-center gap-1.5">
                            <StatusDot status={ev.status} />
                            <span className="capitalize">{ev.status}</span>
                          </div>
                        )}
                      </div>
                    </div>
                    {/* tooltip arrow */}
                    <div className="absolute left-1/2 -translate-x-1/2 -bottom-1 w-2 h-2 rotate-45 bg-bg-overlay border-r border-b border-border" />
                  </div>
                </div>
              ))}
            </div>
          );
        })}
      </div>

      {/* footer stats */}
      <div className="flex flex-wrap items-center gap-4 pt-2 text-2xs text-text-muted">
        <div className="flex items-center gap-1.5">
          <Clock className="w-3 h-3" />
          <span className="font-mono">{timeWindow.duration_seconds}s</span>
          <span>total duration</span>
        </div>
        <div className="flex items-center gap-1.5">
          <AlertTriangle className="w-3 h-3" />
          <span className="font-mono">{events.length}</span>
          <span>events correlated</span>
        </div>
        {stageList.length > 1 && (
          <div className="flex items-center gap-1.5">
            <span className="font-mono">{stageList.length}</span>
            <span>attack stages</span>
          </div>
        )}
      </div>
    </div>
  );
}
