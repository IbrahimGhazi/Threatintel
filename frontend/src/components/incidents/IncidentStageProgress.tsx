import clsx from "clsx";
import { CheckCircle2, Circle, ChevronRight } from "lucide-react";

/* ── stage → colour mapping ─────────────────────────────────── */
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

interface IncidentStageProgressProps {
  stages: string[];
  progression?: string[] | Record<string, unknown>[];
}

function normalizeProgression(progression?: string[] | Record<string, unknown>[]) {
  if (!Array.isArray(progression)) return [] as string[];

  return progression
    .map((item) => {
      if (typeof item === "string") return item;
      if (item && typeof item === "object") {
        const candidate = item.stage ?? item.name ?? item.label;
        return typeof candidate === "string" ? candidate : null;
      }
      return null;
    })
    .filter((item): item is string => Boolean(item))
    .map((item) => item.toLowerCase());
}

export function IncidentStageProgress({
  stages,
  progression,
}: IncidentStageProgressProps) {
  const normalizedStages = stages.filter(Boolean);
  const completedStages = normalizeProgression(progression);

  if (normalizedStages.length === 0) return null;

  const completedCount = normalizedStages.filter((s) => completedStages.includes(s.toLowerCase())).length;
  const progressPct = Math.round((completedCount / normalizedStages.length) * 100);

  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-accent/10 border border-accent/20 flex items-center justify-center">
            <ChevronRight className="w-3.5 h-3.5 text-accent" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-text-primary">Attack progression</h2>
            <p className="text-2xs text-text-muted">
              Kill-chain stages derived from correlated activity
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-accent/10 border border-accent/20 text-accent text-2xs font-mono font-medium">
            {completedCount}/{normalizedStages.length} stages
          </span>
        </div>
      </div>

      {/* progress bar */}
      <div className="relative h-1.5 rounded-full bg-bg-elevated mb-5 overflow-hidden">
        <div
          className="absolute inset-y-0 left-0 rounded-full bg-gradient-to-r from-blue-500 via-purple-500 to-red-500 transition-all duration-700"
          style={{ width: `${progressPct}%` }}
        />
      </div>

      {/* stage cards */}
      <div className="flex flex-wrap items-stretch gap-2">
        {normalizedStages.map((stage, index) => {
          const completed = completedStages.includes(stage.toLowerCase());
          const c = getStageColors(stage);
          const isLast = index === normalizedStages.length - 1;

          return (
            <div key={`${stage}-${index}`} className="flex items-center gap-2">
              <div
                className={clsx(
                  "relative flex items-center gap-2.5 px-3 py-2.5 rounded-xl border transition-all",
                  completed
                    ? [c.bg, c.border, "hover:shadow-lg hover:shadow-black/10"]
                    : "bg-bg-elevated/40 border-border/40 opacity-50",
                )}
              >
                {/* step number / check */}
                <div
                  className={clsx(
                    "w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold flex-shrink-0 transition-all",
                    completed
                      ? [c.dot, "text-white", c.glow]
                      : "bg-bg-base border border-border text-text-muted",
                  )}
                >
                  {completed ? (
                    <CheckCircle2 className="w-4 h-4" />
                  ) : (
                    <span>{index + 1}</span>
                  )}
                </div>

                <div className="min-w-0">
                  <p className={clsx(
                    "text-xs font-semibold capitalize leading-tight",
                    completed ? c.text : "text-text-muted",
                  )}>
                    {stage}
                  </p>
                  <p className={clsx(
                    "text-2xs mt-0.5",
                    completed ? "text-text-secondary" : "text-text-muted",
                  )}>
                    {completed ? "Observed" : "Not detected"}
                  </p>
                </div>

                {/* subtle glow for completed stages */}
                {completed && (
                  <span className={clsx("absolute inset-0 rounded-xl opacity-20", c.bg)} />
                )}
              </div>

              {/* connector arrow */}
              {!isLast && (
                <ChevronRight className={clsx(
                  "w-4 h-4 flex-shrink-0",
                  completed ? c.text : "text-border",
                  "opacity-40",
                )} />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
