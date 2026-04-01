import clsx from "clsx";
import { ExternalLink, Shield } from "lucide-react";
import type { MitreAttackMapping } from "@/lib/api";

/* ── tactic → colour mapping ────────────────────────────────── */
const TACTIC_COLORS: Record<string, { bg: string; border: string; text: string; dot: string }> = {
  "reconnaissance":        { bg: "bg-blue-500/10",    border: "border-blue-500/30",    text: "text-blue-400",    dot: "bg-blue-400" },
  "resource development":  { bg: "bg-sky-500/10",     border: "border-sky-500/30",     text: "text-sky-400",     dot: "bg-sky-400" },
  "initial access":        { bg: "bg-amber-500/10",   border: "border-amber-500/30",   text: "text-amber-400",   dot: "bg-amber-400" },
  "execution":             { bg: "bg-indigo-500/10",  border: "border-indigo-500/30",  text: "text-indigo-400",  dot: "bg-indigo-400" },
  "persistence":           { bg: "bg-purple-500/10",  border: "border-purple-500/30",  text: "text-purple-400",  dot: "bg-purple-400" },
  "privilege escalation":  { bg: "bg-pink-500/10",    border: "border-pink-500/30",    text: "text-pink-400",    dot: "bg-pink-400" },
  "defense evasion":       { bg: "bg-rose-500/10",    border: "border-rose-500/30",    text: "text-rose-400",    dot: "bg-rose-400" },
  "credential access":     { bg: "bg-emerald-500/10", border: "border-emerald-500/30", text: "text-emerald-400", dot: "bg-emerald-400" },
  "discovery":             { bg: "bg-cyan-500/10",    border: "border-cyan-500/30",    text: "text-cyan-400",    dot: "bg-cyan-400" },
  "lateral movement":      { bg: "bg-teal-500/10",    border: "border-teal-500/30",    text: "text-teal-400",    dot: "bg-teal-400" },
  "collection":            { bg: "bg-amber-500/10",   border: "border-amber-500/30",   text: "text-amber-400",   dot: "bg-amber-400" },
  "command and control":   { bg: "bg-red-500/10",     border: "border-red-500/30",     text: "text-red-400",     dot: "bg-red-400" },
  "exfiltration":          { bg: "bg-fuchsia-500/10", border: "border-fuchsia-500/30", text: "text-fuchsia-400", dot: "bg-fuchsia-400" },
  "impact":                { bg: "bg-gray-500/10",    border: "border-gray-500/30",    text: "text-gray-400",    dot: "bg-gray-400" },
};
const DEFAULT_TACTIC = { bg: "bg-accent/10", border: "border-accent/30", text: "text-accent", dot: "bg-accent" };

function getTacticColors(tactic: string) {
  return TACTIC_COLORS[tactic.toLowerCase().trim()] || DEFAULT_TACTIC;
}

interface IncidentMITRECardProps {
  mappings?: MitreAttackMapping[];
}

export function IncidentMITRECard({ mappings }: IncidentMITRECardProps) {
  if (!Array.isArray(mappings) || mappings.length === 0) return null;

  /* group by tactic */
  const byTactic = new Map<string, MitreAttackMapping[]>();
  for (const m of mappings) {
    const key = m.tactic || "Unknown";
    if (!byTactic.has(key)) byTactic.set(key, []);
    byTactic.get(key)!.push(m);
  }

  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center">
            <Shield className="w-3.5 h-3.5 text-red-400" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-text-primary">MITRE ATT&CK</h2>
            <p className="text-2xs text-text-muted">
              Mapped tactics and techniques
            </p>
          </div>
        </div>
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-2xs font-mono font-medium">
          {mappings.length} technique{mappings.length !== 1 ? "s" : ""}
        </span>
      </div>

      <div className="space-y-4">
        {Array.from(byTactic.entries()).map(([tactic, techniques]) => {
          const c = getTacticColors(tactic);

          return (
            <div key={tactic}>
              {/* tactic header */}
              <div className="flex items-center gap-2 mb-2">
                <span className={clsx("w-2 h-2 rounded-full", c.dot)} />
                <span className={clsx("text-xs font-semibold uppercase tracking-wide", c.text)}>
                  {tactic}
                </span>
                <div className="flex-1 h-px bg-border/30" />
              </div>

              {/* technique cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pl-4">
                {techniques.map((mapping, index) => (
                  <div
                    key={`${mapping.technique_id ?? mapping.technique ?? "t"}-${index}`}
                    className={clsx(
                      "group rounded-xl border p-3 transition-all hover:shadow-lg hover:shadow-black/10",
                      c.bg, c.border,
                    )}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        {mapping.technique_id && (
                          <span className={clsx(
                            "inline-flex items-center px-2 py-0.5 rounded-md text-2xs font-mono font-bold border mb-1.5",
                            c.bg, c.border, c.text,
                          )}>
                            {mapping.technique_id}
                          </span>
                        )}
                        {mapping.technique && (
                          <p className="text-sm font-medium text-text-primary leading-snug">
                            {mapping.technique}
                          </p>
                        )}
                      </div>

                      {mapping.technique_id && (
                        <a
                          href={`https://attack.mitre.org/techniques/${mapping.technique_id.replace(".", "/")}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className={clsx(
                            "flex-shrink-0 w-6 h-6 rounded-md border flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity",
                            c.bg, c.border, c.text,
                          )}
                          title="View on MITRE ATT&CK"
                        >
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
