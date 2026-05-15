"use client";

import { Fragment, useState, useMemo } from "react";
import useSWR, { mutate as globalMutate } from "swr";
import {
  Link2, ShieldCheck, ShieldAlert, AlertTriangle, Gauge, CheckCircle, XCircle,
  RefreshCw, Search, Target, Database, Filter, TrendingUp, Trash2, Activity,
  Globe, FlaskConical, X, Code2, Network, ExternalLink, Shuffle,
  ShieldAlert as ShieldAlertIcon, FileCode2, Link as LinkIcon, DownloadCloud,
  Eye, EyeOff, Fingerprint, AlertOctagon, Layers, Workflow, Sliders, Tag,
  GitBranch, Zap, ArrowRight, Radio,
} from "lucide-react";
import {
  getUrlIntelStats, getUrlIntelHistogram, getUrlIntelAccuracy,
  getUrlIntelRecent, submitUrlIntelFeedback, clearUrlIntelFeedback,
  getIndicatorCacheStats,
  getUrlContentAnalysis, requestUrlContentAnalysis,
  getUrlIntelModelInfo, getUrlIntelCombinedHistogram, getUrlIntelHeatmap,
  getUrlIntelIndicatorTags, getUrlIntelIndicatorLifecycle,
  type UrlIntelStats, type UrlIntelHistogram, type UrlIntelAccuracy,
  type UrlIntelRecentPage, type UrlIntelRecentRow, type UrlVerdict,
  type IndicatorCacheStats,
  type ContentVerdict, type UrlContentAnalysisBundle, type UrlContentIndicators,
  type UrlIntelModelInfo, type UrlIntelCombinedHistogram, type UrlIntelHeatmap,
  type UrlIntelIndicatorTags, type UrlIntelIndicatorLifecycle,
} from "@/lib/api";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { StatCard } from "@/components/ui/StatCard";
import { formatDistanceToNow, parseISO } from "date-fns";
import clsx from "clsx";

// ═══════════════════════════════════════════════════════════════════════════
// Small visual helpers
// ═══════════════════════════════════════════════════════════════════════════

const VERDICT_COLOR: Record<string, string> = {
  benign:     "text-emerald-300 bg-emerald-500/[0.08] border-emerald-500/25",
  suspicious: "text-amber-300   bg-amber-500/[0.08]   border-amber-500/25",
  malicious:  "text-rose-300    bg-rose-500/[0.08]    border-rose-500/30",
  error:      "text-zinc-400    bg-zinc-500/[0.08]    border-zinc-500/25",
};
const VERDICT_DOT: Record<string, string> = {
  benign: "bg-emerald-400", suspicious: "bg-amber-400",
  malicious: "bg-rose-400", error: "bg-zinc-400",
};

function Pill({ children, tone }: { children: React.ReactNode; tone: string }) {
  return (
    <span className={clsx(
      "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md border text-[11px] font-medium tracking-tight capitalize",
      VERDICT_COLOR[tone] || "text-text-secondary bg-bg-elevated border-border")}>
      <span className={clsx("w-1.5 h-1.5 rounded-full", VERDICT_DOT[tone] || "bg-text-muted")} />
      {children}
    </span>
  );
}

function fmtPct(x: number | null | undefined): string {
  if (x === null || x === undefined || isNaN(x)) return "–";
  return `${(x * 100).toFixed(1)}%`;
}
function fmtNum(x: number | null | undefined): string {
  if (x === null || x === undefined) return "–";
  return x.toLocaleString();
}

function ContentBadge({ verdict, score }: { verdict?: string | null; score?: number | null }) {
  if (!verdict) return <span className="text-text-muted text-[10px] italic">pending</span>;
  const tone = verdict === "error" ? "error" : verdict;
  return (
    <span className={clsx(
      "inline-flex items-center gap-1.5 px-1.5 py-0.5 rounded-md border text-[10px] font-medium",
      VERDICT_COLOR[tone] || "text-text-secondary bg-bg-elevated border-border",
    )}>
      <Globe className="w-2.5 h-2.5 opacity-70" />
      <span className="capitalize">{verdict}</span>
      {typeof score === "number" && <span className="opacity-60 tabular-nums">· {score}</span>}
    </span>
  );
}

function CombinedBadge({ verdict, score }: { verdict?: string | null; score?: number | null }) {
  if (verdict === null || verdict === undefined)
    return <span className="text-text-muted text-[10px] italic">–</span>;
  const tone = verdict;
  return (
    <span className={clsx(
      "inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md border text-[10px] font-mono",
      VERDICT_COLOR[tone] || "text-text-secondary bg-bg-elevated border-border",
    )}>
      <Layers className="w-2.5 h-2.5 opacity-70" />
      <span className="capitalize">{verdict}</span>
      {typeof score === "number" && (
        <span className="opacity-60 tabular-nums">· {score.toFixed(2)}</span>
      )}
    </span>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Multi-bar verdict distribution (ML / Content / Combined)
// ═══════════════════════════════════════════════════════════════════════════

function TriVerdictBars({ stats }: { stats: UrlIntelStats }) {
  const make = (label: string, denom: number, counts: { benign: number; suspicious: number; malicious: number; errors?: number }, errorDim = false) => {
    const d = Math.max(1, denom);
    const segs = [
      { label: "benign",     n: counts.benign,     color: "bg-emerald-400/80" },
      { label: "suspicious", n: counts.suspicious, color: "bg-amber-400/80" },
      { label: "malicious",  n: counts.malicious,  color: "bg-rose-400/80" },
      ...(errorDim && counts.errors !== undefined ? [{ label: "error", n: counts.errors, color: "bg-zinc-400/60" }] : []),
    ];
    return { label, denom, segs, total: denom };
  };

  const bars = [
    make("ML verdict",       stats.total,                        stats.counts, true),
    make("Content verdict",  stats.content?.analyzed ?? 0,       stats.content?.counts ?? { benign: 0, suspicious: 0, malicious: 0 }, true),
    make("Combined verdict", stats.combined?.analyzed ?? 0,      stats.combined?.counts ?? { benign: 0, suspicious: 0, malicious: 0 }),
  ];

  return (
    <div className="space-y-4">
      {bars.map(b => (
        <div key={b.label} className="space-y-1.5">
          <div className="flex items-baseline justify-between">
            <span className="text-[11px] font-medium text-text-secondary tracking-tight">{b.label}</span>
            <span className="text-[10px] font-mono text-text-muted tabular-nums">n={fmtNum(b.total)}</span>
          </div>
          <div className="flex h-2.5 rounded-full overflow-hidden bg-bg-elevated/60">
            {b.segs.map((s) => (
              <div key={s.label} title={`${s.label}: ${s.n}`}
                   className={clsx(s.color, "transition-all")}
                   style={{ width: `${(s.n / Math.max(1, b.total)) * 100}%` }} />
            ))}
          </div>
          <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-text-muted">
            {b.segs.map(s => (
              <div key={s.label} className="flex items-center gap-1">
                <span className={clsx("w-1.5 h-1.5 rounded-full", s.color)} />
                <span className="capitalize">{s.label}</span>
                <span className="font-mono tabular-nums text-text-secondary">{fmtNum(s.n)}</span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 5a. Combined-score histogram (with threshold overlay)
// ═══════════════════════════════════════════════════════════════════════════

function CombinedHistogram({ h }: { h: UrlIntelCombinedHistogram }) {
  const max = Math.max(
    1,
    ...h.buckets.map(b => b.benign + b.suspicious + b.malicious),
  );
  const thrX = Math.round(h.threshold_malicious * 100);
  return (
    <div className="space-y-2 relative">
      <div className="flex items-end gap-1 h-36 relative">
        {h.buckets.map(b => {
          const total = b.benign + b.suspicious + b.malicious;
          const h1 = (b.benign / max) * 100;
          const h2 = (b.suspicious / max) * 100;
          const h3 = (b.malicious / max) * 100;
          return (
            <div key={b.bucket} className="flex-1 h-full flex flex-col justify-end group relative rounded-t overflow-hidden">
              <div className="bg-rose-400/80"    style={{ height: `${h3}%` }} />
              <div className="bg-amber-400/80"   style={{ height: `${h2}%` }} />
              <div className="bg-emerald-400/80" style={{ height: `${h1}%` }} />
              <div className="opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none absolute -top-20 left-1/2 -translate-x-1/2 bg-bg-surface border border-border/70 rounded-lg shadow-lg p-2.5 text-[10px] font-mono whitespace-nowrap z-10 space-y-0.5">
                <div className="text-text-muted">combined {b.range}</div>
                <div className="text-text-primary tabular-nums">total {total}</div>
                <div className="text-emerald-300 tabular-nums">benign {b.benign}</div>
                <div className="text-amber-300 tabular-nums">suspicious {b.suspicious}</div>
                <div className="text-rose-300 tabular-nums">malicious {b.malicious}</div>
              </div>
            </div>
          );
        })}
        {/* threshold overlay */}
        <div className="absolute top-0 bottom-0 border-l-2 border-dashed border-rose-400/50 pointer-events-none"
             style={{ left: `${thrX}%` }}>
          <span className="absolute -top-1 left-1 text-[9px] font-mono text-rose-300 bg-bg-surface px-1 rounded whitespace-nowrap">
            thr={h.threshold_malicious}
          </span>
        </div>
      </div>
      <div className="flex justify-between text-2xs text-text-muted font-mono">
        <span>0.0</span><span>0.2</span><span>0.4</span><span>0.6</span><span>0.8</span><span>1.0</span>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 5b. ML×content 2-D heatmap
// ═══════════════════════════════════════════════════════════════════════════

function MlContentHeatmap({ hm }: { hm: UrlIntelHeatmap }) {
  const flat = hm.grid.flat();
  const max = Math.max(1, ...flat);
  return (
    <div className="space-y-2">
      <div className="relative">
        <div className="grid gap-[2px]" style={{ gridTemplateColumns: "auto repeat(10, 1fr)" }}>
          {/* empty top-left */}
          <div />
          {hm.content_buckets.map((c, i) => (
            <div key={i} className="text-[9px] font-mono text-text-muted text-center">{i}</div>
          ))}
          {hm.grid.map((_, i) => (
            <Fragment key={`row-${i}`}>
              <div className="text-[9px] font-mono text-text-muted pr-1 flex items-center justify-end">
                {(9 - i) * 10}
              </div>
              {hm.grid[9 - i].map((v, j) => {
                const t = v / max;
                const ml = (9 - i) * 10;   // ML risk center value
                const ct = j;              // content risk bucket
                const combined = hm.w_ml * (ml / 100) + hm.w_content * Math.min(ct / 10, 1);
                const aboveThr = combined >= hm.threshold_malicious;
                return (
                  <div
                    key={`c-${i}-${j}`}
                    className={clsx(
                      "aspect-square rounded-sm relative group",
                      aboveThr && "ring-1 ring-rose-400/50",
                    )}
                    style={{
                      backgroundColor: v === 0
                        ? "rgb(30 30 35 / 0.3)"
                        : `rgba(239, 68, 68, ${0.15 + t * 0.75})`,
                    }}
                    title={`ml=${ml} content=${ct} n=${v} combined=${combined.toFixed(2)}`}
                  >
                    {v > 0 && (
                      <span className="absolute inset-0 flex items-center justify-center text-[8px] font-mono text-white/80">
                        {v > 999 ? `${(v / 1000).toFixed(1)}k` : v}
                      </span>
                    )}
                  </div>
                );
              })}
            </Fragment>
          ))}
        </div>
      </div>
      <div className="flex items-center justify-between text-[9px] text-text-muted font-mono">
        <span>↓ ML risk (0-100)</span>
        <span>content risk (0-10) →</span>
        <span className="text-rose-300">◻ above threshold = ring</span>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. ML confidence histogram (existing)
// ═══════════════════════════════════════════════════════════════════════════

function Histogram({ h }: { h: UrlIntelHistogram }) {
  const max = Math.max(1, ...h.buckets.map(b => b.benign + b.suspicious + b.malicious));
  return (
    <div className="space-y-2">
      <div className="flex items-end gap-1 h-28">
        {h.buckets.map(b => {
          const total = b.benign + b.suspicious + b.malicious;
          const h1 = (b.benign / max) * 100;
          const h2 = (b.suspicious / max) * 100;
          const h3 = (b.malicious / max) * 100;
          return (
            <div key={b.bucket} className="flex-1 h-full flex flex-col justify-end group relative rounded-t overflow-hidden">
              <div className="bg-rose-400/80"    style={{ height: `${h3}%` }} />
              <div className="bg-amber-400/80"   style={{ height: `${h2}%` }} />
              <div className="bg-emerald-400/80" style={{ height: `${h1}%` }} />
              <div className="opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none absolute -top-16 left-1/2 -translate-x-1/2 bg-bg-surface border border-border/70 rounded-lg shadow-lg p-2 text-[10px] font-mono whitespace-nowrap z-10 space-y-0.5">
                <div className="text-text-muted">conf {b.range}</div>
                <div className="tabular-nums">total {total}</div>
              </div>
            </div>
          );
        })}
      </div>
      <div className="flex justify-between text-2xs text-text-muted font-mono">
        <span>0.0</span><span>0.5</span><span>1.0</span>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Model Health card — single rollup of overall accuracy + 14-day sparkline
// ═══════════════════════════════════════════════════════════════════════════
//
// Replaces the previous three-basis AccuracyCard panel (ML / Content / Combined,
// each with a confusion-matrix mini-table). Operators stopped consulting the
// confusion matrix once the auto-curator started managing labels, so the panel
// collapsed into one widget showing only the combined-basis health.

function AccuracySparkline({ history }: {
  history: { date: string; accuracy: number | null }[];
}) {
  // Inline SVG polyline — keep the dependency surface small and match the
  // hand-rolled Histogram / TagDonut idiom elsewhere on this page.
  const W = 220, H = 48, PAD = 4;
  const innerW = W - PAD * 2, innerH = H - PAD * 2;
  const xStep = history.length > 1 ? innerW / (history.length - 1) : 0;
  // y-axis fixed to [0, 1] so the line communicates absolute accuracy,
  // not a zoomed view of recent noise.
  const yFor = (a: number) => PAD + innerH - a * innerH;

  const plotted = history.flatMap((p, i) =>
    p.accuracy === null ? [] : [{ i, a: p.accuracy }],
  );
  if (plotted.length === 0) {
    return (
      <div className="h-12 flex items-center justify-center text-2xs text-text-muted">
        no labeled data in last 14 days
      </div>
    );
  }
  const points = plotted.map(p => `${PAD + p.i * xStep},${yFor(p.a)}`).join(" ");
  const last = plotted[plotted.length - 1];
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-12" preserveAspectRatio="none">
      {/* 50% baseline */}
      <line x1={PAD} x2={W - PAD} y1={yFor(0.5)} y2={yFor(0.5)}
            stroke="currentColor" className="text-border" strokeDasharray="2 3" strokeWidth={0.5} />
      <polyline points={points} fill="none"
                stroke="currentColor" className="text-accent" strokeWidth={1.5}
                strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={PAD + last.i * xStep} cy={yFor(last.a)} r={2} className="fill-accent" />
    </svg>
  );
}

function ModelHealthCard() {
  // Combined basis — that's what the WCA gate actually uses, so it's the
  // most operationally meaningful single number.
  const { data: acc } = useSWR<UrlIntelAccuracy>(
    ["/url-intel/accuracy", "combined"],
    () => getUrlIntelAccuracy("combined"),
    { refreshInterval: 20_000 },
  );
  if (!acc) {
    return (
      <div className="rounded-lg border border-border/60 bg-bg-elevated/40 p-5 text-2xs text-text-muted">
        Loading model health…
      </div>
    );
  }
  const hasData = acc.total_labels > 0;
  const lastLabelText = acc.last_labeled_at
    ? `${formatDistanceToNow(parseISO(acc.last_labeled_at), { addSuffix: false })} ago`
    : "never";
  return (
    <div className="rounded-lg border border-border/60 bg-bg-elevated/40 p-5">
      <div className="grid md:grid-cols-3 gap-5 items-center">
        {/* Headline accuracy */}
        <div className="space-y-1">
          <div className="text-2xs uppercase tracking-wider text-text-muted">Overall accuracy</div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-semibold tabular-nums text-text-primary leading-none">
              {hasData ? fmtPct(acc.overall_accuracy) : "–"}
            </span>
            {hasData && (
              <span className="text-2xs text-text-muted tabular-nums">
                of {fmtNum(acc.labeled_total)} eval
              </span>
            )}
          </div>
        </div>

        {/* Label volume + freshness */}
        <div className="space-y-2 text-xs">
          <div className="flex items-center justify-between gap-3">
            <span className="text-text-muted">Total labels</span>
            <span className="font-mono tabular-nums text-text-primary">
              {fmtNum(acc.total_labels)}
            </span>
          </div>
          <div className="flex items-center justify-between gap-3">
            <span className="text-text-muted">Last label</span>
            <span className="font-mono tabular-nums text-text-secondary">{lastLabelText}</span>
          </div>
        </div>

        {/* 14-day accuracy sparkline */}
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-2xs uppercase tracking-wider text-text-muted">14-day trend</span>
            <span className="text-2xs text-text-muted font-mono">0–100%</span>
          </div>
          <AccuracySparkline history={acc.accuracy_history} />
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. Tag-distribution donut
// ═══════════════════════════════════════════════════════════════════════════

const TAG_COLOR: Record<string, string> = {
  authoritative_feed: "#10b981",
  combined_gate:      "#f97316",
  content_verified:   "#f97316",
  urlhaus:            "#059669",
  openphish:          "#0d9488",
  spamhaus_dbl:       "#0369a1",
  gsb:                "#7c3aed",
  ml_classified:      "#71717a",
  urlbert:            "#71717a",
  urlbert_classifier: "#71717a",
};

function TagDonut({ data }: { data: UrlIntelIndicatorTags }) {
  const tags = data.tags.slice(0, 10);
  const sum = tags.reduce((a, t) => a + t.count, 0) || 1;
  let off = 0;
  const size = 120, stroke = 18, r = (size - stroke) / 2, c = 2 * Math.PI * r;
  return (
    <div className="flex items-center gap-4">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          {tags.map(t => {
            const frac = t.count / sum;
            const len = c * frac;
            const gap = c - len;
            const seg = (
              <circle key={t.tag}
                cx={size/2} cy={size/2} r={r} fill="none"
                stroke={TAG_COLOR[t.tag] || "#52525b"}
                strokeWidth={stroke}
                strokeDasharray={`${len} ${gap}`}
                strokeDashoffset={-off}
              />
            );
            off += len;
            return seg;
          })}
        </svg>
        <div className="absolute inset-0 flex items-center justify-center flex-col">
          <span className="text-xl font-semibold tabular-nums">{fmtNum(sum)}</span>
          <span className="text-2xs text-text-muted">active tags</span>
        </div>
      </div>
      <div className="flex-1 space-y-0.5">
        {tags.map(t => (
          <div key={t.tag} className="flex items-center gap-2 text-2xs">
            <span className="w-2 h-2 rounded-sm" style={{ background: TAG_COLOR[t.tag] || "#52525b" }} />
            <span className="font-mono text-text-secondary flex-1 truncate">{t.tag}</span>
            <span className="font-mono tabular-nums text-text-muted">{fmtNum(t.count)}</span>
            <span className="font-mono tabular-nums text-text-muted w-10 text-right">
              {fmtPct(t.count / sum)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Label buttons
// ═══════════════════════════════════════════════════════════════════════════

function LabelButtons({ row, onChanged }: {
  row: UrlIntelRecentRow; onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const label = async (lbl: UrlVerdict) => {
    setBusy(true);
    try { await submitUrlIntelFeedback(row.url, lbl); onChanged(); }
    finally { setBusy(false); }
  };
  const clear = async () => {
    setBusy(true);
    try { await clearUrlIntelFeedback(row.id); onChanged(); }
    finally { setBusy(false); }
  };
  return (
    <div className="flex items-center gap-1">
      <button onClick={() => label("benign")} disabled={busy} title="Label as benign"
              className={clsx("btn btn-ghost border border-border px-1.5 py-0.5 text-2xs",
                row.ground_truth === "benign" && "bg-emerald-500/15 text-emerald-400 border-emerald-500/30")}>
        <ShieldCheck className="w-3 h-3" />
      </button>
      <button onClick={() => label("suspicious")} disabled={busy} title="Label as suspicious"
              className={clsx("btn btn-ghost border border-border px-1.5 py-0.5 text-2xs",
                row.ground_truth === "suspicious" && "bg-amber-500/15 text-amber-400 border-amber-500/30")}>
        <AlertTriangle className="w-3 h-3" />
      </button>
      <button onClick={() => label("malicious")} disabled={busy} title="Label as malicious"
              className={clsx("btn btn-ghost border border-border px-1.5 py-0.5 text-2xs",
                row.ground_truth === "malicious" && "bg-red-500/15 text-red-400 border-red-500/30")}>
        <ShieldAlert className="w-3 h-3" />
      </button>
      {row.ground_truth && (
        <button onClick={clear} disabled={busy} title="Clear label"
                className="btn btn-ghost border border-border px-1.5 py-0.5 text-2xs">
          <Trash2 className="w-3 h-3" />
        </button>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Page
// ═══════════════════════════════════════════════════════════════════════════

export default function UrlIntelPage() {
  const [filter, setFilter] = useState<UrlVerdict | "all">("all");
  const [onlyMispred, setOnlyMispred] = useState(false);
  const [onlyLabeled, setOnlyLabeled] = useState<"all" | "labeled" | "unlabeled">("all");
  const [combinedOnly, setCombinedOnly] = useState(false);
  const [search, setSearch] = useState("");
  const [contentRowId, setContentRowId] = useState<number | null>(null);

  const listKey = useMemo(() => [
    "/url-intel/recent", filter, onlyMispred, onlyLabeled, combinedOnly, search,
  ], [filter, onlyMispred, onlyLabeled, combinedOnly, search]);

  const { data: stats, isLoading: sLoading, mutate: mStats } =
    useSWR<UrlIntelStats>("/url-intel/stats", getUrlIntelStats, { refreshInterval: 10_000 });
  const { data: modelInfo } =
    useSWR<UrlIntelModelInfo>("/url-intel/model-info", getUrlIntelModelInfo, { refreshInterval: 60_000 });
  const { data: hist } =
    useSWR<UrlIntelHistogram>("/url-intel/histogram", getUrlIntelHistogram, { refreshInterval: 30_000 });
  const { data: combHist } =
    useSWR<UrlIntelCombinedHistogram>("/url-intel/combined-histogram",
      getUrlIntelCombinedHistogram, { refreshInterval: 30_000 });
  const { data: heatmap } =
    useSWR<UrlIntelHeatmap>("/url-intel/heatmap", getUrlIntelHeatmap, { refreshInterval: 30_000 });
  const { data: tags } =
    useSWR<UrlIntelIndicatorTags>("/url-intel/indicator-tags",
      getUrlIntelIndicatorTags, { refreshInterval: 30_000 });
  const { data: lifecycle } =
    useSWR<UrlIntelIndicatorLifecycle>("/url-intel/indicator-lifecycle",
      () => getUrlIntelIndicatorLifecycle(60, 30), { refreshInterval: 15_000 });
  const { data: cache } =
    useSWR<IndicatorCacheStats>("/indicators/cache/stats", getIndicatorCacheStats, { refreshInterval: 5_000 });
  const { data: recent, mutate: mRecent, isLoading: rLoading } =
    useSWR<UrlIntelRecentPage>(listKey, () => getUrlIntelRecent({
      prediction: filter === "all" ? undefined : filter,
      labeled: onlyLabeled === "all" ? undefined : onlyLabeled === "labeled",
      only_mispredictions: onlyMispred || undefined,
      combined_only: combinedOnly || undefined,
      q: search || undefined,
      limit: 100,
    }), { refreshInterval: 15_000 });

  const refreshAll = () => {
    mStats(); mRecent();
    globalMutate("/url-intel/histogram");
    globalMutate("/url-intel/combined-histogram");
    globalMutate("/url-intel/heatmap");
    globalMutate("/url-intel/indicator-tags");
    globalMutate("/url-intel/indicator-lifecycle");
    globalMutate("/indicators/cache/stats");
    globalMutate("/url-intel/model-info");
  };

  if (sLoading || !stats) return <div className="flex justify-center p-12"><LoadingSpinner /></div>;

  const pipeline = stats.pipeline ?? {
    url_classified: stats.total, content_analyzed: 0, combined_gated: 0,
    combined_ge_thr: 0, active_indicators: 0, feed_confirmed: 0,
  };
  const drift = stats.drift ?? {
    overrides_to_benign: 0, overrides_to_malicious: 0,
    deactivated_24h: 0, upserted_24h: 0,
  };
  const gate = stats.gate_diagnostics ?? {
    ml_bad_content_ok: 0, ml_ok_content_bad: 0,
    both_bad: 0, both_ok: 0, ml_bad_content_pending: 0,
  };
  const feedHits = stats.feed_hits ?? {
    urlhaus: 0, openphish: 0, spamhaus_dbl: 0, gsb: 0,
    combined_only: 0, authoritative_feed: 0,
  };
  const thr = stats.threshold_config ?? {
    w_ml: 0.5, w_content: 0.5, threshold_malicious: 0.55, threshold_suspicious: 0.35,
  };

  // ── 1. Header + classifier badge ──
  const classifierName    = modelInfo?.classifier?.name    ?? "urlfeat-gbdt";
  const classifierVersion = modelInfo?.classifier?.version ?? "v2";

  return (
    <div className="space-y-6">
      {/* ── 1. Header ────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1.5">
          <div className="inline-flex items-center gap-2 text-[10px] uppercase tracking-[0.14em] text-text-muted font-medium">
            <span className="w-1 h-1 rounded-full bg-accent" />
            <span className="font-mono">{classifierName} · {classifierVersion}</span>
            <span className="text-border">·</span>
            <span>Combined-verdict gate {thr.threshold_malicious.toFixed(2)}</span>
          </div>
          <h1 className="text-2xl font-semibold text-text-primary tracking-tight flex items-center gap-2.5">
            <Link2 className="w-5 h-5 text-accent" />
            URL Intel
          </h1>
          <p className="text-sm text-text-muted max-w-2xl leading-relaxed">
            GBDT URL classifier (<span className="font-mono text-text-secondary">ML</span>),
            web-content analyzer (<span className="font-mono text-text-secondary">Content</span>),
            and the authoritative combined gate
            (<span className="font-mono text-text-secondary">Combined</span>) that drives
            indicators + alerts.
          </p>
        </div>
        <button onClick={refreshAll}
                className="btn btn-ghost border border-border/70 text-sm rounded-lg px-3 py-1.5 hover:bg-bg-elevated transition-colors">
          <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
        </button>
      </div>

      {/* ── 2. Pipeline KPI band ─────────────────────────────────── */}
      <div className="rounded-xl border border-border/70 bg-bg-surface p-4 shadow-sm">
        <div className="flex items-center gap-2 text-xs font-semibold text-text-primary mb-3">
          <Workflow className="w-4 h-4 text-accent" /> Pipeline
        </div>
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          <PipelineStep label="URL classified" value={pipeline.url_classified} icon={<Database className="w-3 h-3" />} />
          <PipelineStep label="Content analyzed" value={pipeline.content_analyzed}
                        ratio={pipeline.url_classified > 0 ? pipeline.content_analyzed / pipeline.url_classified : 0}
                        icon={<Globe className="w-3 h-3" />} arrow />
          <PipelineStep label="Combined gated" value={pipeline.combined_gated}
                        ratio={pipeline.content_analyzed > 0 ? pipeline.combined_gated / pipeline.content_analyzed : 0}
                        icon={<Layers className="w-3 h-3" />} arrow />
          <PipelineStep label="≥ threshold" value={pipeline.combined_ge_thr}
                        ratio={pipeline.combined_gated > 0 ? pipeline.combined_ge_thr / pipeline.combined_gated : 0}
                        icon={<Zap className="w-3 h-3 text-rose-400" />} arrow tone="danger" />
          <PipelineStep label="Active indicators" value={pipeline.active_indicators}
                        icon={<Radio className="w-3 h-3 text-accent" />} arrow />
          <PipelineStep label="Feed-confirmed" value={pipeline.feed_confirmed}
                        ratio={pipeline.active_indicators > 0 ? pipeline.feed_confirmed / pipeline.active_indicators : 0}
                        icon={<ShieldCheck className="w-3 h-3 text-emerald-400" />} />
        </div>
      </div>

      {/* ── 2b. Verdict-drift counters ───────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <DriftCard label="Overrides → benign" value={drift.overrides_to_benign} tone="success" sub="content wins, ML was false-positive" />
        <DriftCard label="Overrides → malicious" value={drift.overrides_to_malicious} tone="danger" sub="content wins, ML was false-negative" />
        <DriftCard label="Indicators upserted · 24h" value={drift.upserted_24h} tone="danger" sub="combined-gate ≥ threshold" />
        <DriftCard label="Indicators deactivated · 24h" value={drift.deactivated_24h} tone="muted" sub="combined-gate < threshold" />
      </div>

      {/* ── 4. Verdict distribution (3 bars) + Histograms ───────── */}
      <div className="grid lg:grid-cols-3 gap-4">
        <section className="rounded-xl border border-border/70 bg-bg-surface p-5 space-y-4 shadow-sm lg:col-span-1">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              <Gauge className="w-4 h-4 text-accent" /> Verdict distribution
            </h2>
            <span className="text-[10px] text-text-muted font-mono tabular-nums">
              avg conf {fmtPct(stats.avg_confidence)} · avg risk {stats.avg_risk_score.toFixed(0)}
            </span>
          </div>
          <TriVerdictBars stats={stats} />
        </section>

        <section className="rounded-xl border border-border/70 bg-bg-surface p-5 space-y-3 shadow-sm">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <Layers className="w-4 h-4 text-accent" /> Combined-score histogram
          </h2>
          {combHist ? <CombinedHistogram h={combHist} /> : <LoadingSpinner />}
          <div className="text-2xs text-text-muted">
            combined = {thr.w_ml.toFixed(2)}·ML + {thr.w_content.toFixed(2)}·content —
            ≥{thr.threshold_malicious.toFixed(2)} ⇒ indicator-active
          </div>
        </section>

        <section className="rounded-xl border border-border/70 bg-bg-surface p-5 space-y-3 shadow-sm">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-accent" /> ML confidence (legacy)
          </h2>
          {hist ? <Histogram h={hist} /> : <LoadingSpinner />}
          <div className="text-2xs text-text-muted">
            Pure ML probability — reference only, no indicator authority.
          </div>
        </section>
      </div>

      {/* ── 5b. Heatmap + gate diagnostics ──────────────────────── */}
      <div className="grid lg:grid-cols-3 gap-4">
        <section className="rounded-xl border border-border/70 bg-bg-surface p-5 space-y-3 shadow-sm lg:col-span-2">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-accent" /> ML × Content density
          </h2>
          {heatmap ? <MlContentHeatmap hm={heatmap} /> : <LoadingSpinner />}
        </section>

        <section className="rounded-xl border border-border/70 bg-bg-surface p-5 space-y-3 shadow-sm">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-accent" /> Gate diagnostics
          </h2>
          <div className="space-y-1.5 text-xs">
            <DiagRow label="Both ML + content ∈ bad" value={gate.both_bad} tone="danger" />
            <DiagRow label="ML bad · content ok"       value={gate.ml_bad_content_ok} tone="warn"
                     note="candidates for gate to suppress" />
            <DiagRow label="ML ok · content bad"       value={gate.ml_ok_content_bad} tone="warn"
                     note="candidates for gate to promote" />
            <DiagRow label="Both ok"                   value={gate.both_ok} tone="muted" />
            <DiagRow label="ML bad · content pending"  value={gate.ml_bad_content_pending} tone="muted"
                     note="awaiting WCA enrichment" />
          </div>
        </section>
      </div>

      {/* ── 6. Model Health ─────────────────────────────────────── */}
      <section className="rounded-xl border border-border/70 bg-bg-surface p-5 space-y-3 shadow-sm">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <Target className="w-4 h-4 text-accent" /> Model Health
          </h2>
          <span className="text-[10px] text-text-muted font-mono tabular-nums">
            {stats.labeled} labeled
          </span>
        </div>
        <ModelHealthCard />
      </section>

      {/* ── 7. Top domains with indicator-state ─── 10. Tag donut ── 11. Threshold knob ── */}
      <div className="grid lg:grid-cols-3 gap-4">
        {/* Top domains */}
        <section className="rounded-xl border border-border/70 bg-bg-surface p-5 lg:col-span-2 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              <Activity className="w-4 h-4 text-accent" /> Top domains by hit count
            </h2>
            <span className="text-[10px] text-text-muted tabular-nums">{stats.top_domains.length} domains</span>
          </div>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wider text-text-muted">
                <th className="pb-2 pr-3 font-medium">Domain</th>
                <th className="pb-2 pr-3 font-medium">ML</th>
                <th className="pb-2 pr-3 font-medium">Content</th>
                <th className="pb-2 pr-3 font-medium">Combined</th>
                <th className="pb-2 pr-3 font-medium">Indicator</th>
                <th className="pb-2 pr-3 font-medium text-right">Hits</th>
                <th className="pb-2 pr-3 font-medium text-right">Avg conf</th>
              </tr>
            </thead>
            <tbody>
              {stats.top_domains.map((d: any, i: number) => (
                <tr key={i} className="border-t border-border/50 hover:bg-bg-elevated/40 transition-colors">
                  <td className="py-2 pr-3 font-mono truncate max-w-xs text-text-primary">{d.domain}</td>
                  <td className="py-2 pr-3"><Pill tone={d.prediction}>{d.prediction}</Pill></td>
                  <td className="py-2 pr-3">
                    {d.content_verdict ? <Pill tone={d.content_verdict}>{d.content_verdict}</Pill>
                                       : <span className="text-text-muted text-[10px]">–</span>}
                  </td>
                  <td className="py-2 pr-3">
                    {d.combined_bad === true
                      ? <span className="inline-flex items-center gap-1 text-rose-300 text-[10px] font-mono">
                          <Zap className="w-3 h-3" /> bad
                        </span>
                      : d.combined_bad === false
                        ? <span className="text-emerald-300/80 text-[10px] font-mono">ok</span>
                        : <span className="text-text-muted text-[10px]">–</span>}
                  </td>
                  <td className="py-2 pr-3">
                    {d.indicator_active
                      ? <span className="inline-flex items-center gap-1 text-rose-300 text-[10px] font-mono">
                          <Radio className="w-3 h-3" /> active
                        </span>
                      : <span className="text-text-muted text-[10px]">inactive</span>}
                  </td>
                  <td className="py-2 pr-3 text-right font-mono tabular-nums">{fmtNum(d.hits)}</td>
                  <td className="py-2 pr-3 text-right font-mono tabular-nums text-text-secondary">{Number(d.avg_conf).toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {/* 11. Threshold knob card */}
        <section className="rounded-xl border border-border/70 bg-bg-surface p-5 space-y-3 shadow-sm">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <Sliders className="w-4 h-4 text-accent" /> Gate configuration
          </h2>
          <div className="space-y-2 text-xs">
            <ConfigRow k="w_ml"                 v={thr.w_ml.toFixed(2)} />
            <ConfigRow k="w_content"            v={thr.w_content.toFixed(2)} />
            <ConfigRow k="threshold malicious"  v={thr.threshold_malicious.toFixed(2)} tone="danger" />
            <ConfigRow k="threshold suspicious" v={thr.threshold_suspicious.toFixed(2)} tone="warn" />
          </div>
          <div className="text-2xs text-text-muted border-t border-border/50 pt-2 font-mono leading-relaxed">
            combined = w_ml · (risk/100) + w_content · min(content/10, 1)
            <br />≥ threshold_malicious ⇒ indicator upsert (active)
            <br />&lt; threshold_malicious ⇒ indicator deactivate (if ML-only)
          </div>
          <div className="text-2xs text-text-muted">
            Set via env: <span className="font-mono">URL_INTEL_W_ML</span>,
            <span className="font-mono"> URL_INTEL_W_CONTENT</span>,
            <span className="font-mono"> ALERT_COMBINED_THR</span>.
          </div>
        </section>
      </div>

      {/* ── 10. Tag donut · 12. Feed hits · Indicator cache ─────── */}
      <div className="grid lg:grid-cols-3 gap-4">
        <section className="rounded-xl border border-border/70 bg-bg-surface p-5 space-y-3 shadow-sm">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <Tag className="w-4 h-4 text-accent" /> Indicator tags (active)
          </h2>
          {tags ? <TagDonut data={tags} /> : <LoadingSpinner />}
        </section>

        <section className="rounded-xl border border-border/70 bg-bg-surface p-5 space-y-3 shadow-sm">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-accent" /> Feed-hit breakdown
          </h2>
          <div className="space-y-1.5 text-xs">
            <FeedRow label="URLhaus"       value={feedHits.urlhaus}      color="#059669" />
            <FeedRow label="OpenPhish"     value={feedHits.openphish}    color="#0d9488" />
            <FeedRow label="Spamhaus DBL"  value={feedHits.spamhaus_dbl} color="#0369a1" />
            <FeedRow label="GSB"           value={feedHits.gsb}          color="#7c3aed" />
            <FeedRow label="Combined-only" value={feedHits.combined_only} color="#f97316" dashed />
          </div>
          <div className="text-2xs text-text-muted pt-2 border-t border-border/50">
            <span className="font-mono">combined-only</span> = active indicators with no authoritative feed match
            (promoted purely by combined-gate).
          </div>
        </section>

        <section className="rounded-xl border border-border/70 bg-bg-surface p-5 space-y-3 shadow-sm">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <Database className="w-4 h-4 text-accent" /> Indicator cache
          </h2>
          {cache ? (
            <>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-semibold text-accent tracking-tight tabular-nums">
                  {fmtPct(cache.hit_ratio)}
                </span>
                <span className="text-xs text-text-muted">hit ratio</span>
              </div>
              <div className="text-xs space-y-1.5">
                {[
                  ["hits", cache.hits],
                  ["negative hits", cache.negative_hits],
                  ["misses → pg", cache.misses],
                  ["invalidations", cache.invalidations],
                  ["errors", cache.errors],
                ].map(([label, value]) => (
                  <div key={String(label)} className="flex justify-between items-baseline">
                    <span className="text-text-muted">{label}</span>
                    <span className="font-mono tabular-nums text-text-primary">{fmtNum(value as number)}</span>
                  </div>
                ))}
              </div>
              <div className="text-[10px] text-text-muted pt-2 border-t border-border/50 font-mono tabular-nums">
                TTL hit {cache.ttl_hit_seconds}s · miss {cache.ttl_miss_seconds}s
              </div>
            </>
          ) : <LoadingSpinner />}
        </section>
      </div>

      {/* ── 9. Indicator lifecycle stream ────────────────────────── */}
      <section className="rounded-xl border border-border/70 bg-bg-surface shadow-sm">
        <div className="px-5 py-3 border-b border-border/60 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <Activity className="w-4 h-4 text-accent" /> Indicator lifecycle · last 60 min
          </h2>
          <span className="text-[10px] text-text-muted font-mono tabular-nums">
            {lifecycle?.events.length ?? 0} events
          </span>
        </div>
        <div className="max-h-72 overflow-y-auto divide-y divide-border/60">
          {lifecycle?.events.length ? lifecycle.events.map(e => (
            <div key={e.id} className="px-5 py-2 flex items-center gap-3 text-xs hover:bg-bg-elevated/40">
              <span className="text-2xs text-text-muted font-mono w-16">
                {formatDistanceToNow(parseISO(e.last_seen), { addSuffix: false })} ago
              </span>
              {e.event === "upsert" ? (
                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-2xs font-mono
                                 bg-rose-500/15 text-rose-300 border border-rose-500/30">
                  <ArrowRight className="w-2.5 h-2.5" /> upsert
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-2xs font-mono
                                 bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                  <CheckCircle className="w-2.5 h-2.5" /> deactivate
                </span>
              )}
              <span className="font-mono text-text-primary flex-1 truncate" title={e.value}>{e.value}</span>
              <div className="flex flex-wrap gap-0.5 max-w-xs">
                {e.tags.slice(0, 3).map((t, i) => (
                  <span key={i} className="inline-block px-1 py-0.5 text-[9px] font-mono rounded border border-border bg-bg-elevated">
                    {t}
                  </span>
                ))}
                {e.tags.length > 3 && (
                  <span className="text-[9px] text-text-muted">+{e.tags.length - 3}</span>
                )}
              </div>
            </div>
          )) : (
            <div className="px-5 py-6 text-center text-xs text-text-muted">
              No lifecycle events in the last hour.
            </div>
          )}
        </div>
      </section>

      {/* ── 13. Recent predictions (with Combined column) ──────── */}
      <section className="rounded-xl border border-border/70 bg-bg-surface shadow-sm overflow-hidden">
        <div className="px-5 py-4 border-b border-border/60 flex flex-wrap items-center gap-3">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <Filter className="w-4 h-4 text-accent" /> Recent predictions
          </h2>

          <div className="flex items-center gap-1 ml-auto rounded-lg border border-border/60 bg-bg-elevated/40 p-0.5">
            {(["all","benign","suspicious","malicious"] as const).map(v => (
              <button key={v} onClick={() => setFilter(v)}
                      className={clsx(
                        "text-[11px] px-2.5 py-1 rounded-md capitalize transition-colors",
                        filter === v
                          ? "bg-accent/15 text-accent"
                          : "text-text-secondary hover:text-text-primary hover:bg-bg-elevated")}>
                {v}
              </button>
            ))}
          </div>

          <select value={onlyLabeled}
                  onChange={e => setOnlyLabeled(e.target.value as any)}
                  className="ti-input text-xs w-32 rounded-lg">
            <option value="all">all rows</option>
            <option value="labeled">labeled only</option>
            <option value="unlabeled">unlabeled only</option>
          </select>

          <label className="flex items-center gap-1.5 text-xs text-text-secondary cursor-pointer select-none">
            <input type="checkbox" checked={onlyMispred}
                   onChange={e => setOnlyMispred(e.target.checked)}
                   className="accent-accent" />
            mispredictions
          </label>

          <label className="flex items-center gap-1.5 text-xs text-text-secondary cursor-pointer select-none">
            <input type="checkbox" checked={combinedOnly}
                   onChange={e => setCombinedOnly(e.target.checked)}
                   className="accent-accent" />
            combined ≥ threshold
          </label>

          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
            <input type="text" placeholder="search url / domain"
                   value={search} onChange={e => setSearch(e.target.value)}
                   className="ti-input text-xs pl-7 w-56 rounded-lg" />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-bg-surface/95 backdrop-blur">
              <tr className="text-left text-[10px] uppercase tracking-wider text-text-muted">
                <th className="py-2.5 px-4 font-medium">ML verdict</th>
                <th className="py-2.5 px-3 font-medium">Content</th>
                <th className="py-2.5 px-3 font-medium">Combined</th>
                <th className="py-2.5 px-3 font-medium">Indicator</th>
                <th className="py-2.5 px-3 font-medium text-right">Conf</th>
                <th className="py-2.5 px-3 font-medium text-right">Risk</th>
                <th className="py-2.5 px-3 font-medium">URL</th>
                <th className="py-2.5 px-3 font-medium text-right">Hits</th>
                <th className="py-2.5 px-3 font-medium">Last seen</th>
                <th className="py-2.5 px-3 font-medium">Truth</th>
                <th className="py-2.5 px-3 font-medium">Label</th>
              </tr>
            </thead>
            <tbody>
              {rLoading && (
                <tr><td colSpan={11} className="py-8 text-center"><LoadingSpinner /></td></tr>
              )}
              {!rLoading && recent && recent.items.length === 0 && (
                <tr><td colSpan={11} className="py-6 text-center text-text-muted">No rows match.</td></tr>
              )}
              {!rLoading && recent && recent.items.map(r => {
                const mispred   = r.ground_truth && r.ground_truth !== r.prediction;
                const overridden = !!r.override_reason;
                const combinedBad = r.combined_verdict === "malicious";
                return (
                  <tr key={r.id} className={clsx(
                    "border-t border-border/60 hover:bg-bg-elevated/60 transition-colors",
                    mispred && "bg-red-500/[0.04]",
                    combinedBad && "bg-rose-500/[0.04]",
                    overridden && r.original_prediction && r.original_prediction !== r.prediction && "bg-blue-500/[0.04]",
                  )}>
                    <td className="py-2 px-3">
                      <div className="flex items-center gap-1.5">
                        <Pill tone={r.prediction}>{r.prediction}</Pill>
                        {overridden && r.original_prediction && r.original_prediction !== r.prediction && (
                          <span title={`overridden from ${r.original_prediction}: ${r.override_reason}`}
                                className="inline-flex items-center gap-1 text-blue-300/90 text-[10px] font-mono">
                            <span className="text-text-muted">was</span>
                            <span className="line-through opacity-70">{r.original_prediction}</span>
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-2 px-3">
                      <button onClick={() => setContentRowId(r.id)}
                              className="hover:opacity-80 transition-opacity"
                              title="Open content analysis details">
                        <ContentBadge verdict={r.content_verdict} score={r.content_risk_score} />
                      </button>
                    </td>
                    <td className="py-2 px-3">
                      <CombinedBadge verdict={r.combined_verdict} score={r.combined_score} />
                    </td>
                    <td className="py-2 px-3">
                      {r.indicator_active === null || r.indicator_active === undefined ? (
                        <span className="text-text-muted text-[10px]">–</span>
                      ) : r.indicator_active ? (
                        <span title={r.indicator_tags?.join(", ")}
                              className="inline-flex items-center gap-1 text-rose-300 text-[10px] font-mono">
                          <Radio className="w-2.5 h-2.5" /> active
                        </span>
                      ) : (
                        <span className="text-text-muted text-[10px]">inactive</span>
                      )}
                    </td>
                    <td className="py-2 px-3 font-mono tabular-nums text-right text-text-secondary">{r.confidence.toFixed(3)}</td>
                    <td className="py-2 px-3 font-mono tabular-nums text-right text-text-secondary">{r.risk_score}</td>
                    <td className="py-2 px-3 font-mono truncate max-w-md text-text-primary" title={r.url}>{r.url}</td>
                    <td className="py-2 px-3 font-mono tabular-nums text-right text-text-secondary">{r.hit_count}</td>
                    <td className="py-2 px-3 text-text-muted whitespace-nowrap">
                      {formatDistanceToNow(parseISO(r.last_seen), { addSuffix: true })}
                    </td>
                    <td className="py-2 px-3">
                      {r.ground_truth ? <Pill tone={r.ground_truth}>{r.ground_truth}</Pill> : <span className="text-text-muted">—</span>}
                    </td>
                    <td className="py-2 px-3">
                      <LabelButtons row={r} onChanged={() => { mRecent(); mStats(); }} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {recent && (
          <div className="px-5 py-2.5 text-[11px] text-text-muted border-t border-border/60 flex items-center justify-between bg-bg-elevated/30">
            <span className="tabular-nums">showing {recent.items.length} of {fmtNum(recent.total)}</span>
          </div>
        )}
      </section>

      {contentRowId !== null && (
        <ContentAnalysisModal rowId={contentRowId}
          onClose={() => setContentRowId(null)}
          onReanalyzed={() => { mRecent(); mStats(); }} />
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Supporting small components
// ═══════════════════════════════════════════════════════════════════════════

function PipelineStep({ label, value, ratio, icon, arrow, tone }: {
  label: string; value: number; ratio?: number;
  icon: React.ReactNode; arrow?: boolean;
  tone?: "danger" | "success" | "default";
}) {
  return (
    <div className="relative">
      {arrow && (
        <ArrowRight className="hidden md:block w-3 h-3 text-border absolute -left-2.5 top-3" />
      )}
      <div className={clsx(
        "rounded-lg border px-3 py-2 space-y-1",
        tone === "danger" ? "border-rose-500/30 bg-rose-500/[0.03]"
                          : "border-border/60 bg-bg-elevated/40",
      )}>
        <div className="flex items-center gap-1.5 text-[10px] text-text-muted uppercase tracking-wide">
          {icon}{label}
        </div>
        <div className="flex items-baseline gap-1.5">
          <span className="text-lg font-semibold tabular-nums text-text-primary">{fmtNum(value)}</span>
          {ratio !== undefined && ratio > 0 && (
            <span className="text-2xs font-mono tabular-nums text-text-muted">
              {(ratio * 100).toFixed(1)}%
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function DriftCard({ label, value, tone, sub }: {
  label: string; value: number;
  tone: "success" | "danger" | "muted";
  sub: string;
}) {
  const toneCls = tone === "success" ? "border-emerald-500/25 bg-emerald-500/[0.04]"
                : tone === "danger"  ? "border-rose-500/25    bg-rose-500/[0.04]"
                                     : "border-border/60      bg-bg-elevated/40";
  const valCls  = tone === "success" ? "text-emerald-300"
                : tone === "danger"  ? "text-rose-300"
                                     : "text-text-primary";
  return (
    <div className={clsx("rounded-lg border p-3 space-y-1", toneCls)}>
      <div className="text-[10px] text-text-muted uppercase tracking-wide">{label}</div>
      <div className={clsx("text-2xl font-semibold tabular-nums", valCls)}>{fmtNum(value)}</div>
      <div className="text-2xs text-text-muted">{sub}</div>
    </div>
  );
}

function DiagRow({ label, value, tone, note }: {
  label: string; value: number;
  tone: "danger" | "warn" | "muted";
  note?: string;
}) {
  const valCls = tone === "danger" ? "text-rose-300"
               : tone === "warn"   ? "text-amber-300"
                                   : "text-text-secondary";
  return (
    <div className="flex items-baseline justify-between gap-2">
      <div className="flex-1">
        <div className="text-text-secondary">{label}</div>
        {note && <div className="text-2xs text-text-muted">{note}</div>}
      </div>
      <span className={clsx("font-mono tabular-nums text-sm", valCls)}>{fmtNum(value)}</span>
    </div>
  );
}

function ConfigRow({ k, v, tone }: {
  k: string; v: string; tone?: "danger" | "warn";
}) {
  const vCls = tone === "danger" ? "text-rose-300"
             : tone === "warn"   ? "text-amber-300"
                                 : "text-text-primary";
  return (
    <div className="flex items-baseline justify-between gap-2">
      <span className="font-mono text-text-secondary">{k}</span>
      <span className={clsx("font-mono tabular-nums", vCls)}>{v}</span>
    </div>
  );
}

function FeedRow({ label, value, color, dashed }: {
  label: string; value: number; color: string; dashed?: boolean;
}) {
  return (
    <div className="flex items-center gap-2">
      <span className={clsx("w-2 h-2 rounded-sm", dashed && "ring-1 ring-dashed")}
            style={{ background: color }} />
      <span className="flex-1 text-text-secondary">{label}</span>
      <span className="font-mono tabular-nums text-text-primary">{fmtNum(value)}</span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Content Analysis modal (unchanged, minus header tweak)
// ═══════════════════════════════════════════════════════════════════════════

function nz(n: number | undefined | null): boolean {
  return typeof n === "number" && n > 0;
}

function Metric({ label, value, highlight, mono = true }: {
  label: string; value: React.ReactNode; highlight?: boolean; mono?: boolean;
}) {
  return (
    <div className={clsx(
      "rounded border px-2 py-1.5",
      highlight ? "border-red-500/40 bg-red-500/5" : "border-border bg-bg-elevated",
    )}>
      <div className="text-2xs text-text-muted uppercase tracking-wide">{label}</div>
      <div className={clsx("mt-0.5 text-sm", mono && "font-mono", highlight && "text-red-300")}>
        {value ?? "–"}
      </div>
    </div>
  );
}

function Chips({ items, tone = "neutral", max = 10 }: {
  items: string[] | undefined | null;
  tone?: "neutral" | "warn" | "danger"; max?: number;
}) {
  const arr = (items || []).slice(0, max);
  if (!arr.length) return <span className="text-text-muted text-2xs italic">none</span>;
  const cls = tone === "danger" ? "text-red-300 border-red-500/40 bg-red-500/10"
            : tone === "warn"   ? "text-amber-300 border-amber-500/40 bg-amber-500/10"
                                : "text-text-secondary border-border bg-bg-elevated";
  return (
    <div className="flex flex-wrap gap-1">
      {arr.map((s, i) => (
        <span key={i} className={clsx(
          "inline-block px-1.5 py-0.5 rounded border text-2xs font-mono break-all",
          cls,
        )} title={s}>{s.length > 80 ? s.slice(0, 80) + "…" : s}</span>
      ))}
      {(items?.length || 0) > max && (
        <span className="text-2xs text-text-muted">+{(items!.length - max)} more</span>
      )}
    </div>
  );
}

function Section({ title, icon, danger, children }: {
  title: string; icon: React.ReactNode; danger?: boolean; children: React.ReactNode;
}) {
  return (
    <div className={clsx("rounded border", danger ? "border-red-500/30" : "border-border")}>
      <div className={clsx(
        "px-3 py-2 flex items-center gap-2 border-b",
        danger ? "border-red-500/30 bg-red-500/5" : "border-border bg-bg-elevated/40",
      )}>
        {icon}
        <span className="font-semibold text-text-primary">{title}</span>
      </div>
      <div className="p-3 space-y-2 text-xs">{children}</div>
    </div>
  );
}

function IndicatorPanel({ ind }: { ind: UrlContentIndicators }) {
  const p = ind.phishing, j = ind.js_obfuscation, h = ind.hidden_dom;
  const r = ind.redirects, x = ind.external_resources, l = ind.links;
  const m = ind.malware_delivery, c = ind.page_complexity;

  const phishingHot = nz(p.password_input_count) || nz(p.forms_posting_external)
    || nz(p.forms_posting_http_on_https_page) || nz(p.hidden_form_count)
    || p.brand_domain_mismatch || p.suspicious_title_keywords.length > 0;
  const jsHot = nz(j.eval_calls) || nz(j.new_function_calls) || nz(j.long_hex_blobs)
    || nz(j.long_b64_blobs) || nz(j.obfuscated_identifiers) || j.document_write_script_tag
    || (j.crypto_miner_tokens?.length || 0) > 0 || j.wasm_loading
    || nz(j.dynamic_script_creation) || j.clipboard_access || nz(j.key_event_listeners)
    || j.fingerprinting.canvas || j.fingerprinting.webgl || j.fingerprinting.audio
    || j.fingerprinting.fonts;
  const domHot = nz(h.hidden_iframes) || nz(h.invisible_overlays)
    || nz(h.fullpage_invisible_els) || (h.external_iframe_srcs?.length || 0) > 0;
  const redirHot = r.chain_length > 3 || r.cross_domain_hops > 0
    || !!r.meta_refresh || nz(r.js_location_assignments);
  const extHot = (x.scripts_from_ip?.length || 0) > 0
    || (x.scripts_from_suspicious_tld?.length || 0) > 0
    || x.final_url_suspicious_tld || x.final_url_is_ip || x.external_domain_count > 20;
  const linkHot = nz(l.links_to_ip) || (l.shortener_links?.length || 0) > 0
    || (l.mismatched_anchor_url?.length || 0) > 0 || (l.executable_file_links?.length || 0) > 0;
  const malHot = nz(m.auto_download_attr_links) || m.content_disposition_attachment
    || nz(m.executable_file_links_count) || m.dynamic_script_injection;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-xs">
        <ShieldAlertIcon className="w-3.5 h-3.5 text-accent" />
        <span className="font-semibold text-text-primary">Security indicators</span>
        <span className="text-text-muted text-2xs font-mono">({ind.extractor_version})</span>
      </div>

      <Section title="1. Phishing indicators" icon={<ShieldAlertIcon className="w-3.5 h-3.5 text-red-400" />} danger={phishingHot}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <Metric label="Login forms"       value={p.login_form_count}     highlight={nz(p.login_form_count)} />
          <Metric label="Password inputs"   value={p.password_input_count} highlight={nz(p.password_input_count)} />
          <Metric label="Hidden forms"      value={p.hidden_form_count}    highlight={nz(p.hidden_form_count)} />
          <Metric label="Forms → external"  value={p.forms_posting_external} highlight={nz(p.forms_posting_external)} />
          <Metric label="HTTP post on HTTPS" value={p.forms_posting_http_on_https_page} highlight={nz(p.forms_posting_http_on_https_page)} />
          <Metric label="Brand mismatch"    value={p.brand_domain_mismatch ? "yes" : "no"} highlight={p.brand_domain_mismatch} />
        </div>
        <div>
          <div className="text-2xs text-text-muted uppercase mb-1">Suspicious title keywords</div>
          <Chips items={p.suspicious_title_keywords} tone="warn" />
        </div>
        <div>
          <div className="text-2xs text-text-muted uppercase mb-1">Brand keywords</div>
          <Chips items={[...p.brand_keywords_in_title, ...p.brand_keywords_in_body]} tone="warn" />
        </div>
      </Section>

      <Section title="2. JS / obfuscation" icon={<FileCode2 className="w-3.5 h-3.5 text-amber-400" />} danger={jsHot}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <Metric label="eval()"           value={j.eval_calls}          highlight={nz(j.eval_calls)} />
          <Metric label="new Function()"   value={j.new_function_calls}  highlight={nz(j.new_function_calls)} />
          <Metric label="atob()"           value={j.atob_calls}          highlight={j.atob_calls > 5} />
          <Metric label="long b64 blobs"   value={j.long_b64_blobs}      highlight={nz(j.long_b64_blobs)} />
          <Metric label="obfuscated ids"   value={j.obfuscated_identifiers} highlight={j.obfuscated_identifiers >= 10} />
          <Metric label="entropy (bits)"   value={j.largest_inline_script_entropy.toFixed(2)} highlight={j.largest_inline_script_entropy >= 5.2} />
        </div>
      </Section>

      <Section title="3. Hidden DOM" icon={<EyeOff className="w-3.5 h-3.5 text-purple-400" />} danger={domHot}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <Metric label="iframes total"      value={h.total_iframes} />
          <Metric label="hidden iframes"     value={h.hidden_iframes} highlight={nz(h.hidden_iframes)} />
          <Metric label="invisible overlays" value={h.invisible_overlays} highlight={nz(h.invisible_overlays)} />
          <Metric label="display:none"       value={h.display_none_elements} />
        </div>
      </Section>

      <Section title="4. Redirects" icon={<Shuffle className="w-3.5 h-3.5 text-cyan-400" />} danger={redirHot}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <Metric label="chain length"      value={r.chain_length} highlight={r.chain_length > 3} />
          <Metric label="cross-domain hops" value={r.cross_domain_hops} highlight={nz(r.cross_domain_hops)} />
          <Metric label="meta refresh"      value={r.meta_refresh ? `${r.meta_refresh.delay}s` : "none"} highlight={!!r.meta_refresh} />
        </div>
      </Section>

      <Section title="5. External resources" icon={<Network className="w-3.5 h-3.5 text-blue-400" />} danger={extHot}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <Metric label="external domains" value={x.external_domain_count} highlight={x.external_domain_count > 20} />
          <Metric label="scripts from IP"  value={x.scripts_from_ip.length} highlight={x.scripts_from_ip.length > 0} />
          <Metric label="final URL on susp TLD" value={x.final_url_suspicious_tld ? "yes" : "no"} highlight={x.final_url_suspicious_tld} />
        </div>
      </Section>

      <Section title="6. Link analysis" icon={<LinkIcon className="w-3.5 h-3.5 text-emerald-400" />} danger={linkHot}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <Metric label="total"            value={l.total_links} />
          <Metric label="external"         value={l.external_links} />
          <Metric label="shortener"        value={l.shortener_links.length} highlight={l.shortener_links.length > 0} />
          <Metric label="executable"       value={l.executable_file_links.length} highlight={l.executable_file_links.length > 0} />
        </div>
      </Section>

      <Section title="7. Malware delivery" icon={<DownloadCloud className="w-3.5 h-3.5 text-red-400" />} danger={malHot}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <Metric label="download-attr"    value={m.auto_download_attr_links} highlight={nz(m.auto_download_attr_links)} />
          <Metric label="attachment hdr"   value={m.content_disposition_attachment ? "yes" : "no"} highlight={m.content_disposition_attachment} />
          <Metric label="exe links"        value={m.executable_file_links_count} highlight={nz(m.executable_file_links_count)} />
        </div>
      </Section>

      <Section title="8. Page complexity" icon={<AlertOctagon className="w-3.5 h-3.5 text-text-muted" />}>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
          <Metric label="HTML size" value={fmtNum(c.html_size)} />
          <Metric label="scripts"   value={c.script_count} />
          <Metric label="iframes"   value={c.iframe_count} />
          <Metric label="forms"     value={c.form_count} />
          <Metric label="links"     value={c.link_count} />
        </div>
      </Section>
    </div>
  );
}

function ContentAnalysisModal({ rowId, onClose, onReanalyzed }: {
  rowId: number; onClose: () => void; onReanalyzed: () => void;
}) {
  const { data, error, mutate, isLoading } = useSWR<UrlContentAnalysisBundle>(
    `/url-intel/content/${rowId}`,
    () => getUrlContentAnalysis(rowId),
    { refreshInterval: 10_000 },
  );
  const [busy, setBusy] = useState(false);

  const triggerReanalyze = async () => {
    if (!data?.reputation?.url) return;
    setBusy(true);
    try {
      await requestUrlContentAnalysis(data.reputation.url);
      await mutate(); onReanalyzed();
    } finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-start justify-center p-4 overflow-y-auto"
         onClick={onClose}>
      <div className="bg-bg-surface border border-border rounded-lg w-full max-w-4xl my-8"
           onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <FlaskConical className="w-4 h-4 text-accent" /> Web content analysis
          </h3>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary">
            <X className="w-4 h-4" />
          </button>
        </div>

        {isLoading && <div className="p-8 flex justify-center"><LoadingSpinner /></div>}
        {error && <div className="p-6 text-red-400 text-sm">Failed to load: {String(error)}</div>}

        {data && (
          <div className="p-4 space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded border border-border p-3">
                <div className="text-2xs text-text-muted uppercase">URL</div>
                <div className="font-mono break-all mt-1">{data.reputation.url}</div>
                {data.latest?.final_url && data.latest.final_url !== data.reputation.url && (
                  <div className="mt-2 text-text-muted">
                    → {data.latest.final_url}
                    <ExternalLink className="inline w-3 h-3 ml-1" />
                  </div>
                )}
              </div>
              <div className="rounded border border-border p-3 space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-2xs text-text-muted uppercase w-16">ML verdict</span>
                  <Pill tone={data.reputation.prediction}>{data.reputation.prediction}</Pill>
                  <span className="font-mono text-text-muted">conf={data.reputation.confidence.toFixed(3)}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-2xs text-text-muted uppercase w-16">Content</span>
                  {data.latest
                    ? <ContentBadge verdict={data.latest.content_verdict} score={data.latest.content_risk_score} />
                    : <span className="text-text-muted italic">not analyzed yet</span>}
                </div>
                {data.reputation.override_reason && (
                  <div className="flex items-start gap-2">
                    <span className="text-2xs text-text-muted uppercase w-16">Override</span>
                    <span className="text-blue-400 font-mono">
                      {data.reputation.original_prediction} → {data.reputation.prediction}
                    </span>
                    <span className="text-text-muted text-2xs">{data.reputation.override_reason}</span>
                  </div>
                )}
              </div>
            </div>

            {data.latest?.indicators && <IndicatorPanel ind={data.latest.indicators} />}

            <div className="flex items-center gap-2 pt-2 border-t border-border">
              <button onClick={triggerReanalyze} disabled={busy}
                      className="btn btn-ghost border border-border text-xs">
                <RefreshCw className={clsx("w-3 h-3 mr-1.5", busy && "animate-spin")} />
                {busy ? "Queuing…" : "Re-analyze"}
              </button>
              <span className="text-text-muted text-2xs">
                Worker picks the URL back up on its next poll cycle.
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
