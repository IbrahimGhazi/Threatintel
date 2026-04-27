// @ts-nocheck
"use client";

import { Suspense, useState } from "react";
import useSWR from "swr";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Search, ChevronLeft, ChevronRight,
  Plus, ExternalLink, AlertTriangle, Flag, Trash2,
} from "lucide-react";
import { getIndicators, markFalsePositive, deleteIndicator, type Indicator } from "@/lib/api";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { formatDistanceToNow, parseISO } from "date-fns";
import clsx from "clsx";

const PAGE_SIZE = 50;

const TYPE_COLORS: Record<string, string> = {
  ip:     "text-accent-blue",
  domain: "text-accent",
  url:    "text-severity-medium",
  sha256: "text-severity-high",
  md5:    "text-severity-high",
  sha1:   "text-severity-high",
  email:  "text-status-success",
};

function ConfidenceBar({ value }: { value: number }) {
  const color =
    value >= 80 ? "bg-severity-critical" :
    value >= 60 ? "bg-severity-high" :
    value >= 40 ? "bg-severity-medium" :
    "bg-severity-low";
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-bg-elevated rounded-full overflow-hidden">
        <div className={clsx("h-full rounded-full", color)} style={{ width: `${value}%` }} />
      </div>
      <span className="text-2xs text-text-muted font-mono">{value}%</span>
    </div>
  );
}

function IndicatorsContent() {
  const searchParams = useSearchParams();

  const [q, setQ]             = useState(searchParams.get("q") ?? "");
  const [typeFilter, setType] = useState(searchParams.get("type") ?? "");
  const [sevFilter, setSev]   = useState("");
  const [page, setPage]       = useState(0);

  // Per-row action state: id → "fp" | "delete" | "confirm-delete"
  const [rowAction, setRowAction] = useState<Record<string, string>>({});

  const swrKey = ["indicators", q, typeFilter, sevFilter, page];
  const { data, isLoading, error, mutate } = useSWR(
    swrKey,
    () => getIndicators({
      q: q || undefined,
      type: typeFilter || undefined,
      severity: sevFilter || undefined,
      offset: page * PAGE_SIZE,
      limit: PAGE_SIZE,
    }),
    { refreshInterval: 30000 }
  );

  const handleFP = async (id: string) => {
    setRowAction(r => ({ ...r, [id]: "fp" }));
    try {
      await markFalsePositive(id);
      mutate(
        prev => prev
          ? { ...prev, items: prev.items.filter((i: Indicator) => i.id !== id), total: prev.total - 1 }
          : prev,
        false
      );
    } finally {
      setRowAction(r => { const n = { ...r }; delete n[id]; return n; });
    }
  };

  const handleDelete = async (id: string) => {
    setRowAction(r => ({ ...r, [id]: "delete" }));
    try {
      await deleteIndicator(id);
      mutate(
        prev => prev
          ? { ...prev, items: prev.items.filter((i: Indicator) => i.id !== id), total: prev.total - 1 }
          : prev,
        false
      );
    } finally {
      setRowAction(r => { const n = { ...r }; delete n[id]; return n; });
    }
  };

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text-primary">Indicators</h1>
          <p className="text-sm text-text-muted mt-0.5">
            {data ? `${data.total.toLocaleString()} total indicators` : "Threat intelligence database"}
          </p>
        </div>
        <Link href="/indicators/submit" className="btn-primary text-xs">
          <Plus className="w-3.5 h-3.5" />
          Add Indicator
        </Link>
      </div>

      {/* Filters */}
      <div className="card p-4 flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted pointer-events-none" />
          <input
            value={q}
            onChange={(e) => { setQ(e.target.value); setPage(0); }}
            placeholder="Search by value, domain, IP…"
            className="ti-input w-full pl-9 text-xs"
          />
        </div>

        <select
          value={typeFilter}
          onChange={(e) => { setType(e.target.value); setPage(0); }}
          className="ti-input text-xs"
        >
          <option value="">All Types</option>
          {["ip", "domain", "url", "sha256", "md5", "sha1", "email"].map((t) => (
            <option key={t} value={t}>{t.toUpperCase()}</option>
          ))}
        </select>

        <select
          value={sevFilter}
          onChange={(e) => { setSev(e.target.value); setPage(0); }}
          className="ti-input text-xs"
        >
          <option value="">All Severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-16">
            <LoadingSpinner />
          </div>
        ) : error ? (
          <div className="flex items-center justify-center py-16 gap-2 text-text-muted text-sm">
            <AlertTriangle className="w-4 h-4 text-severity-high" />
            Failed to load indicators
          </div>
        ) : (
          <table className="ti-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Sources</th>
                <th>Last Seen</th>
                <th>Tags</th>
                <th className="w-40 text-right pr-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {(data?.items ?? []).map((ind: Indicator) => {
                const acting = rowAction[ind.id];
                return (
                <tr key={ind.id}>
                  <td>
                    <span className={clsx(
                      "badge bg-bg-elevated border-border font-mono",
                      TYPE_COLORS[ind.type] ?? "text-text-secondary"
                    )}>
                      {ind.type.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    <span className="mono-value text-xs line-clamp-1 max-w-xs" title={ind.value}>
                      {ind.value.length > 60 ? ind.value.slice(0, 60) + "…" : ind.value}
                    </span>
                  </td>
                  <td>
                    <SeverityBadge severity={ind.severity} />
                  </td>
                  <td>
                    <ConfidenceBar value={ind.confidence} />
                  </td>
                  <td>
                    <span className="text-xs text-text-muted">
                      {ind.sources?.length ?? 0}
                    </span>
                  </td>
                  <td>
                    <span className="text-xs text-text-muted">
                      {ind.last_seen
                        ? formatDistanceToNow(parseISO(ind.last_seen), { addSuffix: true })
                        : "—"}
                    </span>
                  </td>
                  <td>
                    <div className="flex flex-wrap gap-1 max-w-xs">
                      {(ind.tags ?? []).slice(0, 3).map((tag) => (
                        <span key={tag} className="badge bg-bg-elevated border-border text-text-muted">
                          {tag}
                        </span>
                      ))}
                      {(ind.tags?.length ?? 0) > 3 && (
                        <span className="badge bg-bg-elevated border-border text-text-muted">
                          +{ind.tags.length - 3}
                        </span>
                      )}
                    </div>
                  </td>
                  <td>
                    <div className="flex items-center justify-end gap-1 pr-1">
                      {/* View detail */}
                      <Link
                        href={`/indicators/${ind.id}`}
                        className="p-1 text-text-muted hover:text-accent transition-colors"
                        title="View detail"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </Link>

                      {/* False-positive button — hidden if already marked */}
                      {!ind.false_positive && (
                        <button
                          onClick={() => handleFP(ind.id)}
                          disabled={!!acting}
                          title="Mark as false positive"
                          className="p-1 text-text-muted hover:text-severity-medium transition-colors disabled:opacity-40"
                        >
                          {acting === "fp"
                            ? <span className="text-2xs text-severity-medium">…</span>
                            : <Flag className="w-3.5 h-3.5" />
                          }
                        </button>
                      )}

                      {/* Delete — two-step confirm */}
                      {acting === "confirm-delete" ? (
                        <span className="flex items-center gap-1">
                          <button
                            onClick={() => handleDelete(ind.id)}
                            className="text-2xs px-1.5 py-0.5 rounded bg-severity-critical/20 text-severity-critical border border-severity-critical/40 hover:bg-severity-critical/30"
                          >
                            Confirm
                          </button>
                          <button
                            onClick={() => setRowAction(r => { const n = { ...r }; delete n[ind.id]; return n; })}
                            className="text-2xs text-text-muted hover:text-text-primary px-1"
                          >
                            ✕
                          </button>
                        </span>
                      ) : (
                        <button
                          onClick={() => setRowAction(r => ({ ...r, [ind.id]: "confirm-delete" }))}
                          disabled={!!acting}
                          title="Delete indicator"
                          className="p-1 text-text-muted hover:text-severity-critical transition-colors disabled:opacity-40"
                        >
                          {acting === "delete"
                            ? <span className="text-2xs text-severity-critical">…</span>
                            : <Trash2 className="w-3.5 h-3.5" />
                          }
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
                );
              })}
              {data?.items?.length === 0 && (
                <tr>
                  <td colSpan={8} className="text-center py-12 text-text-muted text-sm">
                    No indicators found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}

        {/* Pagination */}
        {data && data.total > PAGE_SIZE && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-border">
            <p className="text-xs text-text-muted">
              Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, data.total)} of {data.total.toLocaleString()}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                className="btn-ghost p-1 text-xs disabled:opacity-40"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="text-xs text-text-muted">
                {page + 1} / {totalPages}
              </span>
              <button
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="btn-ghost p-1 text-xs disabled:opacity-40"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function IndicatorsPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center py-16">
        <LoadingSpinner />
      </div>
    }>
      <IndicatorsContent />
    </Suspense>
  );
}