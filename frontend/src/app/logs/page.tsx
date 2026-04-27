"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import useSWR from "swr";
import {
  ScrollText, AlertTriangle, CheckCircle, Server,
  Wifi, ChevronDown, ChevronUp, Copy, Check,
  RadioTower, Activity, Terminal,
  Search, Plus, Trash2, Filter, X, Play,
} from "lucide-react";
import {
  getLogs, searchLogs,
  type LogEntry, type FilterCondition, type FilterGroup, type LogSearchQuery,
} from "@/lib/api";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { StatCard } from "@/components/ui/StatCard";
import { formatDistanceToNow, parseISO } from "date-fns";
import clsx from "clsx";

const API_KEY = process.env.NEXT_PUBLIC_API_KEY ?? "";
const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "/api";

// ── Searchable fields ────────────────────────────────────────────────────────

const SEARCH_FIELDS = [
  { value: "source_type",  label: "Source Type" },
  { value: "source_name",  label: "Source Name" },
  { value: "source_ip",    label: "Source IP (device)" },
  { value: "raw_log",      label: "Raw Log" },
  { value: "src_ip",       label: "Src IP (parsed)" },
  { value: "dst_ip",       label: "Dst IP (parsed)" },
  { value: "dst_port",     label: "Dst Port" },
  { value: "protocol",     label: "Protocol" },
  { value: "action",       label: "Action" },
  { value: "url",          label: "URL" },
  { value: "threat_name",  label: "Threat Name" },
  { value: "application",  label: "Application" },
  { value: "log_type",     label: "Log Type" },
  { value: "log_subtype",  label: "Log Subtype" },
  { value: "rule_name",    label: "Rule Name" },
  { value: "src_zone",     label: "Src Zone" },
  { value: "dst_zone",     label: "Dst Zone" },
  { value: "hostname",     label: "Hostname" },
  { value: "program",      label: "Program" },
  { value: "username",     label: "Username" },
  { value: "status",       label: "Status" },
  { value: "is_malicious", label: "Is Malicious" },
];

const OPERATORS = [
  { value: "eq",           label: "EQ",           desc: "Equals" },
  { value: "neq",          label: "NEQ",          desc: "Not Equals" },
  { value: "contains",     label: "CONTAINS",     desc: "Contains" },
  { value: "not_contains", label: "NOT CONTAINS", desc: "Does Not Contain" },
  { value: "cidr",         label: "CIDR",         desc: "IP in Subnet (e.g. 192.168.3.0/24)" },
  { value: "gt",           label: "GT",           desc: "Greater Than" },
  { value: "lt",           label: "LT",           desc: "Less Than" },
  { value: "regex",        label: "REGEX",        desc: "Regex Match" },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      className="btn btn-ghost border border-border text-xs px-2 py-1 flex-shrink-0"
    >
      {copied ? <Check className="w-3 h-3 text-status-success" /> : <Copy className="w-3 h-3" />}
    </button>
  );
}

function CodeBlock({ code }: { code: string }) {
  return (
    <div className="flex gap-2 items-start">
      <pre className="flex-1 bg-bg-elevated border border-border rounded p-3 text-2xs font-mono text-text-secondary overflow-x-auto whitespace-pre-wrap">
        {code}
      </pre>
      <CopyButton text={code} />
    </div>
  );
}

// ── Filter Builder Row ──────────────────────────────────────────────────────

function FilterConditionRow({
  cond,
  onChange,
  onRemove,
}: {
  cond: FilterCondition;
  onChange: (c: FilterCondition) => void;
  onRemove: () => void;
}) {
  return (
    <div className="flex items-center gap-2 flex-wrap">
      <select
        value={cond.field}
        onChange={e => onChange({ ...cond, field: e.target.value })}
        className="ti-input text-xs w-40"
      >
        {SEARCH_FIELDS.map(f => (
          <option key={f.value} value={f.value}>{f.label}</option>
        ))}
      </select>

      <select
        value={cond.operator}
        onChange={e => onChange({ ...cond, operator: e.target.value })}
        className="ti-input text-xs w-36"
      >
        {OPERATORS.map(op => (
          <option key={op.value} value={op.value}>{op.label} — {op.desc}</option>
        ))}
      </select>

      <input
        type="text"
        placeholder={cond.operator === "cidr" ? "192.168.3.0/24" : "Value…"}
        value={cond.value}
        onChange={e => onChange({ ...cond, value: e.target.value })}
        className="ti-input text-xs flex-1 min-w-[160px]"
      />

      <button onClick={onRemove} className="btn-ghost p-1 text-text-muted hover:text-severity-high">
        <Trash2 className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}

// ── Filter Group ────────────────────────────────────────────────────────────

function FilterGroupBuilder({
  group,
  groupIdx,
  onChange,
  onRemove,
}: {
  group: FilterGroup;
  groupIdx: number;
  onChange: (g: FilterGroup) => void;
  onRemove: () => void;
}) {
  const addCondition = () => {
    onChange({
      ...group,
      conditions: [...group.conditions, { field: "src_ip", operator: "eq", value: "" }],
    });
  };

  const updateCondition = (i: number, c: FilterCondition) => {
    const updated = [...group.conditions];
    updated[i] = c;
    onChange({ ...group, conditions: updated });
  };

  const removeCondition = (i: number) => {
    const updated = group.conditions.filter((_, idx) => idx !== i);
    if (updated.length === 0) {
      onRemove();
    } else {
      onChange({ ...group, conditions: updated });
    }
  };

  return (
    <div className="card p-3 space-y-2 relative">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <span className="text-2xs text-text-muted font-semibold uppercase tracking-wide">
            Group {groupIdx + 1}
          </span>
          <select
            value={group.logic}
            onChange={e => onChange({ ...group, logic: e.target.value as "AND" | "OR" })}
            className="ti-input text-xs w-20 py-0.5"
          >
            <option value="AND">AND</option>
            <option value="OR">OR</option>
          </select>
        </div>
        <button onClick={onRemove} className="btn-ghost p-1 text-text-muted hover:text-severity-high text-2xs">
          <X className="w-3 h-3" />
        </button>
      </div>

      {group.conditions.map((cond, i) => (
        <div key={i}>
          {i > 0 && (
            <div className="flex items-center gap-2 py-0.5 pl-4">
              <span className="text-2xs font-semibold text-accent">{group.logic}</span>
              <div className="flex-1 border-t border-border/50" />
            </div>
          )}
          <FilterConditionRow
            cond={cond}
            onChange={c => updateCondition(i, c)}
            onRemove={() => removeCondition(i)}
          />
        </div>
      ))}

      <button onClick={addCondition} className="btn btn-ghost text-2xs h-auto py-1 px-2 w-full border border-dashed border-border">
        <Plus className="w-3 h-3" /> Add Condition
      </button>
    </div>
  );
}


// ── Stats fetcher ─────────────────────────────────────────────────────────────

async function fetchStats() {
  const res = await fetch(`${API_BASE}/logs/stats`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error("Failed to fetch log stats");
  return res.json();
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function LogsPage() {
  const [tab, setTab]               = useState<"feed" | "monitor" | "setup">("feed");
  const [maliciousOnly, setMaliciousOnly] = useState(false);
  const [sourceType, setSourceType] = useState("");
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [liveItems, setLiveItems]   = useState<any[]>([]);
  const esRef                       = useRef<EventSource | null>(null);

  // Monitor search state
  const [filterGroups, setFilterGroups] = useState<FilterGroup[]>([
    { logic: "AND", conditions: [{ field: "src_ip", operator: "cidr", value: "192.168.3.0/24" }] },
  ]);
  const [searchResults, setSearchResults] = useState<LogEntry[] | null>(null);
  const [searchTotal, setSearchTotal]     = useState(0);
  const [searching, setSearching]         = useState(false);
  const [searchOffset, setSearchOffset]   = useState(0);
  const SEARCH_LIMIT = 100;

  // Main log table (REST poll)
  const { data: logs, isLoading } = useSWR(
    tab === "feed" ? ["logs", maliciousOnly, sourceType] : null,
    () => getLogs({ malicious_only: maliciousOnly, source_type: sourceType || undefined, limit: 100 }),
    { refreshInterval: 5000 }
  );

  // Stats
  const { data: stats } = useSWR("log-stats", fetchStats, { refreshInterval: 15000 });

  // SSE live feed
  useEffect(() => {
    const es = new EventSource(
      `${API_BASE}/logs/stream?api_key=${API_KEY}`,
    );
    esRef.current = es;
    es.onmessage = (e) => {
      try {
        const item = JSON.parse(e.data);
        setLiveItems(prev => [item, ...prev].slice(0, 50));
      } catch {}
    };
    return () => { es.close(); };
  }, []);

  const filtered = (logs ?? []).filter(l => !sourceType || l.source_type === sourceType);

  // Monitor search handler
  const runSearch = useCallback(async (offset = 0) => {
    // Remove empty conditions
    const cleanGroups = filterGroups
      .map(g => ({
        ...g,
        conditions: g.conditions.filter(c => c.value.trim() !== ""),
      }))
      .filter(g => g.conditions.length > 0);

    if (cleanGroups.length === 0) return;

    setSearching(true);
    setSearchOffset(offset);
    try {
      const result = await searchLogs({
        filters:  cleanGroups,
        order_by: "processed_at",
        order:    "desc",
        offset,
        limit:    SEARCH_LIMIT,
      });
      setSearchResults(result.items);
      setSearchTotal(result.total);
    } catch (err: any) {
      setSearchResults([]);
      setSearchTotal(0);
    } finally {
      setSearching(false);
    }
  }, [filterGroups]);

  const addFilterGroup = () => {
    setFilterGroups(prev => [
      ...prev,
      { logic: "AND", conditions: [{ field: "src_ip", operator: "eq", value: "" }] },
    ]);
  };

  const host = typeof window !== "undefined" ? window.location.hostname : "your-server";

  // ── Log table renderer (shared between feed and monitor) ──────────────────
  const renderLogTable = (entries: LogEntry[], loading: boolean) => (
    <div className="card overflow-hidden">
      {loading ? (
        <div className="flex items-center justify-center py-16"><LoadingSpinner /></div>
      ) : (
        <table className="ti-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Source</th>
              <th>Src IP</th>
              <th>Dst IP</th>
              <th>URL / App</th>
              <th>Matched IOCs</th>
              <th>Timestamp</th>
              <th>Raw Log</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry: LogEntry) => {
              const isExpanded = expandedRow === entry.id;
              const matched    = entry.matched_iocs ?? [];
              const parsed     = entry.parsed ?? {};

              return [
                <tr
                  key={entry.id}
                  className={clsx(
                    "cursor-pointer",
                    entry.is_malicious && "bg-severity-critical/5 hover:bg-severity-critical/10",
                    !entry.is_malicious && "hover:bg-bg-elevated/50"
                  )}
                  onClick={() => setExpandedRow(isExpanded ? null : entry.id)}
                >
                  <td>
                    {entry.is_malicious ? (
                      <span className="badge-critical">
                        <AlertTriangle className="w-3 h-3" /> Match
                      </span>
                    ) : (
                      <span className="badge bg-bg-elevated border-border text-text-muted">
                        <CheckCircle className="w-3 h-3" /> Clean
                      </span>
                    )}
                  </td>
                  <td>
                    <div>
                      <p className="text-xs font-medium text-text-primary uppercase">
                        {entry.source_type}
                      </p>
                      <p className="text-2xs text-text-muted font-mono">
                        {entry.source_name || entry.source_ip || "—"}
                      </p>
                    </div>
                  </td>
                  <td>
                    <span className="text-2xs font-mono text-text-secondary">
                      {(parsed as any)?.src_ip || "—"}
                    </span>
                  </td>
                  <td>
                    <span className="text-2xs font-mono text-text-secondary">
                      {(parsed as any)?.dst_ip || "—"}
                    </span>
                  </td>
                  <td>
                    {(parsed as any)?.url ? (
                      <div>
                        <p className="text-2xs font-mono text-accent-primary truncate max-w-[200px]" title={(parsed as any).url}>
                          {(parsed as any).url}
                        </p>
                        {(parsed as any)?.threat_name && (
                          <p className="text-2xs text-text-muted truncate max-w-[200px]">{(parsed as any).threat_name}</p>
                        )}
                      </div>
                    ) : (parsed as any)?.application ? (
                      <span className="text-2xs text-text-muted">{(parsed as any).application}</span>
                    ) : (
                      <span className="text-2xs text-text-muted">—</span>
                    )}
                  </td>
                  <td>
                    <span className={clsx(
                      "text-xs font-mono",
                      matched.length > 0 ? "text-severity-critical font-semibold" : "text-text-muted"
                    )}>
                      {matched.length > 0 ? matched.length : "—"}
                    </span>
                  </td>
                  <td>
                    <span className="text-xs text-text-muted">
                      {entry.processed_at
                        ? formatDistanceToNow(parseISO(entry.processed_at), { addSuffix: true })
                        : "—"}
                    </span>
                  </td>
                  <td>
                    <div className="flex items-center gap-1">
                      <span className="text-2xs text-text-muted font-mono max-w-[200px] truncate">
                        {entry.raw_log?.slice(0, 80) ?? "—"}
                      </span>
                      {isExpanded ? <ChevronUp className="w-3 h-3 text-text-muted flex-shrink-0" /> : <ChevronDown className="w-3 h-3 text-text-muted flex-shrink-0" />}
                    </div>
                  </td>
                </tr>,

                isExpanded && (
                  <tr key={`${entry.id}-detail`}>
                    <td colSpan={7} className="bg-bg-elevated/50 px-5 py-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                        <div>
                          <p className="text-text-muted font-semibold uppercase tracking-wide mb-2 text-2xs">Raw Log</p>
                          <pre className="bg-bg-base border border-border rounded p-2 text-2xs font-mono text-text-secondary overflow-x-auto whitespace-pre-wrap break-all max-h-32">
                            {entry.raw_log ?? "—"}
                          </pre>
                          {/* Parsed fields */}
                          {parsed && Object.keys(parsed).length > 0 && (
                            <div className="mt-3">
                              <p className="text-text-muted font-semibold uppercase tracking-wide mb-1 text-2xs">Parsed Fields</p>
                              <div className="grid grid-cols-2 gap-1">
                                {Object.entries(parsed).filter(([, v]) => v != null && v !== "").map(([k, v]) => (
                                  <div key={k} className="flex gap-1 text-2xs">
                                    <span className="text-text-muted font-mono">{k}:</span>
                                    <span className="text-text-secondary font-mono truncate">{String(v)}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                        <div>
                          <p className="text-text-muted font-semibold uppercase tracking-wide mb-2 text-2xs">
                            TI Matches ({matched.length})
                          </p>
                          {matched.length > 0 ? (
                            <div className="space-y-1">
                              {matched.map((m: any, i: number) => (
                                <div key={i} className="flex items-center gap-2 p-1.5 rounded bg-severity-critical/10 border border-severity-critical/20">
                                  <span className="text-2xs font-mono text-severity-critical font-semibold uppercase w-12 flex-shrink-0">{m.type}</span>
                                  <span className="text-2xs font-mono text-text-secondary truncate flex-1">{m.value}</span>
                                  <span className={clsx("badge text-2xs flex-shrink-0",
                                    m.severity === "critical" ? "badge-critical" :
                                    m.severity === "high" ? "badge-high" : "badge-medium"
                                  )}>{m.severity}</span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-text-muted">No TI matches in this log</p>
                          )}
                          {entry.extracted_iocs && Object.keys(entry.extracted_iocs).length > 0 && (
                            <div className="mt-3">
                              <p className="text-text-muted font-semibold uppercase tracking-wide mb-1 text-2xs">Extracted IOCs</p>
                              {Object.entries(entry.extracted_iocs).map(([type, values]) =>
                                Array.isArray(values) && values.length > 0 ? (
                                  <div key={type} className="flex gap-1 flex-wrap mb-1">
                                    <span className="text-2xs text-text-muted uppercase font-mono">{type}:</span>
                                    {(values as string[]).slice(0, 5).map(v => (
                                      <span key={v} className="badge bg-bg-elevated border-border text-text-muted text-2xs font-mono">{v}</span>
                                    ))}
                                  </div>
                                ) : null
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    </td>
                  </tr>
                ),
              ].filter(Boolean);
            })}
            {entries.length === 0 && (
              <tr>
                <td colSpan={7} className="text-center py-12 text-text-muted text-sm">
                  No log entries found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  );

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text-primary">Log Analysis</h1>
          <p className="text-sm text-text-muted mt-0.5">
            Central log ingestion — syslog + HTTP ingest with automatic IOC matching
          </p>
        </div>
        {liveItems.length > 0 && (
          <div className="flex items-center gap-2 text-xs text-text-muted">
            <div className="status-dot bg-status-success animate-pulse-slow" />
            {liveItems.length} live events
          </div>
        )}
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Logs Today" value={stats?.total_today ?? "—"} icon={ScrollText} subtitle="Total received" accent="default" />
        <StatCard label="TI Matches" value={stats?.matched_today ?? "—"} icon={AlertTriangle}
          subtitle={`${stats?.match_rate ?? 0}% match rate`}
          accent={(stats?.matched_today ?? 0) > 0 ? "critical" : "success"} />
        <StatCard label="Devices" value={stats?.device_count ?? "—"} icon={Server} subtitle="Reporting sources" accent="default" />
        <StatCard label="Total Logs" value={stats?.total_all ?? "—"} icon={Activity} subtitle="All time" accent="default" />
      </div>

      {/* Live event ticker */}
      {liveItems.length > 0 && (
        <div className="card p-3 overflow-hidden">
          <div className="flex items-center gap-2 mb-2">
            <Wifi className="w-3.5 h-3.5 text-accent" />
            <span className="text-xs font-semibold text-text-primary">Live Feed</span>
          </div>
          <div className="space-y-0.5 max-h-28 overflow-y-auto">
            {liveItems.map((item, i) => (
              <div key={i} className={clsx(
                "flex items-center gap-3 text-2xs font-mono px-2 py-1 rounded",
                item.is_malicious ? "bg-severity-critical/10 text-severity-critical" : "text-text-muted"
              )}>
                <span className={clsx("w-2 h-2 rounded-full flex-shrink-0", item.is_malicious ? "bg-severity-critical" : "bg-text-muted/30")} />
                <span className="w-24 truncate flex-shrink-0">{item.source_name || item.source_ip || item.source_type}</span>
                {item.is_malicious && (
                  <span className="text-severity-critical font-semibold flex-shrink-0">
                    {item.matches} match{item.matches !== 1 ? "es" : ""}
                  </span>
                )}
                <span className="text-text-muted ml-auto flex-shrink-0">
                  {item.at ? formatDistanceToNow(new Date(item.at), { addSuffix: true }) : ""}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-border">
        {(["feed", "monitor", "setup"] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={clsx(
              "px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors flex items-center gap-1.5",
              tab === t ? "border-accent text-accent" : "border-transparent text-text-muted hover:text-text-secondary"
            )}
          >
            {t === "feed" && <><ScrollText className="w-3.5 h-3.5" /> Log Feed</>}
            {t === "monitor" && <><Search className="w-3.5 h-3.5" /> Monitor</>}
            {t === "setup" && <><Server className="w-3.5 h-3.5" /> Device Setup</>}
          </button>
        ))}
      </div>

      {/* ── Tab: Feed ──────────────────────────────────────────────────────── */}
      {tab === "feed" && (
        <>
          <div className="flex flex-wrap gap-3 items-center">
            <button
              onClick={() => setMaliciousOnly(!maliciousOnly)}
              className={clsx("btn text-xs", maliciousOnly ? "btn-primary" : "btn-ghost border border-border")}
            >
              <AlertTriangle className="w-3.5 h-3.5" /> Matched Only
            </button>
            <select
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value)}
              className="ti-input text-xs"
            >
              <option value="">All Sources</option>
              {["firewall", "proxy", "edr", "email", "web_gw", "syslog"].map((s) => (
                <option key={s} value={s}>{s.replace("_", " ").toUpperCase()}</option>
              ))}
            </select>
            <span className="text-xs text-text-muted ml-auto">{filtered.length} entries</span>
          </div>
          {renderLogTable(filtered, isLoading)}
        </>
      )}

      {/* ── Tab: Monitor (PaloAlto-style search) ──────────────────────────── */}
      {tab === "monitor" && (
        <div className="space-y-4">
          {/* Info banner */}
          <div className="card p-3 flex items-center gap-2 text-xs text-text-secondary border-l-2 border-l-accent/50">
            <Filter className="w-3.5 h-3.5 text-accent flex-shrink-0" />
            <span>
              Build queries using AND/OR groups with operators: <span className="font-mono text-accent">EQ</span>,{" "}
              <span className="font-mono text-accent">NEQ</span>,{" "}
              <span className="font-mono text-accent">CIDR</span> (192.168.3.0/24),{" "}
              <span className="font-mono text-accent">CONTAINS</span>,{" "}
              <span className="font-mono text-accent">REGEX</span>,{" "}
              <span className="font-mono text-accent">GT</span>,{" "}
              <span className="font-mono text-accent">LT</span>
            </span>
          </div>

          {/* Filter groups */}
          <div className="space-y-3">
            {filterGroups.map((group, gi) => (
              <div key={gi}>
                {gi > 0 && (
                  <div className="flex items-center gap-2 py-1.5 px-4">
                    <div className="flex-1 border-t border-border/50" />
                    <span className="text-2xs font-bold text-severity-medium uppercase">AND</span>
                    <div className="flex-1 border-t border-border/50" />
                  </div>
                )}
                <FilterGroupBuilder
                  group={group}
                  groupIdx={gi}
                  onChange={g => {
                    const updated = [...filterGroups];
                    updated[gi] = g;
                    setFilterGroups(updated);
                  }}
                  onRemove={() => setFilterGroups(filterGroups.filter((_, i) => i !== gi))}
                />
              </div>
            ))}
          </div>

          {/* Add group + Search */}
          <div className="flex items-center gap-3">
            <button onClick={addFilterGroup} className="btn btn-ghost text-xs h-auto py-1.5 px-3 border border-dashed border-border">
              <Plus className="w-3.5 h-3.5" /> Add Filter Group
            </button>
            <div className="flex-1" />
            <button
              onClick={() => runSearch(0)}
              disabled={searching}
              className="btn btn-primary text-xs h-auto py-2 px-5"
            >
              {searching ? <LoadingSpinner size="sm" /> : <Play className="w-3.5 h-3.5" />}
              {searching ? "Searching…" : "Search"}
            </button>
          </div>

          {/* Search results */}
          {searchResults !== null && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-xs text-text-muted">
                  <span className="font-semibold text-text-primary">{searchTotal.toLocaleString()}</span> results found
                  {searchTotal > SEARCH_LIMIT && (
                    <span className="ml-1">(showing {searchOffset + 1}–{Math.min(searchOffset + SEARCH_LIMIT, searchTotal)})</span>
                  )}
                </p>
                {searchTotal > SEARCH_LIMIT && (
                  <div className="flex gap-1">
                    <button
                      disabled={searchOffset === 0}
                      onClick={() => runSearch(Math.max(0, searchOffset - SEARCH_LIMIT))}
                      className="btn btn-ghost text-2xs px-2 py-1 h-auto"
                    >Prev</button>
                    <button
                      disabled={searchOffset + SEARCH_LIMIT >= searchTotal}
                      onClick={() => runSearch(searchOffset + SEARCH_LIMIT)}
                      className="btn btn-ghost text-2xs px-2 py-1 h-auto"
                    >Next</button>
                  </div>
                )}
              </div>
              {renderLogTable(searchResults, searching)}
            </div>
          )}
        </div>
      )}

      {/* ── Tab: Device Setup ──────────────────────────────────────────────── */}
      {tab === "setup" && (
        <div className="space-y-6">
          <div className="card p-5">
            <h2 className="text-sm font-semibold text-text-primary mb-1 flex items-center gap-2">
              <Server className="w-4 h-4 text-accent" /> Ingest Endpoints
            </h2>
            <p className="text-xs text-text-muted mb-4">
              Point your security devices at one of the following endpoints.
              All logs are automatically parsed for IOCs and matched against the TI database.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                { proto: "Syslog UDP", port: "514", icon: RadioTower, note: "Standard syslog — firewalls, routers, switches. RFC 3164, RFC 5424, CEF." },
                { proto: "Syslog TCP", port: "514", icon: RadioTower, note: "Reliable syslog delivery. Same format support as UDP." },
                { proto: "HTTP POST", port: "9514/ingest", icon: Terminal, note: "JSON or plain-text. Suitable for custom scripts and modern devices." },
              ].map(({ proto, port, icon: Icon, note }) => (
                <div key={proto} className="bg-bg-elevated border border-border rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Icon className="w-4 h-4 text-accent" />
                    <span className="text-sm font-semibold text-text-primary">{proto}</span>
                  </div>
                  <div className="font-mono text-xs text-accent mb-2">{host}:{port}</div>
                  <p className="text-2xs text-text-muted">{note}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="card p-5">
            <h3 className="text-sm font-semibold text-text-primary mb-3">Palo Alto Networks PAN-OS</h3>
            <CodeBlock code={`# Device > Server Profiles > Syslog\n# Name: ti-platform\n# Server: ${host}\n# Port: 514\n# Transport: UDP\n# Format: BSD (RFC 3164)\n\nset shared log-settings syslog ti-platform server ${host} port 514 transport UDP`} />
          </div>

          <div className="card p-5">
            <h3 className="text-sm font-semibold text-text-primary mb-3">Fortinet FortiGate</h3>
            <CodeBlock code={`config log syslogd setting\n    set status enable\n    set server "${host}"\n    set port 514\n    set mode udp\n    set facility local7\n    set format cef\nend`} />
          </div>

          <div className="card p-5">
            <h3 className="text-sm font-semibold text-text-primary mb-3">pfSense / OPNsense</h3>
            <CodeBlock code={`# Status > System Logs > Settings\n# Enable Remote Logging:  ✓\n# Remote log servers:     ${host}\n# Remote Syslog Contents: Everything\n# (UDP 514 by default)`} />
          </div>

          <div className="card p-5">
            <h3 className="text-sm font-semibold text-text-primary mb-3">HTTP API (curl example)</h3>
            <CodeBlock code={`# Single log line (plain text)\ncurl -X POST http://${host}:9514/ingest \\\n  -H "Content-Type: text/plain" \\\n  -d "DENY TCP 192.0.2.1:4444 -> 10.0.0.5:443 policy=block"\n\n# Structured JSON\ncurl -X POST http://${host}:9514/ingest \\\n  -H "Content-Type: application/json" \\\n  -d '{"source_type":"firewall","source_name":"fw01","raw_log":"DENY TCP ..."}'\n\n# Via TI Platform API (with authentication)\ncurl -X POST http://${host}/api/logs \\\n  -H "X-API-Key: ${API_KEY}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"source_type":"firewall","source_name":"fw01","raw_log":"DENY TCP ..."}'`} />
          </div>
        </div>
      )}
    </div>
  );
}
