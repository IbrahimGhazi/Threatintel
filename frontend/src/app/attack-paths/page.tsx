"use client";

import { useState } from "react";
import useSWR from "swr";
import {
  Route,
  Upload,
  Play,
  RefreshCw,
  ShieldAlert,
  Network,
  ArrowRight,
  Check,
  X,
  List as ListIcon,
} from "lucide-react";
import { GraphView } from "@/components/attack-paths/GraphView";
import { AssetsPanel } from "@/components/attack-paths/AssetsPanel";
import { formatDistanceToNow, parseISO } from "date-fns";
import clsx from "clsx";

import {
  ackAttackPathFinding,
  getAttackPathFinding,
  listAttackPathFindings,
  listAttackPathRuns,
  suppressAttackPathFinding,
  triggerAttackPathRun,
  uploadAttackPathConfig,
  type AttackPathFindingDetail,
  type AttackPathFindingKind,
  type AttackPathFindingStatus,
  type AttackPathFindingSummary,
  type AttackPathRunSummary,
  type Severity,
} from "@/lib/api";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";

const KIND_LABELS: Record<AttackPathFindingKind, string> = {
  path: "Attack Path",
  fanout: "Fan-Out",
};

const STATUS_LABELS: Record<AttackPathFindingStatus, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  suppressed: "Suppressed",
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

// ── Page ─────────────────────────────────────────────────────────────────────

type ViewMode = "list" | "graph" | "assets";

export default function AttackPathsPage() {
  const [view, setView] = useState<ViewMode>("list");
  const [kind, setKind] = useState<AttackPathFindingKind | "">("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [statusFilter, setStatusFilter] = useState<AttackPathFindingStatus>("open");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [graphAssetIp, setGraphAssetIp] = useState<string | null>(null);

  const findingsKey = ["attack-path-findings", kind, severity, statusFilter];
  const { data: findings, isLoading, mutate: refetchFindings } =
    useSWR(findingsKey, () =>
      listAttackPathFindings({
        kind:     kind || undefined,
        severity: severity || undefined,
        status:   statusFilter,
        limit:    200,
      }),
    );

  const { data: runs, mutate: refetchRuns } = useSWR(
    "attack-path-runs", () => listAttackPathRuns(10),
    { refreshInterval: 5000 },
  );

  const sorted = (findings ?? []).slice().sort(
    (a, b) =>
      (SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]) ||
      (b.score - a.score),
  );

  return (
    <div className="p-6 space-y-5">
      <header className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-accent/15 border border-accent/30 flex items-center justify-center">
            <Route className="w-5 h-5 text-accent" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-text-primary">Attack Paths</h1>
            <p className="text-xs text-text-muted">
              Config-driven Internet-to-asset reachability and fan-out detection.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <ViewToggle current={view} onChange={setView} />
          <button
            onClick={() => { void refetchFindings(); void refetchRuns(); }}
            className="text-xs px-3 py-2 rounded border border-border text-text-muted hover:text-text-primary inline-flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </header>

      <UploadAndRunPanel
        onRunStarted={() => { void refetchRuns(); void refetchFindings(); }}
      />

      <RunsRail runs={runs ?? []} />

      {view === "list" && (
        <>
          <FilterBar
            kind={kind} setKind={setKind}
            severity={severity} setSeverity={setSeverity}
            statusFilter={statusFilter} setStatusFilter={setStatusFilter}
          />

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="lg:col-span-2 card p-0 overflow-hidden">
              <div className="px-4 py-3 border-b border-border flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-accent" />
                <h2 className="text-sm font-semibold text-text-primary">
                  Findings
                  <span className="ml-2 text-xs text-text-muted">
                    ({sorted.length})
                  </span>
                </h2>
              </div>
              {isLoading ? (
                <div className="p-10 flex justify-center"><LoadingSpinner /></div>
              ) : sorted.length === 0 ? (
                <EmptyState />
              ) : (
                <FindingsTable
                  rows={sorted}
                  selectedId={selectedId}
                  onSelect={setSelectedId}
                />
              )}
            </div>

            <div className="lg:col-span-1">
              {selectedId ? (
                <FindingDetailPanel
                  id={selectedId}
                  onClose={() => setSelectedId(null)}
                  onChange={() => { void refetchFindings(); }}
                  onShowInGraph={(ip) => {
                    setGraphAssetIp(ip);
                    setView("graph");
                  }}
                />
              ) : (
                <div className="card p-6 text-xs text-text-muted">
                  Select a finding to view path details, score breakdown, and the
                  specific firewall rules cited.
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {view === "graph" && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <label className="text-2xs uppercase tracking-wider text-text-muted">Focus asset</label>
            <input
              value={graphAssetIp ?? ""}
              onChange={e => setGraphAssetIp(e.target.value || null)}
              placeholder="Leave blank for full subgraph"
              className="bg-bg-base border border-border rounded px-2 py-1 text-xs text-text-primary font-mono w-56"
            />
            {graphAssetIp && (
              <button onClick={() => setGraphAssetIp(null)}
                      className="text-2xs text-text-muted hover:text-text-primary">
                clear
              </button>
            )}
          </div>
          <GraphView
            assetIp={graphAssetIp}
            onSelectNode={info => {
              if (info.ip) setGraphAssetIp(info.ip);
            }}
          />
        </div>
      )}

      {view === "assets" && (
        <AssetsPanel />
      )}
    </div>
  );
}

function ViewToggle({ current, onChange }: {
  current: ViewMode; onChange: (v: ViewMode) => void;
}) {
  const opts: Array<{ id: ViewMode; label: string; icon: React.ElementType }> = [
    { id: "list",   label: "List",   icon: ListIcon },
    { id: "graph",  label: "Graph",  icon: Network },
    { id: "assets", label: "Assets", icon: ShieldAlert },
  ];
  return (
    <div className="inline-flex rounded border border-border overflow-hidden">
      {opts.map(o => {
        const active = current === o.id;
        const Icon = o.icon;
        return (
          <button
            key={o.id}
            onClick={() => onChange(o.id)}
            className={
              "text-xs px-3 py-2 inline-flex items-center gap-1.5 " +
              (active
                ? "bg-accent/10 text-accent"
                : "text-text-muted hover:text-text-primary hover:bg-bg-base")
            }
          >
            <Icon className="w-3.5 h-3.5" />
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

// ── Upload & run ─────────────────────────────────────────────────────────────

function UploadAndRunPanel({ onRunStarted }: { onRunStarted: () => void }) {
  const [vendor, setVendor] = useState<"panos" | "f5" | "fortinet" | "unknown">("panos");
  const [hostname, setHostname] = useState("");
  const [pendingUploads, setPendingUploads] = useState<{ id: string; name: string }[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true); setErr(null);
    try {
      const res = await uploadAttackPathConfig(file, vendor, hostname || undefined);
      setPendingUploads(prev => [...prev, { id: res.id, name: file.name }]);
    } catch (ex) {
      setErr(String(ex));
    } finally {
      setBusy(false);
      e.target.value = "";
    }
  }

  async function startRun() {
    if (pendingUploads.length === 0) return;
    setBusy(true); setErr(null);
    try {
      await triggerAttackPathRun(pendingUploads.map(u => u.id), "ui");
      setPendingUploads([]);
      onRunStarted();
    } catch (ex) {
      setErr(String(ex));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card p-4">
      <div className="flex flex-wrap items-end gap-3">
        <div>
          <label className="block text-2xs uppercase tracking-wider text-text-muted mb-1">Vendor</label>
          <select
            value={vendor}
            onChange={e => setVendor(e.target.value as typeof vendor)}
            className="bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary"
          >
            <option value="panos">Palo Alto (PAN-OS XML)</option>
            <option value="f5">F5 (bigip.conf)</option>
            <option value="fortinet">Fortinet FortiGate</option>
            <option value="unknown">Auto-detect</option>
          </select>
        </div>
        <div className="flex-1 min-w-[200px]">
          <label className="block text-2xs uppercase tracking-wider text-text-muted mb-1">Hostname (optional)</label>
          <input
            value={hostname}
            onChange={e => setHostname(e.target.value)}
            placeholder="e.g. pa-edge-01"
            className="w-full bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary"
          />
        </div>
        <label className="cursor-pointer text-xs px-3 py-2 rounded border border-border text-text-muted hover:text-text-primary inline-flex items-center gap-1.5">
          <Upload className="w-3.5 h-3.5" />
          {busy ? "Working…" : "Add config"}
          <input type="file" className="hidden" onChange={onFile} disabled={busy} />
        </label>
        <button
          onClick={startRun}
          disabled={pendingUploads.length === 0 || busy}
          className="text-xs px-3 py-2 rounded bg-accent/10 border border-accent/30 text-accent hover:bg-accent/20 disabled:opacity-40 inline-flex items-center gap-1.5"
        >
          <Play className="w-3.5 h-3.5" />
          Run analysis ({pendingUploads.length})
        </button>
      </div>

      {pendingUploads.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {pendingUploads.map(u => (
            <span key={u.id}
                  className="text-2xs px-2 py-1 rounded bg-bg-base border border-border text-text-secondary">
              {u.name}
            </span>
          ))}
        </div>
      )}
      {err && (
        <div className="mt-3 text-xs text-severity-high">{err}</div>
      )}
    </div>
  );
}

// ── Runs rail ────────────────────────────────────────────────────────────────

function RunsRail({ runs }: { runs: AttackPathRunSummary[] }) {
  if (!runs.length) return null;
  return (
    <div className="flex gap-2 overflow-x-auto pb-1">
      {runs.map(r => (
        <div key={r.id}
             className="flex-shrink-0 px-3 py-2 rounded border border-border bg-bg-surface min-w-[180px]">
          <div className="flex items-center gap-2">
            <RunStatusDot status={r.status} />
            <span className="text-2xs uppercase tracking-wider text-text-muted">{r.status}</span>
          </div>
          <div className="mt-1 text-xs text-text-primary">
            {r.findings_count} findings · {r.device_count} devices
          </div>
          <div className="text-2xs text-text-muted">
            {formatDistanceToNow(parseISO(r.started_at), { addSuffix: true })}
          </div>
        </div>
      ))}
    </div>
  );
}

function RunStatusDot({ status }: { status: string }) {
  const color =
    status === "completed" ? "bg-status-success" :
    status === "failed"    ? "bg-severity-high" :
    "bg-severity-medium";
  return <span className={clsx("w-2 h-2 rounded-full", color)} />;
}

// ── Filter bar ───────────────────────────────────────────────────────────────

function FilterBar({
  kind, setKind, severity, setSeverity, statusFilter, setStatusFilter,
}: {
  kind: AttackPathFindingKind | "";
  setKind: (v: AttackPathFindingKind | "") => void;
  severity: Severity | "";
  setSeverity: (v: Severity | "") => void;
  statusFilter: AttackPathFindingStatus;
  setStatusFilter: (v: AttackPathFindingStatus) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Pill label="All kinds"     active={kind === ""}        onClick={() => setKind("")} />
      <Pill label="Attack Paths"  active={kind === "path"}    onClick={() => setKind("path")} />
      <Pill label="Fan-Out"       active={kind === "fanout"}  onClick={() => setKind("fanout")} />
      <span className="w-px h-5 bg-border mx-1" />
      <Pill label="All severities" active={severity === ""}     onClick={() => setSeverity("")} />
      {(["critical","high","medium","low"] as Severity[]).map(s => (
        <Pill key={s} label={s} active={severity === s} onClick={() => setSeverity(s)} />
      ))}
      <span className="w-px h-5 bg-border mx-1" />
      {(["open","acknowledged","suppressed"] as AttackPathFindingStatus[]).map(s => (
        <Pill key={s} label={STATUS_LABELS[s]} active={statusFilter === s}
              onClick={() => setStatusFilter(s)} />
      ))}
    </div>
  );
}

function Pill({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        "text-2xs px-2.5 py-1 rounded border capitalize",
        active
          ? "bg-accent/10 text-accent border-accent/30"
          : "bg-bg-base text-text-muted border-border hover:text-text-primary",
      )}
    >{label}</button>
  );
}

// ── Findings table ───────────────────────────────────────────────────────────

function FindingsTable({
  rows, selectedId, onSelect,
}: {
  rows: AttackPathFindingSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <table className="w-full text-xs">
      <thead className="bg-bg-base text-text-muted">
        <tr>
          <th className="text-left px-3 py-2 font-medium">Severity</th>
          <th className="text-left px-3 py-2 font-medium">Score</th>
          <th className="text-left px-3 py-2 font-medium">Kind</th>
          <th className="text-left px-3 py-2 font-medium">Asset / Node</th>
          <th className="text-left px-3 py-2 font-medium">Ingress</th>
          <th className="text-left px-3 py-2 font-medium">Hops</th>
          <th className="text-left px-3 py-2 font-medium">Last seen</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(r => (
          <tr
            key={r.id}
            onClick={() => onSelect(r.id)}
            className={clsx(
              "border-t border-border cursor-pointer hover:bg-bg-base",
              selectedId === r.id && "bg-accent/5",
            )}
          >
            <td className="px-3 py-2"><SeverityBadge severity={r.severity} /></td>
            <td className="px-3 py-2 text-text-primary font-mono">{r.score.toFixed(1)}</td>
            <td className="px-3 py-2 text-text-secondary">{KIND_LABELS[r.kind]}</td>
            <td className="px-3 py-2 text-text-primary font-mono">
              {r.asset_ip ?? "—"}
              {r.asset_criticality && (
                <span className="ml-1.5 text-2xs text-text-muted">
                  ({r.asset_criticality})
                </span>
              )}
            </td>
            <td className="px-3 py-2 text-text-secondary">{r.ingress}</td>
            <td className="px-3 py-2 text-text-secondary">{r.hops ?? "—"}</td>
            <td className="px-3 py-2 text-text-muted">
              {formatDistanceToNow(parseISO(r.last_seen_at), { addSuffix: true })}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── Detail panel ─────────────────────────────────────────────────────────────

function FindingDetailPanel({
  id, onClose, onChange, onShowInGraph,
}: {
  id: string;
  onClose: () => void;
  onChange: () => void;
  onShowInGraph?: (ip: string) => void;
}) {
  const { data, isLoading, mutate } = useSWR(
    ["attack-path-finding", id], () => getAttackPathFinding(id),
  );
  const [busy, setBusy] = useState(false);

  async function ack() {
    setBusy(true);
    try {
      await ackAttackPathFinding(id, "ui");
      await mutate();
      onChange();
    } finally { setBusy(false); }
  }
  async function suppress() {
    setBusy(true);
    try {
      await suppressAttackPathFinding(id, "ui", "marked safe from UI");
      await mutate();
      onChange();
    } finally { setBusy(false); }
  }

  if (isLoading || !data) {
    return <div className="card p-6"><LoadingSpinner /></div>;
  }

  return (
    <div className="card p-4 space-y-4">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="flex items-center gap-2">
            <SeverityBadge severity={data.severity} />
            <span className="text-xs font-mono text-text-primary">
              score {data.score.toFixed(1)}
            </span>
          </div>
          <h3 className="mt-1 text-sm font-semibold text-text-primary">
            {KIND_LABELS[data.kind]}{data.asset_ip ? ` → ${data.asset_ip}` : ""}
          </h3>
          <div className="text-2xs text-text-muted">
            {data.ingress} · {data.hops ?? "?"} hops · status {data.status}
          </div>
        </div>
        <button onClick={onClose} className="text-text-muted hover:text-text-primary">
          <X className="w-4 h-4" />
        </button>
      </div>

      <PathView detail={data} />

      {data.score_breakdown && Object.keys(data.score_breakdown).length > 0 && (
        <div>
          <h4 className="text-2xs uppercase tracking-wider text-text-muted mb-1">Score breakdown</h4>
          <div className="grid grid-cols-2 gap-1.5 text-2xs">
            {Object.entries(data.score_breakdown).map(([k, v]) => (
              <div key={k} className="px-2 py-1 rounded bg-bg-base border border-border flex justify-between">
                <span className="text-text-muted">{k}</span>
                <span className="text-text-primary font-mono">{Number(v).toFixed(2)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {data.rules_cited && data.rules_cited.length > 0 && (
        <div>
          <h4 className="text-2xs uppercase tracking-wider text-text-muted mb-1">Rules cited</h4>
          <ul className="space-y-1 text-2xs">
            {data.rules_cited.map((r, i) => (
              <li key={i} className="px-2 py-1 rounded bg-bg-base border border-border font-mono text-text-secondary">
                {String(r.device ?? "")}{" / "}{String(r.rule ?? "")}
              </li>
            ))}
          </ul>
        </div>
      )}

      {data.asset_ip && onShowInGraph && (
        <button
          onClick={() => onShowInGraph(data.asset_ip!)}
          className="w-full text-xs px-3 py-2 rounded border border-border text-text-muted hover:text-text-primary inline-flex items-center justify-center gap-1.5"
        >
          <Network className="w-3.5 h-3.5" />
          View paths in graph
        </button>
      )}

      {data.status === "open" && (
        <div className="flex gap-2">
          <button
            onClick={ack} disabled={busy}
            className="flex-1 text-xs px-3 py-2 rounded border border-border text-text-primary hover:bg-bg-base inline-flex items-center justify-center gap-1.5 disabled:opacity-40"
          >
            <Check className="w-3.5 h-3.5" /> Acknowledge
          </button>
          <button
            onClick={suppress} disabled={busy}
            className="flex-1 text-xs px-3 py-2 rounded border border-border text-text-muted hover:text-text-primary disabled:opacity-40"
          >
            Suppress
          </button>
        </div>
      )}
    </div>
  );
}

function PathView({ detail }: { detail: AttackPathFindingDetail }) {
  const payload = (detail.path_json || detail.fanout_json) as
    Record<string, unknown> | undefined;
  if (!payload) return null;

  const nodes = (payload.nodes as Array<Record<string, any>> | undefined) ?? [];

  if (detail.kind === "fanout") {
    const node = (payload.node as Record<string, any>) ?? {};
    return (
      <div className="text-xs text-text-secondary">
        <div className="flex items-center gap-2">
          <Network className="w-3.5 h-3.5 text-accent" />
          <span className="font-mono">
            {node.kind} · {node.name ?? node.address ?? node.ip ?? "—"}
          </span>
        </div>
        <p className="mt-1 text-text-muted">
          {String(payload.outbound_targets ?? 0)} outbound targets ·
          {" "}{String(payload.ingress_paths ?? 0)} Internet ingress paths
        </p>
      </div>
    );
  }

  if (!nodes.length) return null;
  return (
    <div className="flex items-center flex-wrap gap-1.5 text-2xs">
      {nodes.map((n, i) => {
        const labels = (n.labels as string[]) ?? [];
        const props  = (n.props  as Record<string, any>) ?? {};
        const kind = labels[0] ?? "?";
        const label =
          props.ip ?? props.address ?? props.name ?? props.cidr ?? props.id ?? kind;
        return (
          <span key={i} className="inline-flex items-center gap-1.5">
            <span className="px-2 py-1 rounded bg-bg-base border border-border font-mono text-text-primary">
              <span className="text-accent mr-1">{kind}</span>
              {String(label)}
            </span>
            {i < nodes.length - 1 && <ArrowRight className="w-3 h-3 text-text-muted" />}
          </span>
        );
      })}
    </div>
  );
}

// ── Empty state ──────────────────────────────────────────────────────────────

function EmptyState() {
  return (
    <div className="px-6 py-10 text-center text-xs text-text-muted">
      <Route className="w-8 h-8 mx-auto mb-2 opacity-40" />
      <p>No findings match the current filters.</p>
      <p className="mt-1">
        Upload a Palo Alto or F5 config above and trigger a run to populate.
      </p>
    </div>
  );
}
