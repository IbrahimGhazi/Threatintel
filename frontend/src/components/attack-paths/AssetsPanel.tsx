"use client";

/**
 * Asset criticality management — defines the `:Asset` set used by the
 * attack-path engine. Without tagged assets, the engine has no destinations
 * for path-finding, only fan-out.
 */
import { useMemo, useState } from "react";
import useSWR from "swr";
import { Plus, ShieldCheck } from "lucide-react";
import { apiFetch } from "@/lib/api";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import clsx from "clsx";

type Criticality = "crown_jewel" | "high" | "medium" | "low";

interface Asset {
  ip: string;
  hostname?: string;
  criticality: Criticality;
  business_unit?: string;
  notes?: string;
}

const CRIT_BADGE: Record<Criticality, string> = {
  crown_jewel: "text-severity-critical bg-severity-critical/10 border-severity-critical/30",
  high:        "text-severity-high     bg-severity-high/10     border-severity-high/30",
  medium:      "text-severity-medium   bg-severity-medium/10   border-severity-medium/30",
  low:         "text-severity-low      bg-severity-low/10      border-severity-low/30",
};

const CRIT_LABEL: Record<Criticality, string> = {
  crown_jewel: "Crown jewel",
  high:        "High",
  medium:      "Medium",
  low:         "Low",
};

async function listAssets(): Promise<Asset[]> {
  return apiFetch<Asset[]>("/attack-paths/assets");
}

async function upsertAsset(ip: string, body: Omit<Asset, "ip">): Promise<Asset> {
  return apiFetch<Asset>(`/attack-paths/assets/${encodeURIComponent(ip)}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

export function AssetsPanel() {
  const { data, isLoading, mutate } = useSWR("attack-paths-assets", listAssets);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Form state for the inline "add asset" row
  const [newIp,   setNewIp]   = useState("");
  const [newName, setNewName] = useState("");
  const [newBu,   setNewBu]   = useState("");
  const [newCrit, setNewCrit] = useState<Criticality>("high");
  const [newNotes, setNewNotes] = useState("");

  const grouped = useMemo(() => {
    const out: Record<Criticality, Asset[]> = {
      crown_jewel: [], high: [], medium: [], low: [],
    };
    for (const a of data ?? []) out[a.criticality]?.push(a);
    return out;
  }, [data]);

  async function add() {
    if (!newIp.trim()) return;
    setBusy(true); setErr(null);
    try {
      await upsertAsset(newIp.trim(), {
        hostname: newName.trim() || undefined,
        criticality: newCrit,
        business_unit: newBu.trim() || undefined,
        notes: newNotes.trim() || undefined,
      });
      setNewIp(""); setNewName(""); setNewBu(""); setNewNotes("");
      await mutate();
    } catch (ex) {
      setErr(String(ex));
    } finally {
      setBusy(false);
    }
  }

  async function changeCrit(asset: Asset, criticality: Criticality) {
    setBusy(true); setErr(null);
    try {
      await upsertAsset(asset.ip, {
        hostname: asset.hostname,
        criticality,
        business_unit: asset.business_unit,
        notes: asset.notes,
      });
      await mutate();
    } catch (ex) {
      setErr(String(ex));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="card p-4">
        <div className="flex items-center gap-2 mb-3">
          <Plus className="w-4 h-4 text-accent" />
          <h3 className="text-sm font-semibold text-text-primary">Tag a new asset</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-6 gap-2">
          <input value={newIp}   onChange={e => setNewIp(e.target.value)}
                 placeholder="IP (10.20.30.40)"
                 className="md:col-span-1 bg-bg-base border border-border rounded px-2 py-1.5 text-xs font-mono text-text-primary" />
          <input value={newName} onChange={e => setNewName(e.target.value)}
                 placeholder="Hostname"
                 className="md:col-span-1 bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary" />
          <input value={newBu}   onChange={e => setNewBu(e.target.value)}
                 placeholder="Business unit"
                 className="md:col-span-1 bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary" />
          <select value={newCrit} onChange={e => setNewCrit(e.target.value as Criticality)}
                  className="md:col-span-1 bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary">
            {(["crown_jewel","high","medium","low"] as Criticality[]).map(c => (
              <option key={c} value={c}>{CRIT_LABEL[c]}</option>
            ))}
          </select>
          <input value={newNotes} onChange={e => setNewNotes(e.target.value)}
                 placeholder="Notes (optional)"
                 className="md:col-span-1 bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary" />
          <button onClick={add} disabled={busy || !newIp.trim()}
                  className="md:col-span-1 text-xs px-3 py-1.5 rounded bg-accent/10 border border-accent/30 text-accent hover:bg-accent/20 disabled:opacity-40">
            {busy ? "Adding…" : "Add asset"}
          </button>
        </div>
        {err && <div className="mt-2 text-xs text-severity-high">{err}</div>}
        <p className="mt-3 text-2xs text-text-muted">
          Crown-jewel assets are weighted 1.0× in the criticality factor; high
          0.7×, medium 0.4×, low 0.2×. Untagged hosts default to 0.3× so they
          still surface, but score lower than tagged assets.
        </p>
      </div>

      {isLoading ? (
        <div className="card p-10 flex justify-center"><LoadingSpinner /></div>
      ) : (
        (["crown_jewel","high","medium","low"] as Criticality[]).map(c => (
          <div key={c} className="card overflow-hidden">
            <div className="px-4 py-2 border-b border-border flex items-center gap-2">
              <span className={clsx("text-2xs px-2 py-0.5 rounded border", CRIT_BADGE[c])}>
                {CRIT_LABEL[c]}
              </span>
              <span className="text-2xs text-text-muted">
                {grouped[c].length} asset{grouped[c].length === 1 ? "" : "s"}
              </span>
            </div>
            {grouped[c].length === 0 ? (
              <div className="px-4 py-3 text-2xs text-text-muted">
                No assets at this level.
              </div>
            ) : (
              <table className="w-full text-xs">
                <thead className="bg-bg-base text-text-muted">
                  <tr>
                    <th className="text-left px-3 py-2 font-medium">IP</th>
                    <th className="text-left px-3 py-2 font-medium">Hostname</th>
                    <th className="text-left px-3 py-2 font-medium">Business unit</th>
                    <th className="text-left px-3 py-2 font-medium">Notes</th>
                    <th className="text-left px-3 py-2 font-medium">Change level</th>
                  </tr>
                </thead>
                <tbody>
                  {grouped[c].map(a => (
                    <tr key={a.ip} className="border-t border-border">
                      <td className="px-3 py-2 text-text-primary font-mono">{a.ip}</td>
                      <td className="px-3 py-2 text-text-secondary">{a.hostname ?? "—"}</td>
                      <td className="px-3 py-2 text-text-secondary">{a.business_unit ?? "—"}</td>
                      <td className="px-3 py-2 text-text-muted">{a.notes ?? ""}</td>
                      <td className="px-3 py-2">
                        <select
                          value={a.criticality}
                          onChange={e => changeCrit(a, e.target.value as Criticality)}
                          disabled={busy}
                          className="bg-bg-base border border-border rounded px-1 py-0.5 text-2xs text-text-primary"
                        >
                          {(["crown_jewel","high","medium","low"] as Criticality[]).map(opt => (
                            <option key={opt} value={opt}>{CRIT_LABEL[opt]}</option>
                          ))}
                        </select>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        ))
      )}

      {(data?.length ?? 0) === 0 && !isLoading && (
        <div className="card p-6 text-center text-xs text-text-muted">
          <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-40" />
          <p>No assets tagged yet. Tag at least one to enable attack-path findings.</p>
        </div>
      )}
    </div>
  );
}
