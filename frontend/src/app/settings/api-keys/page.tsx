"use client";

/**
 * API Keys settings page.
 *
 * Lets operators paste their own threat-intel feed credentials. Plaintext
 * values never round-trip through the browser — backend returns last-4 only.
 *
 * See services/api/app/routers/api_keys.py for the corresponding endpoints.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  KeyRound,
  CheckCircle2,
  Circle,
  AlertTriangle,
  Loader2,
  Edit3,
  Eraser,
  ExternalLink,
  Eye,
  EyeOff,
  ShieldCheck,
  X,
} from "lucide-react";
import clsx from "clsx";

// ── API ──────────────────────────────────────────────────────────────────────

const API = process.env.NEXT_PUBLIC_API_URL ?? "/api";
const KEY = process.env.NEXT_PUBLIC_API_KEY ?? "";
const HDRS = (): Record<string, string> => ({
  "Content-Type": "application/json",
  "X-API-Key": KEY,
});

// ── Types ────────────────────────────────────────────────────────────────────

interface ApiKeyRow {
  id: string;
  label: string;
  env_var: string;
  upstream_url: string;
  consumer: "ingestion" | "sandbox";
  status: "ui" | "env" | "empty";
  masked: string | null;
  updated_at: string | null;
}

// ── Status pill ──────────────────────────────────────────────────────────────

function StatusPill({ status }: { status: ApiKeyRow["status"] }) {
  if (status === "ui") {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-status-success/15 text-status-success border border-status-success/25">
        <CheckCircle2 className="w-3 h-3" />
        UI-managed
      </span>
    );
  }
  if (status === "env") {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-status-warning/15 text-status-warning border border-status-warning/25">
        <ShieldCheck className="w-3 h-3" />
        env (.env)
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-bg-elevated text-text-muted border border-border">
      <Circle className="w-3 h-3" />
      Empty
    </span>
  );
}

// ── Set / Edit modal ─────────────────────────────────────────────────────────

function SetKeyModal({
  row,
  onClose,
  onSaved,
}: {
  row: ApiKeyRow;
  onClose: () => void;
  onSaved: (msg: string) => void;
}) {
  const [value, setValue] = useState("");
  const [reveal, setReveal] = useState(false);
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!value.trim() || !consent) return;
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`${API}/system/api-keys/${row.id}`, {
        method: "PUT",
        headers: HDRS(),
        body: JSON.stringify({ value: value.trim() }),
      });
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        throw new Error(`HTTP ${res.status}${txt ? `: ${txt}` : ""}`);
      }
      const body = await res.json();
      onSaved(body.message || `${row.label} key saved.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg bg-bg-surface border border-border rounded-lg shadow-xl">
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-border">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-accent" />
            Set {row.label} API key
          </h2>
          <button
            onClick={onClose}
            className="text-text-muted hover:text-text-primary"
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          <div className="text-xs text-text-secondary leading-relaxed">
            Paste your <span className="font-mono">{row.label}</span> key.
            Stored encrypted (Fernet / AES-128) in the platform database.
            Plaintext is never logged and never returned by the API.
          </div>

          <a
            href={row.upstream_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-accent hover:underline"
          >
            Get a key at {row.upstream_url}
            <ExternalLink className="w-3 h-3" />
          </a>

          {row.masked && (
            <div className="text-xs text-text-muted">
              Currently set: <span className="font-mono">{row.masked}</span>{" "}
              (will be overwritten)
            </div>
          )}

          <div className="relative">
            <input
              type={reveal ? "text" : "password"}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="Paste key here…"
              autoFocus
              className={clsx(
                "w-full px-3 py-2 pr-10 rounded-md text-sm font-mono",
                "bg-bg-elevated border border-border text-text-primary",
                "placeholder:text-text-muted",
                "focus:outline-none focus:border-accent",
              )}
              disabled={busy}
            />
            <button
              type="button"
              onClick={() => setReveal((r) => !r)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary"
              tabIndex={-1}
              aria-label={reveal ? "Hide" : "Show"}
            >
              {reveal ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>

          <label className="flex items-start gap-2 text-xs text-text-secondary cursor-pointer">
            <input
              type="checkbox"
              checked={consent}
              onChange={(e) => setConsent(e.target.checked)}
              className="mt-0.5"
              disabled={busy}
            />
            <span>
              I understand this key will be encrypted and stored on this server.
              {" "}Losing the master key makes stored values unrecoverable.
            </span>
          </label>

          {error && (
            <div className="text-xs text-status-error bg-status-error/10 border border-status-error/25 rounded px-3 py-2">
              {error}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 px-5 py-3 border-t border-border bg-bg-elevated/40">
          <button
            onClick={onClose}
            disabled={busy}
            className="px-3 py-1.5 text-xs rounded-md border border-border text-text-secondary hover:bg-bg-elevated"
          >
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={busy || !value.trim() || !consent}
            className={clsx(
              "px-3 py-1.5 text-xs rounded-md font-medium inline-flex items-center gap-1.5",
              "bg-accent text-bg-base hover:bg-accent/90",
              "disabled:opacity-40 disabled:cursor-not-allowed",
            )}
          >
            {busy && <Loader2 className="w-3 h-3 animate-spin" />}
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function ApiKeysPage() {
  const [rows, setRows] = useState<ApiKeyRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [encAvailable, setEncAvailable] = useState<boolean | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const fetchAll = useCallback(async () => {
    try {
      const [listRes, diagRes] = await Promise.all([
        fetch(`${API}/system/api-keys`, { headers: HDRS() }),
        fetch(`${API}/system/api-keys/_diag/encryption`, { headers: HDRS() }),
      ]);
      if (!listRes.ok) throw new Error(`list: HTTP ${listRes.status}`);
      const list = (await listRes.json()) as ApiKeyRow[];
      setRows(list);
      if (diagRes.ok) {
        const diag = await diagRes.json();
        setEncAvailable(Boolean(diag.available));
      }
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => setToast(null), 4500);
    return () => window.clearTimeout(t);
  }, [toast]);

  const clearKey = async (row: ApiKeyRow) => {
    if (!confirm(`Clear ${row.label} key? Env-var fallback (if any) will resume.`))
      return;
    try {
      const res = await fetch(`${API}/system/api-keys/${row.id}`, {
        method: "DELETE",
        headers: HDRS(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setToast(`${row.label} key cleared.`);
      fetchAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const editingRow = useMemo(
    () => (editingId ? rows.find((r) => r.id === editingId) ?? null : null),
    [editingId, rows],
  );

  return (
    <div className="p-6 max-w-5xl">
      <div className="mb-5">
        <h1 className="text-xl font-semibold text-text-primary flex items-center gap-2">
          <KeyRound className="w-5 h-5 text-accent" />
          Threat-Intelligence API Keys
        </h1>
        <p className="mt-1 text-xs text-text-secondary leading-relaxed max-w-3xl">
          Bring your own keys for upstream threat-intel feeds and the
          VirusTotal sandbox. Keys are stored encrypted (Fernet / AES-128) in
          the platform database with a master key held only on this server.
          Plaintext is never logged, never returned by the API, and never
          transmitted back to the browser.
        </p>
      </div>

      {encAvailable === false && (
        <div className="mb-4 flex items-start gap-2 px-3 py-2.5 rounded-md text-xs bg-status-warning/10 border border-status-warning/30 text-status-warning">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold">Encryption disabled</div>
            <div className="mt-0.5 text-text-secondary">
              <span className="font-mono">MASTER_ENCRYPTION_KEY</span> is not
              configured. Keys saved here will be stored as plaintext. Set the
              secret and restart the API service for production deployments.
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="mb-4 px-3 py-2 rounded-md text-xs bg-status-error/10 border border-status-error/30 text-status-error">
          {error}
        </div>
      )}

      <div className="border border-border rounded-lg overflow-hidden bg-bg-surface">
        <table className="w-full text-sm">
          <thead className="bg-bg-elevated">
            <tr className="text-xs text-text-muted uppercase tracking-wider">
              <th className="text-left px-4 py-2.5 font-semibold">Provider</th>
              <th className="text-left px-4 py-2.5 font-semibold">Status</th>
              <th className="text-left px-4 py-2.5 font-semibold">Value</th>
              <th className="text-left px-4 py-2.5 font-semibold">Consumer</th>
              <th className="text-right px-4 py-2.5 font-semibold">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {loading && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-text-muted">
                  <Loader2 className="w-4 h-4 inline animate-spin mr-2" />
                  Loading providers…
                </td>
              </tr>
            )}
            {!loading &&
              rows.map((r) => (
                <tr key={r.id} className="hover:bg-bg-elevated/40">
                  <td className="px-4 py-3">
                    <div className="font-medium text-text-primary">{r.label}</div>
                    <a
                      href={r.upstream_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-2xs text-text-muted hover:text-accent inline-flex items-center gap-1 mt-0.5"
                    >
                      {r.upstream_url}
                      <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                  </td>
                  <td className="px-4 py-3">
                    <StatusPill status={r.status} />
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs text-text-secondary">
                      {r.masked || <span className="text-text-muted">—</span>}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-text-secondary capitalize">
                    {r.consumer}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="inline-flex gap-1.5">
                      <button
                        onClick={() => setEditingId(r.id)}
                        className="px-2 py-1 text-xs rounded border border-border text-text-secondary hover:bg-bg-elevated hover:text-text-primary inline-flex items-center gap-1"
                      >
                        <Edit3 className="w-3 h-3" />
                        {r.status === "empty" ? "Set" : r.status === "env" ? "Override" : "Edit"}
                      </button>
                      {r.status === "ui" && (
                        <button
                          onClick={() => clearKey(r)}
                          className="px-2 py-1 text-xs rounded border border-border text-text-muted hover:bg-status-error/10 hover:text-status-error hover:border-status-error/30 inline-flex items-center gap-1"
                        >
                          <Eraser className="w-3 h-3" />
                          Clear
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-text-muted">
                  No providers configured. Apply the SQL migration first.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <p className="mt-3 text-2xs text-text-muted">
        Ingestion feeds re-read keys at <span className="font-mono">pod restart</span>.
        VirusTotal sandbox key applies on the next sandbox-pod restart.
        Phase 2 will add live re-load + an upstream-test button.
      </p>

      {editingRow && (
        <SetKeyModal
          row={editingRow}
          onClose={() => setEditingId(null)}
          onSaved={(msg) => {
            setEditingId(null);
            setToast(msg);
            fetchAll();
          }}
        />
      )}

      {toast && (
        <div className="fixed bottom-6 right-6 z-50 max-w-md px-4 py-3 rounded-lg text-sm bg-status-success/15 border border-status-success/40 text-status-success shadow-lg">
          <div className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <div>{toast}</div>
          </div>
        </div>
      )}
    </div>
  );
}
