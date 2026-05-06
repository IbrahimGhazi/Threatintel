"use client";

/**
 * Device-registry panel for /attack-paths.
 *
 * Register a firewall or load-balancer once; the platform polls it on a
 * schedule (default 1h), saves new configs as upload rows, and auto-runs the
 * analysis when a config changes.
 */
import { useState } from "react";
import useSWR from "swr";
import {
  Plus, Server, RefreshCw, Trash2, Power, PowerOff,
  CheckCircle2, AlertTriangle, XCircle, Clock,
} from "lucide-react";
import clsx from "clsx";
import { formatDistanceToNow, parseISO } from "date-fns";

import {
  createAttackPathDevice,
  deleteAttackPathDevice,
  fetchAttackPathDeviceNow,
  listAttackPathDevices,
  patchAttackPathDevice,
  type AttackPathDevice,
  type AttackPathDeviceStatus,
  type AttackPathDeviceVendor,
} from "@/lib/api";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";

const STATUS_DISPLAY: Record<AttackPathDeviceStatus,
  { label: string; cls: string; Icon: React.ElementType }> = {
  pending:     { label: "Pending",     cls: "text-text-muted bg-bg-elevated border-border", Icon: Clock },
  ok:          { label: "Healthy",     cls: "text-status-success bg-status-success/10 border-status-success/30", Icon: CheckCircle2 },
  auth_failed: { label: "Auth failed", cls: "text-severity-high bg-severity-high/10 border-severity-high/30", Icon: AlertTriangle },
  unreachable: { label: "Unreachable", cls: "text-severity-high bg-severity-high/10 border-severity-high/30", Icon: XCircle },
  parse_error: { label: "Parse error", cls: "text-severity-medium bg-severity-medium/10 border-severity-medium/30", Icon: AlertTriangle },
  disabled:    { label: "Disabled",    cls: "text-text-muted bg-bg-elevated border-border", Icon: PowerOff },
};

const VENDOR_LABEL: Record<AttackPathDeviceVendor, string> = {
  panos:    "Palo Alto (PAN-OS)",
  f5:       "F5 BIG-IP",
  fortinet: "Fortinet (not yet supported)",
};

export function DevicesPanel() {
  const { data, isLoading, mutate } = useSWR(
    "attack-paths-devices", listAttackPathDevices,
    { refreshInterval: 30_000 },
  );

  return (
    <div className="space-y-4">
      <RegisterForm onSaved={() => { void mutate(); }} />

      {isLoading ? (
        <div className="card p-10 flex justify-center"><LoadingSpinner /></div>
      ) : (data?.length ?? 0) === 0 ? (
        <div className="card p-6 text-center text-xs text-text-muted">
          <Server className="w-8 h-8 mx-auto mb-2 opacity-40" />
          <p>No devices registered yet.</p>
          <p className="mt-1">Register a firewall or load balancer above —
            the platform will poll it every {Math.round(3600 / 60)} minutes by
            default and re-run analysis when the config changes.</p>
        </div>
      ) : (
        <DevicesTable
          devices={data!}
          onChanged={() => { void mutate(); }}
        />
      )}
    </div>
  );
}

// ── Registration form ───────────────────────────────────────────────────────

function RegisterForm({ onSaved }: { onSaved: () => void }) {
  const [vendor,   setVendor]   = useState<AttackPathDeviceVendor>("panos");
  const [hostname, setHostname] = useState("");
  const [address,  setAddress]  = useState("");
  const [port,     setPort]     = useState(443);
  const [verifyTls, setVerifyTls] = useState(false);
  const [interval, setInterval] = useState(3600);

  // PAN-OS auth modes — api_key OR user/password
  const [authMode, setAuthMode] = useState<"api_key" | "user_pass">("api_key");
  const [apiKey,   setApiKey]   = useState("");
  const [user,     setUser]     = useState("");
  const [password, setPassword] = useState("");

  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const showApiKey = vendor === "panos" && authMode === "api_key";
  const showUserPass = vendor === "f5" || (vendor === "panos" && authMode === "user_pass");

  async function submit() {
    setBusy(true); setErr(null);
    try {
      const credentials: { api_key?: string; user?: string; password?: string } = {};
      if (showApiKey) credentials.api_key = apiKey.trim();
      if (showUserPass) {
        credentials.user = user.trim();
        credentials.password = password;
      }
      await createAttackPathDevice({
        vendor, hostname: hostname.trim(), address: address.trim(),
        port, verify_tls: verifyTls,
        poll_interval_seconds: interval,
        enabled: true, created_by: "ui",
        credentials,
      });
      // Reset on success
      setHostname(""); setAddress(""); setApiKey(""); setUser(""); setPassword("");
      onSaved();
    } catch (ex) {
      setErr(String(ex));
    } finally {
      setBusy(false);
    }
  }

  const valid =
    hostname.trim() && address.trim() &&
    (showApiKey ? apiKey.trim().length > 0
                : user.trim().length > 0 && password.length > 0);

  return (
    <div className="card p-4">
      <div className="flex items-center gap-2 mb-3">
        <Plus className="w-4 h-4 text-accent" />
        <h3 className="text-sm font-semibold text-text-primary">Register a device</h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div>
          <label className="block text-2xs uppercase tracking-wider text-text-muted mb-1">Vendor</label>
          <select value={vendor}
                  onChange={e => setVendor(e.target.value as AttackPathDeviceVendor)}
                  className="w-full bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary">
            {(Object.keys(VENDOR_LABEL) as AttackPathDeviceVendor[]).map(v => (
              <option key={v} value={v} disabled={v === "fortinet"}>
                {VENDOR_LABEL[v]}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-2xs uppercase tracking-wider text-text-muted mb-1">Hostname</label>
          <input value={hostname} onChange={e => setHostname(e.target.value)}
                 placeholder="pa-edge-01"
                 className="w-full bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary" />
        </div>
        <div>
          <label className="block text-2xs uppercase tracking-wider text-text-muted mb-1">Address</label>
          <input value={address} onChange={e => setAddress(e.target.value)}
                 placeholder="10.0.0.1 or fw.internal"
                 className="w-full bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary font-mono" />
        </div>

        <div>
          <label className="block text-2xs uppercase tracking-wider text-text-muted mb-1">Port</label>
          <input type="number" value={port}
                 onChange={e => setPort(Number(e.target.value) || 443)}
                 className="w-full bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary font-mono" />
        </div>
        <div>
          <label className="block text-2xs uppercase tracking-wider text-text-muted mb-1">Poll interval (seconds)</label>
          <input type="number" value={interval}
                 onChange={e => setInterval(Number(e.target.value) || 3600)}
                 min={60} max={86400}
                 className="w-full bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary font-mono" />
        </div>
        <div className="flex items-end">
          <label className="text-xs text-text-secondary inline-flex items-center gap-2">
            <input type="checkbox" checked={verifyTls}
                   onChange={e => setVerifyTls(e.target.checked)} />
            Verify TLS certificate
          </label>
        </div>

        {vendor === "panos" && (
          <div className="md:col-span-3">
            <div className="inline-flex rounded border border-border overflow-hidden">
              {(["api_key", "user_pass"] as const).map(m => (
                <button key={m} type="button"
                        onClick={() => setAuthMode(m)}
                        className={
                          "text-2xs px-3 py-1.5 " +
                          (authMode === m
                            ? "bg-accent/10 text-accent"
                            : "text-text-muted hover:text-text-primary")
                        }>
                  {m === "api_key" ? "API key" : "User + password"}
                </button>
              ))}
            </div>
          </div>
        )}

        {showApiKey && (
          <div className="md:col-span-3">
            <label className="block text-2xs uppercase tracking-wider text-text-muted mb-1">PAN-OS API key</label>
            <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)}
                   placeholder="LUFRPT…"
                   className="w-full bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary font-mono" />
            <p className="mt-1 text-2xs text-text-muted">
              Generate via{" "}
              <code className="font-mono">curl -k 'https://{address || "host"}/api/?type=keygen&user=…&password=…'</code>
            </p>
          </div>
        )}

        {showUserPass && (
          <>
            <div>
              <label className="block text-2xs uppercase tracking-wider text-text-muted mb-1">User</label>
              <input value={user} onChange={e => setUser(e.target.value)}
                     placeholder="admin"
                     className="w-full bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary" />
            </div>
            <div className="md:col-span-2">
              <label className="block text-2xs uppercase tracking-wider text-text-muted mb-1">Password</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                     className="w-full bg-bg-base border border-border rounded px-2 py-1.5 text-xs text-text-primary" />
            </div>
          </>
        )}
      </div>

      <div className="mt-4 flex items-center gap-3">
        <button onClick={submit} disabled={busy || !valid}
                className="text-xs px-3 py-2 rounded bg-accent/10 border border-accent/30 text-accent hover:bg-accent/20 disabled:opacity-40 inline-flex items-center gap-1.5">
          <Plus className="w-3.5 h-3.5" />
          {busy ? "Registering & polling…" : "Register & poll now"}
        </button>
        {err && <span className="text-xs text-severity-high">{err}</span>}
        <span className="ml-auto text-2xs text-text-muted">
          Credentials are encrypted with the platform's master key before
          storage. Only the last 4 chars are shown afterwards.
        </span>
      </div>
    </div>
  );
}

// ── Devices table ───────────────────────────────────────────────────────────

function DevicesTable({
  devices, onChanged,
}: {
  devices: AttackPathDevice[];
  onChanged: () => void;
}) {
  return (
    <div className="card overflow-hidden">
      <div className="px-4 py-3 border-b border-border flex items-center gap-2">
        <Server className="w-4 h-4 text-accent" />
        <h3 className="text-sm font-semibold text-text-primary">
          Registered devices
          <span className="ml-2 text-xs text-text-muted">({devices.length})</span>
        </h3>
      </div>
      <table className="w-full text-xs">
        <thead className="bg-bg-base text-text-muted">
          <tr>
            <th className="text-left px-3 py-2 font-medium">Status</th>
            <th className="text-left px-3 py-2 font-medium">Vendor</th>
            <th className="text-left px-3 py-2 font-medium">Hostname</th>
            <th className="text-left px-3 py-2 font-medium">Address</th>
            <th className="text-left px-3 py-2 font-medium">Edge</th>
            <th className="text-left px-3 py-2 font-medium">Interval</th>
            <th className="text-left px-3 py-2 font-medium">Last poll</th>
            <th className="text-right px-3 py-2 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {devices.map(d => (
            <DeviceRow key={d.id} device={d} onChanged={onChanged} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DeviceRow({ device, onChanged }: {
  device: AttackPathDevice; onChanged: () => void;
}) {
  const [busy, setBusy] = useState<"" | "fetch" | "toggle" | "delete">("");
  const [lastResult, setLastResult] = useState<string | null>(null);
  const status = STATUS_DISPLAY[device.last_status] ?? STATUS_DISPLAY.pending;
  const StatusIcon = status.Icon;

  async function fetchNow() {
    setBusy("fetch"); setLastResult(null);
    try {
      const res = await fetchAttackPathDeviceNow(device.id);
      setLastResult(res.changed ? "config changed → run queued"
                                : res.ok ? "no changes" : `error: ${res.error}`);
      onChanged();
    } catch (ex) {
      setLastResult(`error: ${ex}`);
    } finally {
      setBusy("");
    }
  }

  async function toggle() {
    setBusy("toggle");
    try {
      await patchAttackPathDevice(device.id, { enabled: !device.enabled });
      onChanged();
    } catch (ex) {
      setLastResult(`error: ${ex}`);
    } finally {
      setBusy("");
    }
  }

  async function remove() {
    if (!confirm(`Delete ${device.hostname}? Encrypted credentials will be removed.`)) return;
    setBusy("delete");
    try {
      await deleteAttackPathDevice(device.id);
      onChanged();
    } catch (ex) {
      setLastResult(`error: ${ex}`);
    } finally {
      setBusy("");
    }
  }

  return (
    <tr className="border-t border-border">
      <td className="px-3 py-2">
        <span className={clsx("inline-flex items-center gap-1 px-2 py-0.5 rounded border text-2xs", status.cls)}>
          <StatusIcon className="w-3 h-3" /> {status.label}
        </span>
        {device.last_error && (
          <div className="mt-1 text-2xs text-text-muted truncate max-w-[260px]"
               title={device.last_error}>{device.last_error}</div>
        )}
      </td>
      <td className="px-3 py-2 text-text-secondary">{VENDOR_LABEL[device.vendor]}</td>
      <td className="px-3 py-2 text-text-primary">{device.hostname}</td>
      <td className="px-3 py-2 font-mono text-text-secondary">
        {device.address}:{device.port}
      </td>
      <td className="px-3 py-2">
        {device.is_edge ? (
          <span className="text-2xs text-severity-high">edge</span>
        ) : (
          <span className="text-2xs text-text-muted">—</span>
        )}
      </td>
      <td className="px-3 py-2 text-text-secondary">{device.poll_interval_seconds}s</td>
      <td className="px-3 py-2 text-text-muted">
        {device.last_polled_at
          ? formatDistanceToNow(parseISO(device.last_polled_at), { addSuffix: true })
          : "never"}
        {lastResult && (
          <div className="mt-0.5 text-2xs text-text-secondary">{lastResult}</div>
        )}
      </td>
      <td className="px-3 py-2">
        <div className="flex items-center justify-end gap-1">
          <button onClick={fetchNow} disabled={!!busy} title="Fetch now"
                  className="p-1.5 rounded border border-border text-text-muted hover:text-text-primary disabled:opacity-30">
            <RefreshCw className={clsx("w-3.5 h-3.5", busy === "fetch" && "animate-spin")} />
          </button>
          <button onClick={toggle} disabled={!!busy}
                  title={device.enabled ? "Disable polling" : "Enable polling"}
                  className="p-1.5 rounded border border-border text-text-muted hover:text-text-primary disabled:opacity-30">
            {device.enabled ? <PowerOff className="w-3.5 h-3.5" /> : <Power className="w-3.5 h-3.5" />}
          </button>
          <button onClick={remove} disabled={!!busy} title="Delete"
                  className="p-1.5 rounded border border-border text-text-muted hover:text-severity-high disabled:opacity-30">
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </td>
    </tr>
  );
}
