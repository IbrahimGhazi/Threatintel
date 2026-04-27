"use client";

import { useState } from "react";
import useSWR from "swr";
import { ShieldCheck, Plus, Trash2, AlertTriangle, Clock } from "lucide-react";
import {
  getWhitelist,
  createWhitelistEntry,
  deleteWhitelistEntry,
  type WhitelistEntryType,
  type CreateWhitelistBody,
} from "@/lib/api";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { Badge } from "@/components/ui/badge";
import { formatDistanceToNow, parseISO } from "date-fns";
import clsx from "clsx";

const ENTRY_TYPES = [
  { value: "ip", label: "IP Address" },
  { value: "cidr", label: "CIDR Range" },
  { value: "hostname", label: "Hostname" },
  { value: "rule_name", label: "Rule Name" },
  { value: "indicator_value", label: "Indicator Value" },
];

const RULE_OPTIONS = [
  { value: "", label: "All Rules" },
  { value: "brute_force", label: "Brute Force" },
  { value: "password_spray", label: "Password Spray" },
  { value: "port_scan", label: "Port Scan" },
  { value: "host_discovery", label: "Host Discovery" },
  { value: "service_scan", label: "Service Scan" },
  { value: "repeated_connection_attempts", label: "Repeated Connections" },
  { value: "repeated_blocked_connections", label: "Blocked Connections" },
  { value: "lateral_movement", label: "Lateral Movement" },
  { value: "c2_beaconing", label: "C2 Beaconing" },
  { value: "malicious_ip_connection", label: "Malicious IP" },
  { value: "ti_match", label: "TI Match" },
  { value: "multi_stage_attack", label: "Multi-Stage Attack" },
];

export default function WhitelistPage() {
  const [filterType, setFilterType] = useState("");
  const [showAdd, setShowAdd] = useState(false);
  const [acting, setActing] = useState<string | null>(null);

  // Form state
  const [formType, setFormType] = useState("ip");
  const [formValue, setFormValue] = useState("");
  const [formScope, setFormScope] = useState("");
  const [formReason, setFormReason] = useState("");
  const [formError, setFormError] = useState("");

  const { data, isLoading, error, mutate } = useSWR(
    ["whitelist", filterType],
    () => getWhitelist({ entry_type: filterType || undefined }),
    { refreshInterval: 30000 }
  );

  const handleAdd = async () => {
    if (!formValue.trim()) {
      setFormError("Value is required");
      return;
    }
    setFormError("");
    setActing("add");
    try {
      const body: CreateWhitelistBody = {
        entry_type: formType,
        value: formValue.trim(),
        scope_rule: formScope || null,
        reason: formReason || null,
        created_by: "analyst",
      };
      await createWhitelistEntry(body);
      mutate();
      setShowAdd(false);
      setFormValue("");
      setFormScope("");
      setFormReason("");
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : "Failed to create entry");
    } finally {
      setActing(null);
    }
  };

  const handleDelete = async (id: string) => {
    setActing(id);
    try {
      await deleteWhitelistEntry(id);
      mutate();
    } finally {
      setActing(null);
    }
  };

  const entries = data?.items ?? [];

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text-primary">Whitelist</h1>
          <p className="text-sm text-text-muted mt-0.5">
            {data ? `${data.total} active entries` : "Manage trusted IPs, hosts, and rules to suppress false positive alerts"}
          </p>
        </div>
        <button
          onClick={() => setShowAdd(!showAdd)}
          className="btn btn-primary text-xs flex items-center gap-1.5"
        >
          <Plus className="w-3.5 h-3.5" />
          Add Entry
        </button>
      </div>

      {/* Add form */}
      {showAdd && (
        <div className="card p-5 space-y-4 border-accent/30">
          <h2 className="text-sm font-semibold text-text-primary">New Whitelist Entry</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-text-muted mb-1">Type</label>
              <select
                value={formType}
                onChange={(e) => setFormType(e.target.value)}
                className="ti-input text-sm w-full"
              >
                {ENTRY_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-text-muted mb-1">Value</label>
              <input
                type="text"
                value={formValue}
                onChange={(e) => setFormValue(e.target.value)}
                placeholder={formType === "ip" ? "192.168.1.100" : formType === "cidr" ? "10.0.0.0/8" : "Enter value..."}
                className="ti-input text-sm w-full"
              />
            </div>
            <div>
              <label className="block text-xs text-text-muted mb-1">Scope (optional rule)</label>
              <select
                value={formScope}
                onChange={(e) => setFormScope(e.target.value)}
                className="ti-input text-sm w-full"
              >
                {RULE_OPTIONS.map((r) => (
                  <option key={r.value} value={r.value}>{r.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-text-muted mb-1">Reason</label>
              <input
                type="text"
                value={formReason}
                onChange={(e) => setFormReason(e.target.value)}
                placeholder="e.g., Internal scanner, trusted partner..."
                className="ti-input text-sm w-full"
              />
            </div>
          </div>
          {formError && (
            <p className="text-xs text-severity-high">{formError}</p>
          )}
          <div className="flex gap-2">
            <button
              onClick={handleAdd}
              disabled={acting === "add"}
              className="btn btn-primary text-xs"
            >
              {acting === "add" ? <LoadingSpinner size="sm" /> : "Create"}
            </button>
            <button
              onClick={() => { setShowAdd(false); setFormError(""); }}
              className="btn btn-ghost text-xs"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card p-4 flex flex-wrap gap-3">
        <div className="flex gap-2">
          {[{ value: "", label: "All" }, ...ENTRY_TYPES].map((t) => (
            <button
              key={t.value}
              onClick={() => setFilterType(t.value)}
              className={clsx(
                "btn text-xs",
                filterType === t.value ? "btn-primary" : "btn-ghost"
              )}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Entry list */}
      <div className="space-y-2">
        {isLoading ? (
          <div className="card flex items-center justify-center py-16">
            <LoadingSpinner />
          </div>
        ) : error ? (
          <div className="card flex items-center justify-center py-16 gap-2 text-text-muted text-sm">
            <AlertTriangle className="w-4 h-4 text-severity-high" />
            Failed to load whitelist
          </div>
        ) : entries.length === 0 ? (
          <div className="card flex flex-col items-center justify-center py-16 gap-3">
            <ShieldCheck className="w-8 h-8 text-text-muted" />
            <p className="text-sm text-text-muted">No whitelist entries</p>
            <p className="text-xs text-text-muted">Add entries to suppress false positive alerts</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-bg-elevated">
                  <th className="text-left py-2.5 px-4 text-text-muted font-medium text-xs">Type</th>
                  <th className="text-left py-2.5 px-4 text-text-muted font-medium text-xs">Value</th>
                  <th className="text-left py-2.5 px-4 text-text-muted font-medium text-xs">Scope</th>
                  <th className="text-left py-2.5 px-4 text-text-muted font-medium text-xs">Reason</th>
                  <th className="text-left py-2.5 px-4 text-text-muted font-medium text-xs">Created</th>
                  <th className="text-right py-2.5 px-4 text-text-muted font-medium text-xs w-20">Actions</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry: WhitelistEntryType) => (
                  <tr key={entry.id} className="border-b border-border last:border-0 hover:bg-bg-elevated/50">
                    <td className="py-2.5 px-4">
                      <Badge variant="secondary" className="text-xs">
                        {entry.entry_type}
                      </Badge>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-xs text-accent">
                      {entry.value}
                    </td>
                    <td className="py-2.5 px-4 text-xs text-text-muted">
                      {entry.scope_rule ? (
                        <Badge variant="outline" className="text-xs">
                          {entry.scope_rule.replace(/_/g, " ")}
                        </Badge>
                      ) : (
                        <span className="text-text-muted">all rules</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 text-xs text-text-secondary max-w-xs truncate">
                      {entry.reason || "-"}
                    </td>
                    <td className="py-2.5 px-4 text-xs text-text-muted">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {formatDistanceToNow(parseISO(entry.created_at), { addSuffix: true })}
                      </span>
                      <span className="text-2xs">{entry.created_by}</span>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={() => handleDelete(entry.id)}
                        disabled={acting === entry.id}
                        className="btn-ghost text-xs px-2 py-1 h-auto text-severity-high hover:bg-severity-high/10"
                        title="Remove from whitelist"
                      >
                        {acting === entry.id ? <LoadingSpinner size="sm" /> : <Trash2 className="w-3.5 h-3.5" />}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
