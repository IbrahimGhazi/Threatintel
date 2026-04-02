"use client";

import { useState } from "react";
import useSWR from "swr";
import { ListFilter, Eye, Copy, ExternalLink, CheckCircle } from "lucide-react";
import { getEDLConfigs, previewEDL, type EDLConfig } from "@/lib/api";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { formatDistanceToNow, parseISO } from "date-fns";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "/api";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={copy} className="btn-ghost p-1 text-xs" title="Copy URL">
      {copied ? <CheckCircle className="w-3.5 h-3.5 text-status-success" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

function PreviewModal({ config, onClose }: { config: EDLConfig; onClose: () => void }) {
  const { data, isLoading } = useSWR(["edl-preview", config.id], () => previewEDL(config.id));

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="card w-full max-w-2xl max-h-[80vh] flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-border">
          <div>
            <h2 className="text-sm font-semibold text-text-primary">{config.name}</h2>
            <p className="text-xs text-text-muted">
              {data ? `${data.total} indicators` : "Loading…"}
            </p>
          </div>
          <button onClick={onClose} className="btn-ghost text-xs">Close</button>
        </div>
        <div className="flex-1 overflow-auto p-4">
          {isLoading ? (
            <div className="flex items-center justify-center py-8"><LoadingSpinner /></div>
          ) : (
            <pre className="text-xs font-mono text-text-secondary whitespace-pre-wrap break-all">
              {data?.preview?.join("\n") ?? "No data"}
              {data && data.total > 100 && `\n\n… and ${data.total - 100} more entries`}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}

export default function EDLPage() {
  const { data: configs, isLoading } = useSWR("edl-configs", getEDLConfigs);
  const [previewing, setPreviewing] = useState<EDLConfig | null>(null);

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">EDL Management</h1>
        <p className="text-sm text-text-muted mt-0.5">
          External Dynamic Lists – served as plain text for firewall and proxy consumption
        </p>
      </div>

      {/* Info banner */}
      <div className="card p-4 border-l-2 border-l-accent bg-accent/5">
        <p className="text-xs text-text-secondary">
          <strong className="text-text-primary">EDL Endpoint:</strong>{" "}
          Configure your firewall or proxy to pull from{" "}
          <code className="font-mono text-accent">{typeof window !== "undefined" ? window.location.origin : ""}/api/edl/feed/&lt;slug&gt;</code>
        </p>
        <p className="text-2xs text-text-muted mt-1">
          Lists are rebuilt on each request and cached for 5 minutes.
          No authentication required for polling.
        </p>
      </div>

      {isLoading ? (
        <div className="card flex items-center justify-center py-16"><LoadingSpinner /></div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {(configs ?? []).map((config: EDLConfig) => {
            const feedUrl = `${typeof window !== "undefined" ? window.location.origin : ""}/api/edl/feed/${config.slug}`;

            return (
              <div key={config.id} className="card p-5">
                <div className="flex items-start justify-between gap-3 mb-4">
                  <div>
                    <h3 className="text-sm font-semibold text-text-primary">{config.name}</h3>
                    {config.description && (
                      <p className="text-xs text-text-muted mt-0.5">{config.description}</p>
                    )}
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setPreviewing(config)}
                      className="btn-ghost p-1 text-xs"
                      title="Preview feed"
                    >
                      <Eye className="w-3.5 h-3.5" />
                    </button>
                    <CopyButton text={feedUrl} />
                    <a
                      href={`/api/edl/feed/${config.slug}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn-ghost p-1 text-xs"
                      title="Open feed URL"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-3 text-center">
                  <div className="bg-bg-elevated rounded-md p-2.5">
                    <p className="text-lg font-bold font-mono text-text-primary">
                      {config.cached_count.toLocaleString()}
                    </p>
                    <p className="text-2xs text-text-muted">Entries</p>
                  </div>
                  <div className="bg-bg-elevated rounded-md p-2.5">
                    <p className="text-sm font-mono font-semibold text-text-primary uppercase">
                      {config.indicator_type}
                    </p>
                    <p className="text-2xs text-text-muted">Type</p>
                  </div>
                  <div className="bg-bg-elevated rounded-md p-2.5">
                    <p className="text-sm font-mono font-semibold text-text-primary">
                      {config.min_confidence}%
                    </p>
                    <p className="text-2xs text-text-muted">Min Conf.</p>
                  </div>
                </div>

                <div className="mt-3 p-2.5 bg-bg-elevated rounded-md">
                  <p className="text-2xs text-text-muted mb-1">Feed URL</p>
                  <code className="text-2xs font-mono text-accent break-all">{feedUrl}</code>
                </div>

                <div className="flex items-center justify-between mt-3 text-2xs text-text-muted">
                  <span className="capitalize">Severity ≥ {config.min_severity}</span>
                  {config.max_age_days && <span>Max age: {config.max_age_days}d</span>}
                  {config.last_built_at && (
                    <span>
                      Built {formatDistanceToNow(parseISO(config.last_built_at), { addSuffix: true })}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {previewing && (
        <PreviewModal config={previewing} onClose={() => setPreviewing(null)} />
      )}
    </div>
  );
}
