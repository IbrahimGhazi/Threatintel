"use client";

import { useState, useRef, useEffect } from "react";
import useSWR from "swr";
import {
  FlaskConical, Upload, Clock, CheckCircle, XCircle,
  AlertTriangle, FileText, ChevronDown, ChevronUp, X,
} from "lucide-react";
import { getSandboxResults, type SandboxResult } from "@/lib/api";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { ProgressTracker } from "@/components/sandbox/ProgressTracker";
import { formatDistanceToNow, parseISO } from "date-fns";
import clsx from "clsx";

const API_KEY = process.env.NEXT_PUBLIC_API_KEY ?? "";

const VERDICT_CONFIG: Record<string, { label: string; className: string; icon: any }> = {
  malicious:  { label: "Malicious",  className: "badge-critical", icon: XCircle },
  suspicious: { label: "Suspicious", className: "badge-high",     icon: AlertTriangle },
  clean:      { label: "Clean",      className: "badge text-status-success bg-status-success/10 border-status-success/30", icon: CheckCircle },
  unknown:    { label: "Unknown",    className: "badge bg-bg-elevated border-border text-text-muted", icon: Clock },
};

const STATUS_LABELS: Record<string, string> = {
  pending:   "Pending",
  running:   "Analyzing",
  completed: "Completed",
  failed:    "Failed",
  timeout:   "Timed Out",
};

interface ActiveAnalysis {
  sha256:    string;
  fileName:  string;
  completed: boolean;
}

export default function SandboxPage() {
  const [uploading, setUploading]           = useState(false);
  const [uploadError, setUploadError]       = useState<string | null>(null);
  const [activeAnalyses, setActiveAnalyses] = useState<ActiveAnalysis[]>(() => {
    try {
      const saved = localStorage.getItem("sandbox:activeAnalyses");
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });
  const [expandedRow, setExpandedRow]       = useState<string | null>(null);
  const [selectedFile, setSelectedFile]     = useState<File | null>(null);
  const [dragOver, setDragOver]             = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    try {
      localStorage.setItem("sandbox:activeAnalyses", JSON.stringify(activeAnalyses));
    } catch { /* storage unavailable */ }
  }, [activeAnalyses]);

  const { data: results, error: resultsError, isLoading, mutate } = useSWR(
    "sandbox-results",
    () => getSandboxResults(),
    { refreshInterval: 10000 }
  );

  // Auto-complete any tracked analysis whose DB record is already done.
  // Handles the case where the SSE stream never fires onDone (e.g. Redis key
  // expired or NATS message was dropped during a container restart).
  useEffect(() => {
    if (!results || results.length === 0) return;
    setActiveAnalyses(prev => {
      let changed = false;
      const next = prev.map(a => {
        if (a.completed) return a;
        const found = results.find(r => r.file_sha256 === a.sha256);
        if (found && (found.status === "completed" || found.status === "failed")) {
          changed = true;
          return { ...a, completed: true };
        }
        return a;
      });
      return changed ? next : prev;
    });
  }, [results]);

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    const file = selectedFile ?? fileRef.current?.files?.[0];
    if (!file) return;

    setUploading(true);
    setUploadError(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("/api/sandbox/submit", {
        method: "POST",
        headers: { "X-API-Key": API_KEY },
        body: formData,
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();

      // Open progress panel for this submission
      setActiveAnalyses(prev => [
        { sha256: data.sha256, fileName: file.name, completed: false },
        ...prev.filter(a => a.sha256 !== data.sha256),
      ]);
      mutate();
    } catch (err: any) {
      setUploadError(err.message ?? "Upload failed");
    } finally {
      setUploading(false);
      setSelectedFile(null);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const handleDone = (sha256: string) => {
    setActiveAnalyses(prev =>
      prev.map(a => a.sha256 === sha256 ? { ...a, completed: true } : a)
    );
    mutate();
  };

  const dismissAnalysis = (sha256: string) => {
    setActiveAnalyses(prev => prev.filter(a => a.sha256 !== sha256));
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Sandbox Analysis</h1>
        <p className="text-sm text-text-muted mt-0.5">
          Submit unknown files for static + behavioral analysis
        </p>
      </div>

      {/* Upload + Active Analyses */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Upload card */}
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-text-primary mb-4">Submit File</h2>
          <form onSubmit={handleUpload}>
            <div
              className={clsx(
                "border-2 border-dashed rounded-lg p-8 text-center mb-4 cursor-pointer transition-colors",
                dragOver
                  ? "border-accent bg-accent/5"
                  : "border-border hover:border-accent/50"
              )}
              onClick={() => fileRef.current?.click()}
              onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); setDragOver(true); }}
              onDragLeave={(e) => { e.preventDefault(); e.stopPropagation(); setDragOver(false); }}
              onDrop={(e) => {
                e.preventDefault();
                e.stopPropagation();
                setDragOver(false);
                const file = e.dataTransfer.files?.[0];
                if (file) setSelectedFile(file);
              }}
            >
              <Upload className="w-8 h-8 text-text-muted mx-auto mb-3" />
              {selectedFile ? (
                <>
                  <p className="text-sm text-text-primary font-medium truncate px-2">{selectedFile.name}</p>
                  <p className="text-xs text-text-muted mt-1">
                    {(selectedFile.size / 1024).toFixed(1)} KB — click to change
                  </p>
                </>
              ) : (
                <>
                  <p className="text-sm text-text-secondary">Click to select a file, or drag and drop</p>
                  <p className="text-xs text-text-muted mt-1">
                    Max 50MB — executables, documents, archives, scripts
                  </p>
                </>
              )}
              <input
                ref={fileRef}
                type="file"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) setSelectedFile(file);
                }}
              />
            </div>

            {uploadError && (
              <div className="mb-4 p-3 rounded-md bg-severity-high/10 border border-severity-high/25">
                <p className="text-xs text-severity-high">{uploadError}</p>
              </div>
            )}

            <button type="submit" className="btn-primary w-full justify-center" disabled={uploading}>
              {uploading
                ? <><LoadingSpinner size="sm" /> Uploading…</>
                : <><FlaskConical className="w-4 h-4" /> Submit for Analysis</>}
            </button>
          </form>
        </div>

        {/* Active progress panels */}
        <div className="space-y-3">
          {activeAnalyses.length === 0 ? (
            <div className="card p-5 flex flex-col items-center justify-center h-full text-center min-h-[200px]">
              <FlaskConical className="w-8 h-8 text-text-muted mb-3" />
              <p className="text-sm text-text-muted">
                Submit a file to see the real-time analysis pipeline
              </p>
            </div>
          ) : (
            activeAnalyses.map(analysis => (
              <div key={analysis.sha256} className={clsx(
                "card p-4 border",
                analysis.completed ? "border-status-success/30" : "border-accent/30"
              )}>
                {/* Panel header */}
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2 min-w-0">
                    <FileText className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
                    <span className="text-xs font-medium text-text-primary truncate">
                      {analysis.fileName}
                    </span>
                  </div>
                  <button
                    onClick={() => dismissAnalysis(analysis.sha256)}
                    className="text-text-muted hover:text-text-primary flex-shrink-0 ml-2"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>

                <ProgressTracker
                  sha256={analysis.sha256}
                  onDone={(status) => handleDone(analysis.sha256)}
                />
              </div>
            ))
          )}
        </div>
      </div>

      {/* Results table */}
      <div className="card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <h2 className="text-sm font-semibold text-text-primary">Analysis History</h2>
        </div>
        {resultsError && (
          <div className="px-5 py-3 text-xs text-severity-high bg-severity-high/10 border-b border-severity-high/25">
            Failed to load results: {resultsError?.message ?? "Unknown error"}
          </div>
        )}
        {isLoading ? (
          <div className="flex items-center justify-center py-16"><LoadingSpinner /></div>
        ) : (
          <table className="ti-table">
            <thead>
              <tr>
                <th>File</th>
                <th>SHA256</th>
                <th>Status</th>
                <th>Verdict</th>
                <th>Score</th>
                <th>IOCs</th>
                <th>Submitted</th>
              </tr>
            </thead>
            <tbody>
              {(results ?? []).map((r: SandboxResult) => {
                const vConfig = r.verdict ? VERDICT_CONFIG[r.verdict] ?? VERDICT_CONFIG.unknown : VERDICT_CONFIG.unknown;
                const VIcon   = vConfig.icon;
                const iocCount = Object.values(r.extracted_iocs ?? {}).reduce<number>(
                  (s, v) => s + (Array.isArray(v) ? (v as unknown[]).length : 0), 0
                );
                const isExpanded = expandedRow === r.id;

                return [
                  <tr
                    key={r.id}
                    className="cursor-pointer hover:bg-bg-elevated/50"
                    onClick={() => setExpandedRow(isExpanded ? null : r.id)}
                  >
                    <td>
                      <div className="flex items-center gap-2">
                        <FileText className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
                        <span className="text-xs text-text-primary">{r.file_name ?? "Unknown"}</span>
                      </div>
                    </td>
                    <td>
                      <span className="mono-value text-2xs" title={r.file_sha256}>
                        {r.file_sha256.slice(0, 16)}…
                      </span>
                    </td>
                    <td>
                      <span className="text-xs text-text-secondary">
                        {STATUS_LABELS[r.status] ?? r.status}
                      </span>
                    </td>
                    <td>
                      {r.verdict ? (
                        <span className={vConfig.className}>
                          <VIcon className="w-3 h-3" />{vConfig.label}
                        </span>
                      ) : <span className="text-xs text-text-muted">—</span>}
                    </td>
                    <td>
                      {r.malware_score != null ? (
                        <span className={clsx(
                          "text-xs font-mono font-semibold",
                          r.malware_score >= 70 ? "text-severity-critical" :
                          r.malware_score >= 40 ? "text-severity-high" : "text-status-success"
                        )}>
                          {r.malware_score}/100
                        </span>
                      ) : <span className="text-xs text-text-muted">—</span>}
                    </td>
                    <td>
                      <span className={clsx("text-xs font-mono", iocCount > 0 ? "text-severity-high" : "text-text-muted")}>
                        {iocCount > 0 ? iocCount : "—"}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-1">
                        <span className="text-xs text-text-muted">
                          {formatDistanceToNow(parseISO(r.submitted_at), { addSuffix: true })}
                        </span>
                        {isExpanded ? <ChevronUp className="w-3 h-3 text-text-muted" /> : <ChevronDown className="w-3 h-3 text-text-muted" />}
                      </div>
                    </td>
                  </tr>,

                  // Expanded detail row
                  isExpanded && (
                    <tr key={`${r.id}-detail`}>
                      <td colSpan={7} className="bg-bg-elevated/50 px-5 py-4">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">

                          {/* IOCs */}
                          <div>
                            <p className="text-text-muted font-semibold uppercase tracking-wide mb-2 text-2xs">
                              Extracted IOCs
                            </p>
                            {Object.entries(r.extracted_iocs ?? {}).map(([type, values]) =>
                              Array.isArray(values) && values.length > 0 ? (
                                <div key={type} className="mb-2">
                                  <span className="text-text-muted uppercase text-2xs font-mono">{type}: </span>
                                  <div className="mt-0.5 space-y-0.5">
                                    {(values as string[]).slice(0, 5).map((v) => (
                                      <div key={v} className="font-mono text-2xs text-text-secondary truncate">
                                        {v}
                                      </div>
                                    ))}
                                    {values.length > 5 && (
                                      <div className="text-2xs text-text-muted">
                                        +{values.length - 5} more
                                      </div>
                                    )}
                                  </div>
                                </div>
                              ) : null
                            )}
                            {iocCount === 0 && (
                              <p className="text-text-muted">No IOCs extracted</p>
                            )}
                          </div>

                          {/* File info */}
                          <div>
                            <p className="text-text-muted font-semibold uppercase tracking-wide mb-2 text-2xs">
                              File Details
                            </p>
                            <div className="space-y-1">
                              <div><span className="text-text-muted">Type: </span><span className="font-mono">{r.file_type ?? "—"}</span></div>
                              <div><span className="text-text-muted">Size: </span><span className="font-mono">{r.file_size ? `${(r.file_size / 1024).toFixed(1)} KB` : "—"}</span></div>
                              <div><span className="text-text-muted">Engine: </span><span className="font-mono">{r.sandbox_engine}</span></div>
                              {r.malware_family && (
                                <div><span className="text-text-muted">Family: </span><span className="font-mono text-severity-high">{r.malware_family}</span></div>
                              )}
                            </div>
                          </div>

                          {/* Hashes */}
                          <div>
                            <p className="text-text-muted font-semibold uppercase tracking-wide mb-2 text-2xs">
                              Hashes
                            </p>
                            <div className="space-y-1">
                              <div><span className="text-text-muted">SHA256: </span><span className="font-mono text-2xs break-all">{r.file_sha256}</span></div>
                            </div>
                            {r.error && (
                              <div className="mt-2 p-2 rounded bg-severity-critical/10 border border-severity-critical/20">
                                <p className="text-severity-critical text-2xs">{r.error}</p>
                              </div>
                            )}
                          </div>
                        </div>
                      </td>
                    </tr>
                  ),
                ].filter(Boolean);
              })}
              {(results ?? []).length === 0 && (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-text-muted text-sm">
                    No sandbox results yet
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
