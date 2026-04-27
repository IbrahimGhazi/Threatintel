"use client";

import { useEffect, useRef, useState } from "react";
import {
  Upload, Clock, Search, Server, Activity,
  FastForward, Target, FileText, CheckCircle,
  XCircle, Loader2, SkipForward,
} from "lucide-react";
import clsx from "clsx";

const API_KEY = process.env.NEXT_PUBLIC_API_KEY ?? "";

// ── Stage metadata ─────────────────────────────────────────────────────────────

const STAGE_META: Record<string, { label: string; Icon: any }> = {
  file_received:     { label: "File Received",            Icon: Upload },
  queued:            { label: "Queue Waiting",            Icon: Clock },
  static_analysis:   { label: "Static Analysis",          Icon: Search },
  sandbox_prep:      { label: "Sandbox Preparation",      Icon: Server },
  behavioral_exec:   { label: "Behavioral Execution",     Icon: Activity },
  time_manipulation: { label: "Time-Manipulation Tests",  Icon: FastForward },
  ioc_extraction:    { label: "IOC Extraction",           Icon: Target },
  report_generation: { label: "Report Generation",        Icon: FileText },
};

const STAGE_ORDER = Object.keys(STAGE_META);

type StageStatus = "pending" | "running" | "done" | "failed" | "skipped";

interface Stage {
  id:          string;
  label:       string;
  status:      StageStatus;
  started_at:  string | null;
  duration_ms: number | null;
}

interface ProgressData {
  sha256:            string;
  overall_status:    "queued" | "running" | "completed" | "failed";
  current_stage:     string | null;
  completed_stages:  string[];
  stages:            Stage[];
  started_at:        string;
  updated_at:        string;
  error:             string;
}

interface Props {
  sha256:  string;
  onDone?: (overall: string) => void;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Build a full stage list from the server payload, filling in any gaps. */
function buildStages(data: ProgressData): Stage[] {
  if (data.stages && data.stages.length > 0) {
    return data.stages;
  }
  // Fallback: build from overall_status + completed_stages
  return STAGE_ORDER.map((id) => ({
    id,
    label:       STAGE_META[id]?.label ?? id,
    status:      data.completed_stages?.includes(id) ? "done"
                 : data.current_stage === id          ? "running"
                 : "pending",
    started_at:  null,
    duration_ms: null,
  }));
}

// ── Component ─────────────────────────────────────────────────────────────────

export function ProgressTracker({ sha256, onDone }: Props) {
  const [data, setData]   = useState<ProgressData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const esRef        = useRef<EventSource | null>(null);
  const tickRef      = useRef<ReturnType<typeof setInterval> | null>(null);
  const fallbackRef  = useRef<ReturnType<typeof setTimeout> | null>(null);
  const startRef     = useRef<number | null>(null);

  // Seed the start time from server data so elapsed survives page reloads
  useEffect(() => {
    if (data?.started_at && !startRef.current) {
      const serverStart = new Date(data.started_at).getTime();
      if (!isNaN(serverStart)) {
        startRef.current = serverStart;
        setElapsed(Math.max(0, Math.floor((Date.now() - serverStart) / 1000)));
      }
    }
  }, [data?.started_at]);

  // Elapsed-time ticker
  useEffect(() => {
    tickRef.current = setInterval(() => {
      if (startRef.current) {
        setElapsed(Math.max(0, Math.floor((Date.now() - startRef.current) / 1000)));
      } else {
        setElapsed(s => s + 1);
      }
    }, 1000);
    return () => { if (tickRef.current) clearInterval(tickRef.current); };
  }, []);

  // REST fallback: if still queued/running after 60 s without the SSE
  // transitioning to a terminal state, poll the hash endpoint directly.
  // - completed/failed  → synthesise terminal state and call onDone
  // - pending/running   → NATS message was lost; call the requeue endpoint
  //                       so the worker picks it up and progress resumes
  useEffect(() => {
    if (fallbackRef.current) clearTimeout(fallbackRef.current);
    fallbackRef.current = setTimeout(async () => {
      if (!esRef.current) return; // SSE already closed (completed normally)
      try {
        const res = await fetch(`/api/sandbox/hash/${sha256}`, {
          headers: { "X-API-Key": API_KEY },
        });
        if (!res.ok) return;
        const result = await res.json();
        if (result.status === "completed" || result.status === "failed") {
          esRef.current?.close();
          // Synthesise a terminal progress payload so the UI renders correctly.
          setData(prev => ({
            sha256,
            overall_status: result.status,
            current_stage: null,
            completed_stages: prev?.completed_stages ?? [],
            stages: prev?.stages ?? [],
            started_at: prev?.started_at ?? new Date().toISOString(),
            updated_at: new Date().toISOString(),
            error: result.error ?? "",
          }));
          onDone?.(result.status);
        } else if (result.status === "pending" || result.status === "running") {
          // NATS message was dropped or worker restarted — re-queue the job.
          // The SSE stream will automatically pick up the new Redis progress
          // once the worker starts processing.
          await fetch(`/api/sandbox/${sha256}/requeue`, {
            method: "POST",
            headers: { "X-API-Key": API_KEY },
          }).catch(() => { /* best-effort */ });
        }
      } catch { /* ignore */ }
    }, 60_000);
    return () => { if (fallbackRef.current) clearTimeout(fallbackRef.current); };
  }, [sha256]);

  // SSE connection
  useEffect(() => {
    if (!sha256) return;

    const es = new EventSource(
      `/api/sandbox/${sha256}/progress?api_key=${API_KEY}`,
    );
    esRef.current = es;

    es.onmessage = (e) => {
      try {
        const parsed: ProgressData = JSON.parse(e.data);
        setData(parsed);
        if (parsed.overall_status === "completed" || parsed.overall_status === "failed") {
          es.close();
          if (fallbackRef.current) { clearTimeout(fallbackRef.current); fallbackRef.current = null; }
          onDone?.(parsed.overall_status);
        }
      } catch {
        /* ignore parse errors */
      }
    };

    es.onerror = () => {
      setError("Lost connection to progress stream");
      es.close();
    };

    return () => { es.close(); };
  }, [sha256]);

  // ── Loading skeleton ──────────────────────────────────────────────────────
  if (!data) {
    if (error) {
      return (
        <div className="p-3 rounded-md bg-severity-high/10 border border-severity-high/25 text-xs text-severity-high">
          {error}
        </div>
      );
    }
    return (
      <div className="flex items-center gap-2 py-4 text-text-muted text-sm">
        <Loader2 className="w-4 h-4 animate-spin" />
        Connecting to analysis pipeline…
      </div>
    );
  }

  const overall = data.overall_status;
  const stages  = buildStages(data);

  // Current stage label for the header subtitle
  const currentStageMeta = data.current_stage ? STAGE_META[data.current_stage] : null;

  return (
    <div className="space-y-3">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-2">
          {overall === "running" || overall === "queued" ? (
            <Loader2 className="w-4 h-4 text-accent animate-spin mt-0.5 flex-shrink-0" />
          ) : overall === "completed" ? (
            <CheckCircle className="w-4 h-4 text-status-success mt-0.5 flex-shrink-0" />
          ) : (
            <XCircle className="w-4 h-4 text-severity-critical mt-0.5 flex-shrink-0" />
          )}
          <div>
            <span className="text-sm font-semibold text-text-primary">
              {overall === "queued"    ? "Queued for Analysis" :
               overall === "running"  ? "Analyzing…" :
               overall === "completed"? "Analysis Complete" :
                                        "Analysis Failed"}
            </span>
            {/* Current stage subtitle */}
            {overall === "running" && currentStageMeta && (
              <p className="text-xs text-accent mt-0.5">
                {currentStageMeta.label}
              </p>
            )}
          </div>
        </div>

        {/* Elapsed time */}
        {overall !== "completed" && overall !== "failed" && elapsed > 0 && (
          <span className="text-xs text-text-muted font-mono flex-shrink-0 ml-2 mt-0.5">
            {elapsed >= 60
              ? `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`
              : `${elapsed}s`}
          </span>
        )}
      </div>

      {/* ── SHA256 chip ─────────────────────────────────────────────────────── */}
      <div className="font-mono text-2xs text-text-muted break-all bg-bg-elevated
                      rounded px-2 py-1 border border-border">
        {sha256}
      </div>

      {/* ── Pipeline timeline ───────────────────────────────────────────────── */}
      <div className="space-y-0">
        {stages.map((stage, idx) => {
          const meta   = STAGE_META[stage.id];
          const Icon   = meta?.Icon ?? FileText;
          const isLast = idx === stages.length - 1;

          return (
            <div key={stage.id} className="flex items-start gap-3">

              {/* Connector + status bubble */}
              <div className="flex flex-col items-center flex-shrink-0">
                <div className={clsx(
                  "w-7 h-7 rounded-full border-2 flex items-center justify-center flex-shrink-0",
                  stage.status === "done"    && "bg-status-success/20 border-status-success",
                  stage.status === "running" && "bg-accent/20 border-accent",
                  stage.status === "failed"  && "bg-severity-critical/20 border-severity-critical",
                  stage.status === "skipped" && "bg-bg-elevated border-border/50",
                  stage.status === "pending" && "bg-bg-elevated border-border",
                )}>
                  {stage.status === "running" ? (
                    <Loader2 className="w-3.5 h-3.5 text-accent animate-spin" />
                  ) : stage.status === "done" ? (
                    <CheckCircle className="w-3.5 h-3.5 text-status-success" />
                  ) : stage.status === "failed" ? (
                    <XCircle className="w-3.5 h-3.5 text-severity-critical" />
                  ) : stage.status === "skipped" ? (
                    <SkipForward className="w-3.5 h-3.5 text-text-muted" />
                  ) : (
                    <Icon className="w-3.5 h-3.5 text-text-muted" />
                  )}
                </div>
                {!isLast && (
                  <div className={clsx(
                    "w-0.5 h-5 mt-0.5 transition-colors duration-500",
                    stage.status === "done"    ? "bg-status-success/40" :
                    stage.status === "running" ? "bg-accent/40 animate-pulse" :
                    "bg-border"
                  )} />
                )}
              </div>

              {/* Stage label + duration */}
              <div className="pb-4 min-w-0 flex-1 flex items-center justify-between">
                <span className={clsx(
                  "text-sm font-medium leading-7",
                  stage.status === "done"    && "text-text-primary",
                  stage.status === "running" && "text-accent",
                  stage.status === "failed"  && "text-severity-critical",
                  stage.status === "skipped" && "text-text-muted line-through",
                  stage.status === "pending" && "text-text-muted",
                )}>
                  {meta?.label ?? stage.label}
                </span>

                <span className="text-2xs font-mono text-text-muted flex-shrink-0 ml-2">
                  {stage.status === "done" && stage.duration_ms != null ? (
                    stage.duration_ms < 1000
                      ? `${stage.duration_ms}ms`
                      : `${(stage.duration_ms / 1000).toFixed(1)}s`
                  ) : stage.status === "running" ? (
                    <span className="text-accent animate-pulse">running…</span>
                  ) : stage.status === "skipped" ? (
                    "skipped"
                  ) : null}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Error message ───────────────────────────────────────────────────── */}
      {data.error && (
        <div className="p-3 rounded-md bg-severity-critical/10 border border-severity-critical/25
                        text-xs text-severity-critical">
          {data.error}
        </div>
      )}

      {/* ── SSE connection error ────────────────────────────────────────────── */}
      {error && (
        <div className="p-3 rounded-md bg-severity-high/10 border border-severity-high/25
                        text-xs text-severity-high">
          {error}
        </div>
      )}
    </div>
  );
}
