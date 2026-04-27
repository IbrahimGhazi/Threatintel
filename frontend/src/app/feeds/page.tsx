"use client";

import useSWR from "swr";
import { RadioTower, CheckCircle, XCircle, Clock, AlertTriangle, ToggleLeft, ToggleRight } from "lucide-react";
import { getFeeds, updateFeed, type Feed } from "@/lib/api";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { formatDistanceToNow, parseISO } from "date-fns";
import clsx from "clsx";

export default function FeedsPage() {
  const { data: feeds, isLoading, error, mutate } = useSWR("feeds", getFeeds, { refreshInterval: 30000 });

  const toggleFeed = async (feed: Feed) => {
    await updateFeed(feed.id, { enabled: !feed.enabled });
    mutate();
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Threat Feeds</h1>
        <p className="text-sm text-text-muted mt-0.5">
          Manage open-source and commercial threat intelligence feed sources
        </p>
      </div>

      {isLoading ? (
        <div className="card flex items-center justify-center py-16"><LoadingSpinner /></div>
      ) : error ? (
        <div className="card flex items-center justify-center py-16 gap-2 text-sm text-text-muted">
          <AlertTriangle className="w-4 h-4 text-severity-high" />
          Failed to load feeds
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {(feeds ?? []).map((feed: Feed) => {
            const isHealthy = !!feed.last_success_at;
            const hasError  = !!feed.last_error;

            return (
              <div key={feed.id} className={clsx(
                "card p-5 border-l-2",
                !feed.enabled           ? "border-l-border opacity-60" :
                hasError && !isHealthy  ? "border-l-severity-high" :
                isHealthy               ? "border-l-status-success" :
                                          "border-l-text-muted"
              )}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1">
                      <div className="w-8 h-8 rounded-lg bg-accent/15 border border-accent/25
                                      flex items-center justify-center text-xs font-bold text-accent">
                        {feed.name.slice(0, 2).toUpperCase()}
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold text-text-primary">{feed.display_name}</h3>
                        <p className="text-2xs text-text-muted font-mono">{feed.name}</p>
                      </div>
                    </div>

                    {feed.description && (
                      <p className="text-xs text-text-muted mt-2">{feed.description}</p>
                    )}

                    <div className="grid grid-cols-2 gap-x-4 gap-y-2 mt-3">
                      <div>
                        <p className="text-2xs text-text-muted uppercase tracking-wide">Indicators</p>
                        <p className="text-sm font-semibold text-text-primary font-mono">
                          {feed.total_ingested.toLocaleString()}
                        </p>
                      </div>
                      <div>
                        <p className="text-2xs text-text-muted uppercase tracking-wide">Interval</p>
                        <p className="text-sm font-semibold text-text-primary">
                          {feed.poll_interval >= 3600
                            ? `${feed.poll_interval / 3600}h`
                            : `${feed.poll_interval / 60}m`}
                        </p>
                      </div>
                      <div>
                        <p className="text-2xs text-text-muted uppercase tracking-wide">Status</p>
                        <div className="flex items-center gap-1.5 mt-0.5">
                          {!feed.enabled ? (
                            <span className="badge bg-bg-elevated border-border text-text-muted">Disabled</span>
                          ) : isHealthy ? (
                            <span className="badge bg-status-success/15 border-status-success/30 text-status-success">
                              <CheckCircle className="w-3 h-3" /> Healthy
                            </span>
                          ) : hasError ? (
                            <span className="badge bg-severity-high/15 border-severity-high/30 text-severity-high">
                              <XCircle className="w-3 h-3" /> Error
                            </span>
                          ) : (
                            <span className="badge bg-bg-elevated border-border text-text-muted">Pending</span>
                          )}
                        </div>
                      </div>
                      <div>
                        <p className="text-2xs text-text-muted uppercase tracking-wide">Last Run</p>
                        <p className="text-xs text-text-secondary mt-0.5">
                          {feed.last_run_at
                            ? formatDistanceToNow(parseISO(feed.last_run_at), { addSuffix: true })
                            : "Never"}
                        </p>
                      </div>
                    </div>

                    {feed.last_error && (
                      <div className="mt-3 p-2.5 rounded bg-severity-high/10 border border-severity-high/25">
                        <p className="text-2xs text-severity-high">
                          <AlertTriangle className="w-3 h-3 inline mr-1" />
                          {feed.last_error}
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Toggle */}
                  <button
                    onClick={() => toggleFeed(feed)}
                    className="flex-shrink-0 p-1 text-text-muted hover:text-text-primary transition-colors"
                    title={feed.enabled ? "Disable feed" : "Enable feed"}
                  >
                    {feed.enabled ? (
                      <ToggleRight className="w-6 h-6 text-accent" />
                    ) : (
                      <ToggleLeft className="w-6 h-6" />
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
