// @ts-nocheck
"use client";
/**
 * Dashboard – main SOC overview page.
 * Shows key metrics, recent alerts, feed status, and ingestion timeline.
 */
import {
  Shield, Bell, RadioTower,
  TrendingUp, XCircle,
} from "lucide-react";
import useSWR from "swr";
import { getDashboardStats } from "@/lib/api";
import { StatCard } from "@/components/ui/StatCard";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { PageLoader } from "@/components/ui/LoadingSpinner";
import { IngestionTimeline } from "@/components/charts/IngestionTimeline";
import { SeverityDonut } from "@/components/charts/SeverityDonut";
import Link from "next/link";

// ── Page ──────────────────────────────────────────────────────

export default function DashboardPage() {
  const { data: stats, error, isLoading } = useSWR("dashboard-stats", getDashboardStats, {
    refreshInterval: 30_000,
  });

  if (isLoading) return <PageLoader />;

  if (error || !stats) {
    return (
      <div className="card p-8 text-center">
        <XCircle className="w-8 h-8 text-severity-critical mx-auto mb-3" />
        <p className="text-text-secondary">Could not connect to the API server.</p>
        <p className="text-xs text-text-muted mt-1">
          Ensure the platform is running and the API key is configured.
        </p>
      </div>
    );
  }

  const { indicators, alerts, feeds, top_tags, ingestion_timeline } = stats;
  const openAlerts = alerts.by_status?.open ?? 0;
  const criticalAlerts = alerts.by_severity?.critical ?? 0;
  const healthyFeeds = feeds.filter((f: any) => f.status === "healthy").length;

  return (
    <div className="space-y-6">

      {/* ── Header ──────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text-primary">Threat Intelligence Overview</h1>
          <p className="text-sm text-text-muted mt-0.5">
            Real-time threat landscape for your environment
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-text-muted">
          <div className="status-dot bg-status-success animate-pulse-slow" />
          Live
        </div>
      </div>

      {/* ── KPI Row ─────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Active Indicators"
          value={indicators.active}
          icon={Shield}
          subtitle={`${indicators.recent_24h.toLocaleString()} ingested (24h)`}
          accent="default"
        />
        <StatCard
          label="Open Alerts"
          value={openAlerts}
          icon={Bell}
          subtitle={`${criticalAlerts} critical`}
          accent={criticalAlerts > 0 ? "critical" : openAlerts > 0 ? "high" : "success"}
        />
        <StatCard
          label="Active Feeds"
          value={`${healthyFeeds}/${feeds.length}`}
          icon={RadioTower}
          subtitle={feeds.filter((f: any) => f.status === "degraded").length + " degraded"}
          accent={healthyFeeds === feeds.length ? "success" : "medium"}
        />
        <StatCard
          label="Total Ingested"
          value={indicators.total}
          icon={TrendingUp}
          subtitle="All time indicators"
          accent="default"
        />
      </div>

      {/* ── Charts Row ──────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Ingestion Timeline */}
        <div className="lg:col-span-2 card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-text-primary">Ingestion Timeline</h2>
            <span className="text-2xs text-text-muted">Last 14 days</span>
          </div>
          <div className="h-48">
            <IngestionTimeline data={ingestion_timeline} />
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-text-primary">By Severity</h2>
            <Link href="/indicators" className="text-2xs text-accent hover:underline">View all</Link>
          </div>
          <div className="h-40">
            <SeverityDonut data={indicators.by_severity} />
          </div>
          {/* Legend */}
          <div className="mt-3 space-y-1">
            {Object.entries(indicators.by_severity)
              .sort(([a], [b]) => {
                const order = ["critical", "high", "medium", "low", "info"];
                return order.indexOf(a) - order.indexOf(b);
              })
              .map(([sev, count]) => (
                <div key={sev} className="flex items-center justify-between">
                  <SeverityBadge severity={sev} />
                  <span className="text-xs text-text-muted font-mono">{(count as number).toLocaleString()}</span>
                </div>
              ))}
          </div>
        </div>
      </div>

      {/* ── Bottom Row ──────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Feed Status */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-text-primary">Feed Status</h2>
            <Link href="/feeds" className="text-2xs text-accent hover:underline">Manage</Link>
          </div>
          <ul className="space-y-2.5">
            {feeds.map((feed: any) => (
              <li key={feed.name} className="flex items-center gap-3">
                <div className={`status-dot flex-shrink-0 ${
                  feed.status === "healthy" ? "bg-status-success" :
                  feed.status === "degraded" ? "bg-status-warning" :
                  "bg-text-muted"
                }`} />
                <span className="text-sm text-text-secondary flex-1 truncate">{feed.name}</span>
                <span className="text-2xs text-text-muted font-mono">
                  {feed.total_ingested.toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        </div>

        {/* Top Tags */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-text-primary">Top Threat Tags</h2>
          </div>
          <ul className="space-y-2">
            {top_tags.slice(0, 8).map(({ tag, count }: { tag: string; count: number }) => (
              <li key={tag} className="flex items-center gap-2">
                <span className="badge bg-bg-elevated border-border text-text-secondary flex-1 truncate">
                  {tag}
                </span>
                <span className="text-2xs text-text-muted font-mono flex-shrink-0">
                  {count.toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        </div>

        {/* Type Distribution */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-text-primary">Indicator Types</h2>
          </div>
          <ul className="space-y-2.5">
            {Object.entries(indicators.by_type)
              .sort(([, a], [, b]) => (b as number) - (a as number))
              .map(([type, count]) => {
                const total = indicators.active || 1;
                const pct = Math.round(((count as number) / total) * 100);
                return (
                  <li key={type}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-text-secondary uppercase tracking-wide font-mono">
                        {type}
                      </span>
                      <span className="text-xs text-text-muted font-mono">
                        {(count as number).toLocaleString()}
                      </span>
                    </div>
                    <div className="h-1.5 bg-bg-elevated rounded-full overflow-hidden">
                      <div
                        className="h-full bg-accent/60 rounded-full transition-all"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </li>
                );
              })}
          </ul>
        </div>
      </div>
    </div>
  );
}