import { Activity, Network, Server, ShieldAlert } from "lucide-react";
import type { AlertContext } from "@/lib/api";
import { StatCard } from "@/components/ui/StatCard";

interface IncidentSummaryCardsProps {
  context?: AlertContext | Record<string, unknown>;
  alertSeverity: string;
}

function getAffectedHosts(context?: AlertContext | Record<string, unknown>) {
  const hosts = Array.isArray(context?.affected_hosts)
    ? context.affected_hosts.filter((item): item is string => typeof item === "string" && item.length > 0)
    : [];

  if (hosts.length > 0) return hosts;
  if (typeof context?.affected_host === "string" && context.affected_host.length > 0) {
    return [context.affected_host];
  }

  return [];
}

export function IncidentSummaryCards({
  context,
  alertSeverity,
}: IncidentSummaryCardsProps) {
  const affectedHosts = getAffectedHosts(context);
  const eventCount = typeof context?.event_count === "number" ? context.event_count : 0;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      <StatCard
        label="Attack Type"
        value={context?.attack_type && typeof context.attack_type === "string" ? context.attack_type : "Correlated incident"}
        icon={ShieldAlert}
        subtitle="Detection grouping"
        accent={alertSeverity === "critical" ? "critical" : alertSeverity === "high" ? "high" : "medium"}
      />
      <StatCard
        label="Events Correlated"
        value={eventCount}
        icon={Activity}
        subtitle={
          context?.time_window && typeof context.time_window === "object" && "duration_seconds" in context.time_window
            ? `${((context.time_window as { duration_seconds: number }).duration_seconds / 60) | 0}m window`
            : typeof context?.time_window === "string"
            ? context.time_window
            : "Detection window"
        }
        accent="default"
      />
      <StatCard
        label="Source IP"
        value={typeof context?.source_ip === "string" ? context.source_ip : "Unknown"}
        icon={Network}
        subtitle={typeof context?.destination_ip === "string" ? `Target ${context.destination_ip}` : "Target unavailable"}
        accent="default"
      />
      <StatCard
        label="Affected Hosts"
        value={affectedHosts.length}
        icon={Server}
        subtitle={affectedHosts.slice(0, 2).join(", ") || "No hostnames provided"}
        accent="success"
      />
    </div>
  );
}