import clsx from "clsx";
import type { Severity } from "@/lib/api";

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

const CONFIG: Record<string, string> = {
  critical: "badge-critical",
  high:     "badge-high",
  medium:   "badge-medium",
  low:      "badge-low",
  info:     "badge-info",
};

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const cls = CONFIG[severity?.toLowerCase()] ?? "badge-info";
  return (
    <span className={clsx(cls, className)}>
      {severity?.toUpperCase()}
    </span>
  );
}
