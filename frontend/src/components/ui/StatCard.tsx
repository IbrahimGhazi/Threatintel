import { LucideIcon } from "lucide-react";
import clsx from "clsx";

interface StatCardProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  change?: string;
  changePositive?: boolean;
  accent?: "default" | "critical" | "high" | "medium" | "success";
  subtitle?: string;
}

const ACCENT_CLASSES = {
  default:  "text-accent border-accent/25 bg-accent/10",
  critical: "text-severity-critical border-severity-critical/25 bg-severity-critical/10",
  high:     "text-severity-high border-severity-high/25 bg-severity-high/10",
  medium:   "text-severity-medium border-severity-medium/25 bg-severity-medium/10",
  success:  "text-status-success border-status-success/25 bg-status-success/10",
};

export function StatCard({
  label, value, icon: Icon, change, changePositive, accent = "default", subtitle,
}: StatCardProps) {
  const accentClass = ACCENT_CLASSES[accent];

  return (
    <div className="stat-card flex items-start gap-4">
      <div className={clsx("flex-shrink-0 w-10 h-10 rounded-lg border flex items-center justify-center", accentClass)}>
        <Icon className="w-5 h-5" strokeWidth={1.75} />
      </div>

      <div className="flex-1 min-w-0">
        <p className="text-2xs text-text-muted uppercase tracking-wider font-semibold">{label}</p>
        <p className="text-2xl font-bold text-text-primary mt-0.5 font-mono tabular-nums">
          {typeof value === "number" ? value.toLocaleString() : value}
        </p>
        {subtitle && (
          <p className="text-xs text-text-muted mt-0.5">{subtitle}</p>
        )}
        {change && (
          <p className={clsx("text-xs mt-1", changePositive ? "text-status-success" : "text-severity-high")}>
            {change}
          </p>
        )}
      </div>
    </div>
  );
}
