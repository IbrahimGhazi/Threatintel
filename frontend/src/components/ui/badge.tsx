import clsx from "clsx";
import type { HTMLAttributes } from "react";

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: "default" | "secondary" | "outline" | "ghost" | "destructive";
}

export function Badge({ className, variant = "default", ...props }: BadgeProps) {
  return (
    <span
      className={clsx(
        "badge",
        variant === "default"     && "bg-accent/10 text-accent border border-accent/25",
        variant === "secondary"   && "bg-bg-elevated text-text-secondary border border-border",
        variant === "outline"     && "bg-transparent border border-border text-text-secondary",
        variant === "ghost"       && "bg-bg-elevated/60 text-text-muted",
        variant === "destructive" && "bg-severity-critical/10 text-severity-critical border border-severity-critical/25",
        className,
      )}
      {...props}
    />
  );
}
