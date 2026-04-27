import clsx from "clsx";

interface SeparatorProps {
  orientation?: "horizontal" | "vertical";
  className?: string;
}

export function Separator({ orientation = "horizontal", className }: SeparatorProps) {
  if (orientation === "vertical") {
    return <div className={clsx("w-px bg-border self-stretch", className)} aria-hidden />;
  }
  return <div className={clsx("h-px w-full bg-border", className)} aria-hidden />;
}
