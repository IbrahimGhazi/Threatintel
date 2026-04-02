import clsx from "clsx";

interface LoadingSpinnerProps {
  size?: "sm" | "md" | "lg";
  className?: string;
}

export function LoadingSpinner({ size = "md", className }: LoadingSpinnerProps) {
  return (
    <span
      role="status"
      className={clsx(
        "inline-block rounded-full border-2 border-border border-t-accent animate-spin",
        size === "sm" && "w-3.5 h-3.5",
        size === "md" && "w-5 h-5",
        size === "lg" && "w-8 h-8",
        className,
      )}
    />
  );
}

/** Full-page centered loader */
export function PageLoader() {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <LoadingSpinner size="lg" />
    </div>
  );
}
