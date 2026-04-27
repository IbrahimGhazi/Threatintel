import React, { ButtonHTMLAttributes } from "react";
import clsx from "clsx";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "ghost" | "secondary" | "outline" | "link" | "destructive";
  size?: "sm" | "md" | "lg";
  asChild?: boolean;
}

const VARIANT_CLASSES: Record<NonNullable<ButtonProps["variant"]>, string> = {
  default:     "btn btn-primary",
  ghost:       "btn btn-ghost",
  secondary:   "btn bg-bg-elevated border border-border text-text-secondary hover:bg-bg-base",
  outline:     "btn border border-border text-text-secondary hover:bg-bg-elevated",
  link:        "text-accent underline-offset-4 hover:underline bg-transparent border-0 p-0 h-auto cursor-pointer",
  destructive: "btn bg-severity-critical/15 text-severity-critical border border-severity-critical/30 hover:bg-severity-critical/25",
};

const SIZE_CLASSES: Record<NonNullable<ButtonProps["size"]>, string> = {
  sm: "text-xs px-2 py-1 h-auto",
  md: "text-sm px-3 py-2",
  lg: "text-base px-4 py-2.5",
};

export function Button({
  variant = "default",
  size = "md",
  asChild = false,
  className,
  children,
  ...props
}: ButtonProps) {
  const classes = clsx(VARIANT_CLASSES[variant], SIZE_CLASSES[size], className);

  if (asChild && React.isValidElement(children)) {
    const child = children as React.ReactElement<{ className?: string }>;
    return React.cloneElement(child, {
      className: clsx(classes, child.props?.className),
    });
  }

  return (
    <button className={classes} {...props}>
      {children}
    </button>
  );
}
