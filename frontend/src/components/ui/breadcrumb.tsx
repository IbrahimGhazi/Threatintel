import React, { HTMLAttributes, LiHTMLAttributes } from "react";
import clsx from "clsx";

export function Breadcrumb({ className, children, ...props }: HTMLAttributes<HTMLElement>) {
  return (
    <nav aria-label="Breadcrumb" className={clsx("flex items-center", className)} {...props}>
      <ol className="flex items-center gap-1 text-sm">{children}</ol>
    </nav>
  );
}

export function BreadcrumbItem({ className, children, ...props }: LiHTMLAttributes<HTMLLIElement>) {
  return (
    <li className={clsx("flex items-center", className)} {...props}>
      {children}
    </li>
  );
}

export interface BreadcrumbLinkProps extends HTMLAttributes<HTMLElement> {
  asChild?: boolean;
  href?: string;
}

export function BreadcrumbLink({ asChild, href, className, children, ...props }: BreadcrumbLinkProps) {
  const linkClass = clsx("text-text-muted hover:text-text-primary transition-colors", className);

  if (asChild && React.isValidElement(children)) {
    const child = children as React.ReactElement<{ className?: string }>;
    return React.cloneElement(child, {
      className: clsx(linkClass, child.props?.className),
    });
  }

  if (href) {
    return (
      <a href={href} className={linkClass}>
        {children}
      </a>
    );
  }

  return (
    <span className={clsx("text-text-primary font-medium", className)} {...props}>
      {children}
    </span>
  );
}

export function BreadcrumbSeparator({ className, ...props }: HTMLAttributes<HTMLSpanElement>) {
  return (
    <span className={clsx("text-text-muted mx-1 select-none", className)} aria-hidden {...props}>
      /
    </span>
  );
}
