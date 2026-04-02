"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  ShieldAlert,
  FileSearch,
  Globe,
  Layers,
  Filter,
  List,
  Settings,
  Cpu,
  Sliders,
  BookOpen,
} from "lucide-react";
import clsx from "clsx";

const NAV_ITEMS = [
  { href: "/",           label: "Dashboard",    icon: LayoutDashboard },
  { href: "/alerts",     label: "Alerts",       icon: ShieldAlert },
  { href: "/indicators", label: "Indicators",   icon: Globe },
  { href: "/logs",       label: "Logs",         icon: FileSearch },
  { href: "/tuning",     label: "Tuning",       icon: Sliders },
  { href: "/sandbox",    label: "Sandbox",      icon: Cpu },
  { href: "/feeds",      label: "Feeds",        icon: Layers },
  { href: "/edl",        label: "EDL",          icon: List },
  { href: "/whitelist",  label: "Whitelist",    icon: Filter },
  { href: "/firewall",   label: "Firewall",     icon: BookOpen },
  { href: "/system",     label: "System",       icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside
      className={clsx(
        "fixed left-0 top-0 h-screen z-40",
        "w-16 lg:w-56",
        "bg-bg-surface border-r border-border",
        "flex flex-col",
      )}
    >
      {/* Logo */}
      <div className="h-14 flex items-center px-3 lg:px-4 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2.5 min-w-0">
          <div
            className={clsx(
              "w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0",
              "bg-accent/15 border border-accent/30",
            )}
          >
            <ShieldAlert className="w-4 h-4 text-accent" />
          </div>
          <span className="hidden lg:block text-sm font-semibold text-text-primary truncate">
            TI Platform
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 px-2">
        <ul className="space-y-0.5">
          {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
            const active =
              href === "/" ? pathname === "/" : pathname.startsWith(href);

            return (
              <li key={href}>
                <Link
                  href={href}
                  title={label}
                  className={clsx(
                    "flex items-center gap-3 px-2.5 py-2 rounded-md text-sm font-medium",
                    "transition-colors duration-100 group",
                    active
                      ? "bg-accent/10 text-accent border border-accent/20"
                      : "text-text-secondary hover:text-text-primary hover:bg-bg-elevated",
                  )}
                >
                  <Icon
                    className={clsx(
                      "w-4 h-4 flex-shrink-0",
                      active ? "text-accent" : "text-text-muted group-hover:text-text-secondary",
                    )}
                  />
                  <span className="hidden lg:block truncate">{label}</span>

                  {/* Tuning badge — draws attention to the new feature */}
                  {href === "/tuning" && !active && (
                    <span className="hidden lg:block ml-auto text-2xs px-1.5 py-0.5 rounded bg-accent/15 text-accent border border-accent/25 font-mono">
                      NEW
                    </span>
                  )}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Footer */}
      <div className="flex-shrink-0 px-3 py-3 border-t border-border">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-status-success animate-pulse-slow flex-shrink-0" />
          <span className="hidden lg:block text-2xs text-text-muted truncate">
            System online
          </span>
        </div>
      </div>
    </aside>
  );
}
