"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Search, Bell, RefreshCw } from "lucide-react";
import { ThemeToggle } from "@/components/ui/ThemeToggle";

export function TopBar() {
  const router = useRouter();
  const [query, setQuery] = useState("");

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;
    router.push(`/indicators?q=${encodeURIComponent(query.trim())}`);
    setQuery("");
  };

  return (
    <header className="h-14 border-b border-border bg-bg-surface/80 backdrop-blur-sm
                       flex items-center gap-4 px-6 sticky top-0 z-30 flex-shrink-0">

      {/* Global search */}
      <form onSubmit={handleSearch} className="flex-1 max-w-lg">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted pointer-events-none" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            type="text"
            placeholder="Search indicators, IPs, domains, hashes…"
            className="ti-input w-full pl-9 py-1.5 text-xs"
          />
        </div>
      </form>

      {/* Right actions */}
      <div className="flex items-center gap-2 ml-auto">
        <button
          onClick={() => router.refresh()}
          className="btn-ghost p-1.5 rounded-md"
          title="Refresh"
        >
          <RefreshCw className="w-4 h-4" />
        </button>

        <ThemeToggle />

        <button className="btn-ghost p-1.5 rounded-md relative" title="Alerts">
          <Bell className="w-4 h-4" />
          <span className="absolute top-0.5 right-0.5 w-2 h-2 rounded-full bg-severity-high" />
        </button>

        <div className="h-6 w-px bg-border mx-1" />

        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-full bg-accent/20 border border-accent/40
                          flex items-center justify-center text-xs font-semibold text-accent">
            SOC
          </div>
        </div>
      </div>
    </header>
  );
}
