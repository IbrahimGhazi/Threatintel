"use client";

/**
 * Admin → Trials listing.
 *
 * Top-level entry point for the trial OVA builder. Links to
 * `/admin/trials/new` for starting a new build.
 *
 * Note: this is the placeholder shell; per-trial progress pages live at
 * `/admin/trials/[id]`.
 */

import Link from "next/link";
import { Package, Plus } from "lucide-react";

export default function TrialsListPage() {
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text-primary flex items-center gap-2">
            <Package className="w-5 h-5 text-accent" />
            Trial OVA Builds
          </h1>
          <p className="text-sm text-text-muted mt-0.5">
            Build customer-tailored OVA images with a chosen feature subset.
          </p>
        </div>
        <Link
          href="/admin/trials/new"
          className="btn btn-primary text-xs flex items-center gap-1.5"
        >
          <Plus className="w-3.5 h-3.5" />
          New Trial OVA
        </Link>
      </div>

      <div className="card p-8 flex flex-col items-center justify-center gap-2 text-center">
        <Package className="w-8 h-8 text-text-muted" />
        <p className="text-sm text-text-muted">No trial builds to list yet.</p>
        <p className="text-xs text-text-muted">
          Click <span className="text-accent">New Trial OVA</span> to start a build.
        </p>
      </div>
    </div>
  );
}
