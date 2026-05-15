"use client";

/**
 * Admin → New Trial OVA Build.
 *
 * Lets the operator pick a customer name, trial duration, and the set of
 * features that should ship in the built OVA. POSTs to
 * `/admin/trials/build` and then redirects to the per-trial progress page.
 *
 * The feature key list MUST stay in sync with the backend (Unit 2) and
 * helm flags — see `TrialFeatureKey` in `@/lib/api`.
 */

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Package, ArrowLeft } from "lucide-react";
import { buildTrial, type TrialDurationDays, type TrialFeatureKey } from "@/lib/api";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";

interface FeatureSpec {
  key:         TrialFeatureKey;
  label:       string;
  description: string;
  defaultOn:   boolean;
}

const FEATURES: FeatureSpec[] = [
  { key: "monitoring",   label: "Monitoring (Prometheus + Grafana)", description: "Adds ~1 GB; trials usually skip.",                       defaultOn: false },
  { key: "sandbox",      label: "File Sandbox",                       description: "Detonates suspicious attachments in isolated k8s pods.", defaultOn: true  },
  { key: "icap",         label: "ICAP Web Filter",                    description: "Inline web content filter for proxies.",                 defaultOn: true  },
  { key: "correlation",  label: "Correlation Engine",                 description: "Cross-event detection rules + tuning.",                  defaultOn: true  },
  { key: "enrichment",   label: "Indicator Enrichment",               description: "Pulls extra context for IOCs.",                          defaultOn: true  },
  { key: "vendor_audit", label: "Vendor / Firewall Audit",            description: "CVE matcher against device configs.",                    defaultOn: true  },
  { key: "minio",        label: "MinIO Object Storage",               description: "For large artifact retention.",                          defaultOn: false },
  { key: "neo4j",        label: "Neo4j Graph DB",                     description: "Backs the attack-paths feature.",                        defaultOn: true  },
  { key: "attack_paths", label: "Attack Paths",                       description: "Graph view of lateral-movement chains (requires Neo4j).", defaultOn: true  },
];

const DURATIONS: TrialDurationDays[] = [15, 30, 45];

function initialFeatureState(): Record<TrialFeatureKey, boolean> {
  return FEATURES.reduce((acc, f) => {
    acc[f.key] = f.defaultOn;
    return acc;
  }, {} as Record<TrialFeatureKey, boolean>);
}

export default function NewTrialPage() {
  const router = useRouter();
  const [customer, setCustomer] = useState("");
  const [duration, setDuration] = useState<TrialDurationDays>(15);
  const [features, setFeatures] = useState<Record<TrialFeatureKey, boolean>>(initialFeatureState);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const toggleFeature = (key: TrialFeatureKey) => {
    setFeatures((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = customer.trim();
    if (!name) {
      setError("Customer name is required");
      return;
    }
    setError("");
    setSubmitting(true);
    try {
      const selected = FEATURES
        .filter((f) => features[f.key])
        .map((f) => f.key);
      const res = await buildTrial({
        customer:      name,
        duration_days: duration,
        features:      selected,
      });
      router.push(`/admin/trials/${res.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start build");
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-5 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <Link
            href="/admin/trials"
            className="inline-flex items-center gap-1.5 text-xs text-text-muted hover:text-text-secondary mb-2"
          >
            <ArrowLeft className="w-3 h-3" />
            Back to trials
          </Link>
          <h1 className="text-xl font-semibold text-text-primary flex items-center gap-2">
            <Package className="w-5 h-5 text-accent" />
            New Trial OVA
          </h1>
          <p className="text-sm text-text-muted mt-0.5">
            Configure a customer trial build. Toggle the features that ship in this OVA.
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Customer name */}
        <div className="card p-5 space-y-2">
          <label htmlFor="customer" className="block text-xs font-medium text-text-secondary">
            Customer name <span className="text-severity-high">*</span>
          </label>
          <input
            id="customer"
            type="text"
            value={customer}
            onChange={(e) => setCustomer(e.target.value)}
            placeholder="e.g., Acme Corp"
            required
            className="ti-input text-sm w-full"
            autoComplete="off"
          />
        </div>

        {/* Duration */}
        <fieldset className="card p-5 space-y-3">
          <legend className="text-xs font-medium text-text-secondary px-1">
            Trial duration
          </legend>
          <div className="flex flex-wrap gap-3">
            {DURATIONS.map((days) => {
              const id = `duration-${days}`;
              const checked = duration === days;
              return (
                <div key={days} className="flex items-center gap-2">
                  <input
                    id={id}
                    type="radio"
                    name="duration"
                    value={days}
                    checked={checked}
                    onChange={() => setDuration(days)}
                    className="w-3.5 h-3.5 accent-accent cursor-pointer"
                  />
                  <label
                    htmlFor={id}
                    className="text-sm text-text-primary cursor-pointer select-none"
                  >
                    {days} days
                  </label>
                </div>
              );
            })}
          </div>
        </fieldset>

        {/* Features */}
        <fieldset className="card p-5 space-y-3">
          <legend className="text-xs font-medium text-text-secondary px-1">
            Features
          </legend>
          <div className="space-y-2">
            {FEATURES.map((f) => {
              const id = `feature-${f.key}`;
              const checked = features[f.key];
              return (
                <div
                  key={f.key}
                  className="flex items-start gap-3 p-2 rounded-md hover:bg-bg-elevated/60 transition-colors"
                >
                  <input
                    id={id}
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggleFeature(f.key)}
                    className="mt-1 w-3.5 h-3.5 accent-accent cursor-pointer"
                  />
                  <label htmlFor={id} className="flex-1 cursor-pointer select-none">
                    <div className="text-sm font-medium text-text-primary">{f.label}</div>
                    <div className="text-xs text-text-muted mt-0.5">{f.description}</div>
                  </label>
                </div>
              );
            })}
          </div>
        </fieldset>

        {error && (
          <div className="card p-4 border-severity-high/40 bg-severity-high/5">
            <p className="text-xs text-severity-high">{error}</p>
          </div>
        )}

        <div className="flex items-center gap-2">
          <button
            type="submit"
            disabled={submitting}
            className="btn btn-primary text-xs flex items-center gap-1.5"
          >
            {submitting ? (
              <>
                <LoadingSpinner size="sm" />
                Building...
              </>
            ) : (
              <>
                <Package className="w-3.5 h-3.5" />
                Build OVA
              </>
            )}
          </button>
          <Link href="/admin/trials" className="btn btn-ghost text-xs">
            Cancel
          </Link>
        </div>
      </form>
    </div>
  );
}
