"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Flag, Trash2 } from "lucide-react";
import { markFalsePositive, deleteIndicator } from "@/lib/api";

export default function IndicatorActions({
  id,
  isFalsePositive,
}: {
  id: string;
  isFalsePositive: boolean;
}) {
  const router = useRouter();
  const [acting, setActing] = useState<"fp" | "delete" | null>(null);
  const [showConfirm, setShowConfirm] = useState(false);

  const handleFP = async () => {
    setActing("fp");
    try {
      await markFalsePositive(id);
      router.refresh();
    } finally {
      setActing(null);
    }
  };

  const handleDelete = async () => {
    setActing("delete");
    try {
      await deleteIndicator(id);
      router.push("/indicators");
    } finally {
      setActing(null);
      setShowConfirm(false);
    }
  };

  return (
    <div className="flex items-center gap-2 flex-shrink-0">
      {!isFalsePositive && (
        <button
          onClick={handleFP}
          disabled={acting !== null}
          title="Mark as false positive (deactivates)"
          className="btn text-xs h-auto py-1.5 px-3 bg-severity-medium/10 text-severity-medium border border-severity-medium/30 hover:bg-severity-medium/20 flex items-center gap-1.5"
        >
          <Flag className="w-3.5 h-3.5" />
          {acting === "fp" ? "Marking…" : "False Positive"}
        </button>
      )}

      {!showConfirm ? (
        <button
          onClick={() => setShowConfirm(true)}
          disabled={acting !== null}
          title="Permanently delete this indicator"
          className="btn text-xs h-auto py-1.5 px-3 bg-severity-critical/10 text-severity-critical border border-severity-critical/30 hover:bg-severity-critical/20 flex items-center gap-1.5"
        >
          <Trash2 className="w-3.5 h-3.5" />
          Delete
        </button>
      ) : (
        <div className="flex items-center gap-1.5 p-2 rounded border border-severity-critical/40 bg-severity-critical/5">
          <span className="text-2xs text-severity-critical font-medium">Delete permanently?</span>
          <button
            onClick={handleDelete}
            disabled={acting !== null}
            className="btn text-2xs h-auto py-1 px-2 bg-severity-critical/20 text-severity-critical border border-severity-critical/40"
          >
            {acting === "delete" ? "Deleting…" : "Confirm"}
          </button>
          <button
            onClick={() => setShowConfirm(false)}
            className="text-2xs text-text-muted hover:text-text-primary px-1"
          >
            Cancel
          </button>
        </div>
      )}
    </div>
  );
}
