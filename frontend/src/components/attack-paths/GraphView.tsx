"use client";

/**
 * Cytoscape-backed graph view for the attack-paths page.
 *
 * Driven by /api/attack-paths/graph/subgraph (curated subgraph proxy).
 * Click a node → onSelectNode(nodeId/ip) so the parent page can drive
 * the right-pane detail or filter findings.
 *
 * Layout: cose-bilkent (good for medium graphs); falls back to
 * breadthfirst when a single asset is highlighted.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import useSWR from "swr";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import coseBilkent from "cytoscape-cose-bilkent";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { apiFetch } from "@/lib/api";
import { Network, RotateCcw, ZoomIn, ZoomOut } from "lucide-react";

cytoscape.use(coseBilkent);

interface GraphSubgraph {
  nodes: Array<{
    id: string;
    kind: string;
    labels: string[];
    props: Record<string, unknown>;
  }>;
  edges: Array<{
    id: string;
    type: string;
    source: string;
    target: string;
    props: Record<string, unknown>;
  }>;
  truncated: boolean;
}

interface GraphViewProps {
  assetIp?: string | null;
  maxHops?: number;
  onSelectNode?: (info: { kind: string; ip?: string; id: string }) => void;
}

const KIND_COLORS: Record<string, string> = {
  Internet: "#dc2626",  // red
  Zone:     "#7c3aed",  // violet
  Subnet:   "#0891b2",  // cyan
  VIP:      "#f97316",  // orange
  Pool:     "#0d9488",  // teal
  Host:     "#2563eb",  // blue
  Asset:    "#facc15",  // gold (Host:Asset)
  Rule:     "#64748b",  // slate
  NatRule:  "#64748b",
};

const EDGE_COLORS: Record<string, string> = {
  EXPOSES:      "#dc2626",
  DNAT_TO:      "#f97316",
  FORWARDS_TO:  "#0d9488",
  MEMBER_OF:    "#0d9488",
  ALLOWS:       "#16a34a",
  DENIES:       "#94a3b8",
  CONTAINS:     "#cbd5e1",
};

async function getSubgraph(assetIp: string | undefined,
                           maxHops: number): Promise<GraphSubgraph> {
  const q = new URLSearchParams();
  if (assetIp) q.set("asset_ip", assetIp);
  q.set("max_hops", String(maxHops));
  return apiFetch<GraphSubgraph>(`/attack-paths/graph/subgraph?${q.toString()}`);
}

export function GraphView({ assetIp, maxHops = 6, onSelectNode }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);

  const { data, error, isLoading } = useSWR(
    ["attack-paths-subgraph", assetIp, maxHops],
    () => getSubgraph(assetIp ?? undefined, maxHops),
  );

  const elements = useMemo<ElementDefinition[]>(() => {
    if (!data) return [];
    const nodes: ElementDefinition[] = data.nodes.map(n => {
      const isAsset =
        n.labels.includes("Host") &&
        Boolean(n.props && (n.props as Record<string, unknown>)["criticality"]);
      const props = n.props as Record<string, unknown>;
      const label =
        (props.name as string | undefined) ??
        (props.ip as string | undefined) ??
        (props.address as string | undefined) ??
        (props.cidr as string | undefined) ??
        n.kind;
      return {
        group: "nodes",
        data: {
          id: n.id,
          kind: isAsset ? "Asset" : n.kind,
          label: String(label),
          ip: (props.ip as string | undefined) ?? undefined,
        },
      };
    });
    const edges: ElementDefinition[] = data.edges.map(e => ({
      group: "edges",
      data: {
        id: e.id,
        source: e.source,
        target: e.target,
        type: e.type,
      },
    }));
    return [...nodes, ...edges];
  }, [data]);

  // Init / refresh cytoscape when elements change
  useEffect(() => {
    if (!containerRef.current) return;
    if (!cyRef.current) {
      cyRef.current = cytoscape({
        container: containerRef.current,
        elements,
        style: cyStyle(),
        layout: layoutFor(assetIp),
        wheelSensitivity: 0.2,
      });
      cyRef.current.on("tap", "node", evt => {
        const n = evt.target;
        onSelectNode?.({
          kind: n.data("kind"),
          ip:   n.data("ip"),
          id:   n.id(),
        });
      });
    } else {
      const cy = cyRef.current;
      cy.elements().remove();
      cy.add(elements);
      cy.layout(layoutFor(assetIp)).run();
    }
    return () => {
      // intentionally do not destroy on every effect; we recreate on unmount
    };
  }, [elements, assetIp]);     // eslint-disable-line react-hooks/exhaustive-deps

  // Tear down on unmount
  useEffect(() => {
    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, []);

  return (
    <div className="card overflow-hidden">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-accent" />
          <h3 className="text-sm font-semibold text-text-primary">
            Topology graph
            {assetIp && (
              <span className="ml-2 text-xs text-text-muted font-mono">
                paths to {assetIp}
              </span>
            )}
          </h3>
          {data?.truncated && (
            <span className="ml-2 text-2xs px-2 py-0.5 rounded bg-severity-medium/10 text-severity-medium border border-severity-medium/30">
              truncated
            </span>
          )}
        </div>
        <div className="flex gap-1">
          <ToolbarButton onClick={() => cyRef.current?.fit(undefined, 30)} icon={RotateCcw} label="Fit" />
          <ToolbarButton onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 1.2)} icon={ZoomIn}  label="Zoom in" />
          <ToolbarButton onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 0.8)} icon={ZoomOut} label="Zoom out" />
        </div>
      </div>
      <div className="relative" style={{ height: "560px" }}>
        {isLoading && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <LoadingSpinner />
          </div>
        )}
        {error && (
          <div className="absolute inset-0 flex items-center justify-center text-xs text-severity-high">
            Failed to load subgraph: {String(error)}
          </div>
        )}
        <div ref={containerRef} className="absolute inset-0 bg-bg-base" />
      </div>
      <Legend />
    </div>
  );
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function ToolbarButton({
  onClick, icon: Icon, label,
}: {
  onClick: () => void;
  icon: React.ElementType;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      className="p-1.5 rounded border border-border text-text-muted hover:text-text-primary hover:bg-bg-base"
    >
      <Icon className="w-3.5 h-3.5" />
    </button>
  );
}

function Legend() {
  const items: Array<[string, string]> = [
    ["Internet", KIND_COLORS.Internet],
    ["Zone",     KIND_COLORS.Zone],
    ["VIP",      KIND_COLORS.VIP],
    ["Pool",     KIND_COLORS.Pool],
    ["Host",     KIND_COLORS.Host],
    ["Asset",    KIND_COLORS.Asset],
  ];
  return (
    <div className="px-4 py-2 border-t border-border flex flex-wrap gap-3 text-2xs">
      {items.map(([k, c]) => (
        <span key={k} className="inline-flex items-center gap-1.5 text-text-muted">
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: c }} />
          {k}
        </span>
      ))}
    </div>
  );
}

function layoutFor(assetIp: string | null | undefined): cytoscape.LayoutOptions {
  if (assetIp) {
    return { name: "breadthfirst", directed: true, padding: 30, spacingFactor: 1.4 };
  }
  return {
    name: "cose-bilkent",
    nodeRepulsion: 8000,
    idealEdgeLength: 90,
    edgeElasticity: 0.45,
    gravity: 0.25,
    numIter: 1500,
    animate: false,
  } as unknown as cytoscape.LayoutOptions;
}

function cyStyle(): cytoscape.Stylesheet[] {
  return [
    {
      selector: "node",
      style: {
        "background-color": (ele: cytoscape.NodeSingular) =>
          KIND_COLORS[ele.data("kind") as string] ?? "#475569",
        label: "data(label)",
        color: "#e2e8f0",
        "font-size": 9,
        "text-wrap": "wrap",
        "text-max-width": "120px",
        "text-valign": "bottom",
        "text-margin-y": 4,
        "border-width": 1,
        "border-color": "#0f172a",
        width:  (ele: cytoscape.NodeSingular) =>
          ele.data("kind") === "Internet" ? 32 :
          ele.data("kind") === "Asset"    ? 28 : 22,
        height: (ele: cytoscape.NodeSingular) =>
          ele.data("kind") === "Internet" ? 32 :
          ele.data("kind") === "Asset"    ? 28 : 22,
      },
    },
    {
      selector: "edge",
      style: {
        width: 1.5,
        "line-color": (ele: cytoscape.EdgeSingular) =>
          EDGE_COLORS[ele.data("type") as string] ?? "#475569",
        "target-arrow-color": (ele: cytoscape.EdgeSingular) =>
          EDGE_COLORS[ele.data("type") as string] ?? "#475569",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
        opacity: 0.7,
      },
    },
    {
      selector: "node:selected",
      style: {
        "border-width": 3,
        "border-color": "#facc15",
      },
    },
  ];
}
