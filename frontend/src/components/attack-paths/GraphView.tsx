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
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { apiFetch } from "@/lib/api";
import { Network, RotateCcw, ZoomIn, ZoomOut } from "lucide-react";

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
  // Top-down network-diagram layout: Internet at the root, edge devices
  // (firewalls), then LB tier (VIPs/Pools), then leaves (Hosts) at the bottom.
  // `breadthfirst` is built into Cytoscape so we don't need an extra layout dep.
  return {
    name: "breadthfirst",
    directed: true,
    roots: 'node[kind = "Internet"]',
    padding: 40,
    spacingFactor: 1.5,
    nodeDimensionsIncludeLabels: true,
    grid: false,
    animate: false,
  } as unknown as cytoscape.LayoutOptions;
}

// Inline SVG cloud — shipped as a data URL so the runtime image needs no
// extra static assets. White fill so it reads on the dark canvas; we'll
// tint it red via background-color.
const INTERNET_CLOUD_SVG =
  "data:image/svg+xml;utf8," +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 70" fill="#fff">' +
    '<path d="M30,55 C12,55 8,40 22,32 C18,18 38,10 50,18 C56,8 80,8 86,22 ' +
            'C108,18 116,42 96,52 C100,62 82,68 72,60 L40,60 C36,64 30,62 30,55 Z"/>' +
    "</svg>",
  );

function cyStyle(): cytoscape.Stylesheet[] {
  return [
    {
      selector: "node",
      style: {
        "background-color": (ele: cytoscape.NodeSingular) =>
          KIND_COLORS[ele.data("kind") as string] ?? "#475569",
        label: "data(label)",
        color: "#e2e8f0",
        "font-size": 10,
        "font-weight": 500,
        "text-wrap": "wrap",
        "text-max-width": "140px",
        "text-valign": "bottom",
        "text-margin-y": 6,
        "text-outline-width": 2,
        "text-outline-color": "#0f172a",
        "border-width": 1.5,
        "border-color": "#0f172a",
        width:  (ele: cytoscape.NodeSingular) => _nodeSize(ele.data("kind"))[0],
        height: (ele: cytoscape.NodeSingular) => _nodeSize(ele.data("kind"))[1],
      },
    },
    // Internet: render as a cloud (SVG background) at the top of the diagram.
    // The breadthfirst layout already pins it to the root row.
    {
      selector: 'node[kind = "Internet"]',
      style: {
        shape: "round-rectangle",
        "background-color": "#dc2626",
        "background-image": INTERNET_CLOUD_SVG,
        "background-fit": "contain",
        "background-clip": "none",
        "background-opacity": 0,         // hide the rectangle, show only the SVG
        "border-width": 0,
        label: "INTERNET",
        "font-size": 13,
        "font-weight": 700,
        color: "#fca5a5",
        "text-valign": "center",
        "text-margin-y": 0,
      },
    },
    // Edge devices and LB infrastructure get distinctive shapes so a glance
    // at the diagram tells you the role (network-diagram-style).
    {
      selector: 'node[kind = "Zone"]',
      style: {
        shape: "round-rectangle",
        "border-width": 2,
        "border-color": "#a78bfa",
      },
    },
    {
      selector: 'node[kind = "VIP"]',
      style: { shape: "diamond" },
    },
    {
      selector: 'node[kind = "Pool"]',
      style: { shape: "hexagon" },
    },
    {
      selector: 'node[kind = "Subnet"]',
      style: { shape: "round-rectangle" },
    },
    {
      selector: 'node[kind = "Asset"]',
      style: {
        shape: "star",
        "border-width": 2,
        "border-color": "#facc15",
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
        opacity: 0.75,
        label: (ele: cytoscape.EdgeSingular) => _edgeLabel(ele.data("type")),
        "font-size": 8,
        color: "#94a3b8",
        "text-rotation": "autorotate",
        "text-background-color": "#0f172a",
        "text-background-opacity": 0.6,
        "text-background-padding": "2px",
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

function _nodeSize(kind: string): [number, number] {
  switch (kind) {
    case "Internet":  return [80, 56];   // cloud — wider than tall
    case "Asset":     return [38, 38];
    case "VIP":       return [32, 32];
    case "Pool":      return [32, 32];
    case "Zone":      return [44, 28];
    case "Subnet":    return [40, 22];
    case "Host":      return [22, 22];
    default:          return [24, 24];
  }
}

function _edgeLabel(type: string): string {
  // Short readable labels for the most-trafficked edge types — most edges
  // stay unlabelled to keep the diagram clean.
  switch (type) {
    case "EXPOSES":     return "exposes";
    case "FORWARDS_TO": return "lb";
    case "MEMBER_OF":   return "member";
    case "DNAT_TO":     return "dnat";
    default:            return "";
  }
}
