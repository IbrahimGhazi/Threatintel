"use client";

/**
 * Network Map — Firewall Boundary Layout
 *
 * - Boundary devices (firewall/switch/router) along vertical center line
 * - Internal nodes on the LEFT, external nodes on the RIGHT
 * - PAN-OS style filter bar with autocomplete
 * - Per-device-type SVG icons (hexagon, diamond, rectangle, etc.)
 * - Host editing (name, device_type, position) via PUT /network/hosts/{ip}
 * - Drag-to-reposition with auto-save
 * - Attack chain highlighting, timeline replay, country breakdown
 * - Investigation side panel with Host Settings tab
 *
 * Enhancements:
 * 1. Responsive canvas via ResizeObserver
 * 2. Parallel edge offset with quadratic bezier curves
 * 3. Edge thickness scaled by volume (log)
 * 4. Traffic flow dash animation on threat edges
 * 5. Severity heatmap glow (radialGradient behind high-threat nodes)
 * 6. Search bar with fuzzy match, dropdown, Ctrl+K shortcut
 * 7. Minimap with viewport rectangle and drag-to-pan
 * 8. Keyboard shortcuts (F fit, Esc deselect, +/- zoom, arrows pan)
 * 9. Smart label hiding based on zoom level
 */

import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import useSWR, { mutate as globalMutate } from "swr";
import Link from "next/link";
import {
  Network, RefreshCw, AlertTriangle, Loader2, ZoomIn, ZoomOut,
  Maximize2, Shield, Globe, Filter, ChevronRight, ChevronDown,
  Clock, Activity, Eye, EyeOff, X, Search, MapPin, Flag,
  Crosshair, ArrowRight, Radio, Layers, BarChart3, ExternalLink,
  HelpCircle, Save, Trash2, GripVertical, Settings, Monitor,
  Wifi, Server, Smartphone, Printer, Cpu, Router, ChevronUp,
} from "lucide-react";
import clsx from "clsx";

/* ═══════════════════════════════════════════════════════════════════════════
   API HELPERS
   ═══════════════════════════════════════════════════════════════════════════ */

const API = process.env.NEXT_PUBLIC_API_URL ?? "/api";
const KEY = process.env.NEXT_PUBLIC_API_KEY ?? "";

function buildHeaders(extra?: Record<string, string>): Record<string, string> {
  return { "Content-Type": "application/json", "X-API-Key": KEY, ...extra };
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: buildHeaders(init?.headers as Record<string, string>),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

/* ═══════════════════════════════════════════════════════════════════════════
   TYPES
   ═══════════════════════════════════════════════════════════════════════════ */

interface GNode {
  id: string;
  ip: string;
  type: "internal" | "external" | "infrastructure";
  subnet: string;
  country_code?: string;
  country_name?: string;
  threat_score: number;
  alert_count: number;
  severity: string;
  has_alert: boolean;
  ti_match?: boolean;
  rules_triggered: string[];
  mitre_techniques?: string[];
  attack_stages?: string[];
  connection_count: number;
  malicious_connections: number;
  last_alert_at?: string | null;
  collapsed?: boolean;
  member_count?: number;
  members?: string[];
  label?: string;
  total_connections?: number;
  host_name?: string | null;
  device_type?: string;
  saved_x?: number | null;
  saved_y?: number | null;
  x: number;
  y: number;
  vx: number;
  vy: number;
  _visible?: boolean;
  _cluster?: string;
}

interface GEdge {
  source: string;
  target: string;
  count: number;
  malicious: boolean;
  malicious_count: number;
  edge_type: "recon" | "lateral" | "c2" | "exfil" | "normal" | "infra";
  protocol?: string;
  port?: number | null;
  action?: string;
  bytes_sent?: number;
  bytes_recv?: number;
  first_seen?: string | null;
  last_seen?: string | null;
}

interface Cluster {
  id: string;
  label: string;
  type: string;
  node_ids: string[];
  threat_score: number;
  max_severity: string;
  alert_count: number;
  has_attack_chain: boolean;
}

interface AttackChain {
  id: string;
  path: { ip: string; stages: string[]; alert_count: number; rules: string[] }[];
  stages: string[];
  severity: string;
  node_count: number;
  stage_count: number;
  description: string;
}

interface TimelineBucket {
  timestamp: string;
  total: number;
  malicious: number;
  unique_sources: number;
  unique_dests: number;
}

interface CountryStat {
  country_code: string;
  country_name: string;
  node_count: number;
  alert_count: number;
  malicious_connections: number;
  max_severity: string;
  threat_score: number;
}

interface GraphData {
  nodes: GNode[];
  edges: GEdge[];
  clusters: Cluster[];
  attack_chains: AttackChain[];
  timeline: TimelineBucket[];
  countries: CountryStat[];
  generated_at: string;
  hours: number;
  node_count: number;
  edge_count: number;
  cluster_count: number;
  chain_count: number;
  infra_collapsed: number;
  avg_threat_score: number;
  country_count: number;
}

interface NodeDetail {
  ip: string;
  type: string;
  subnet: string;
  alerts: Array<{
    id: string;
    title: string;
    severity: string;
    rule_name?: string;
    created_at: string;
  }>;
  alert_count: number;
  mitre_techniques: string[];
  connections: Record<string, { total?: number; unique_peers?: number; malicious?: number }>;
  top_peers: { ip: string; connections: number; malicious: number }[];
  recent_logs: Array<{
    id: string;
    protocol?: string;
    port?: number;
    action?: string;
    timestamp?: string;
    is_malicious?: boolean;
  }>;
  enrichment: Record<string, Record<string, unknown>>;
}

interface HostMeta {
  ip: string;
  host_name?: string | null;
  device_type?: string;
  x_position?: number | null;
  y_position?: number | null;
}

/* ═══════════════════════════════════════════════════════════════════════════
   FILTER PARSER (PAN-OS style)
   ═══════════════════════════════════════════════════════════════════════════ */

interface FilterClause {
  field: string;
  op: "eq" | "neq" | "contains" | "gt" | "lt";
  value: string;
  conjunction: "and" | "or" | null;
}

const FILTER_FIELDS = [
  "source_ip", "destination_ip", "port", "protocol",
  "action", "rule_name", "severity", "edge_type", "country",
];
const FILTER_OPS = ["eq", "neq", "contains", "gt", "lt"];

function parseFilterExpr(expr: string): FilterClause[] {
  const clauses: FilterClause[] = [];
  if (!expr.trim()) return clauses;
  const tokens = expr.trim().split(/\s+/);
  let i = 0;
  while (i < tokens.length) {
    const field = tokens[i]?.toLowerCase();
    const op = tokens[i + 1]?.toLowerCase();
    const value = tokens[i + 2];
    if (!field || !op || value === undefined) break;
    if (!FILTER_FIELDS.includes(field) || !FILTER_OPS.includes(op)) break;
    const conj = tokens[i + 3]?.toLowerCase();
    const conjunction = (conj === "and" || conj === "or") ? conj : null;
    clauses.push({ field, op: op as FilterClause["op"], value, conjunction });
    i += conjunction ? 4 : 3;
  }
  return clauses;
}

function matchClause(clause: FilterClause, fieldVal: string | number | undefined | null): boolean {
  if (fieldVal === undefined || fieldVal === null) return false;
  const sv = String(fieldVal).toLowerCase();
  const cv = clause.value.toLowerCase();
  switch (clause.op) {
    case "eq": return sv === cv;
    case "neq": return sv !== cv;
    case "contains": return sv.includes(cv);
    case "gt": return Number(fieldVal) > Number(clause.value);
    case "lt": return Number(fieldVal) < Number(clause.value);
    default: return false;
  }
}

function nodeFieldValue(n: GNode, field: string): string | number | undefined {
  switch (field) {
    case "source_ip": return n.ip;
    case "destination_ip": return n.ip;
    case "severity": return n.severity;
    case "country": return n.country_code;
    case "rule_name": return n.rules_triggered?.join(",");
    default: return undefined;
  }
}

function edgeFieldValue(e: GEdge, field: string): string | number | undefined {
  switch (field) {
    case "source_ip": return e.source;
    case "destination_ip": return e.target;
    case "port": return e.port ?? undefined;
    case "protocol": return e.protocol;
    case "action": return e.action;
    case "edge_type": return e.edge_type;
    default: return undefined;
  }
}

function applyFilters(
  nodes: GNode[], edges: GEdge[], clauses: FilterClause[],
): { nodes: GNode[]; edges: GEdge[] } {
  if (!clauses.length) return { nodes, edges };
  const nodeFields = new Set(["source_ip", "destination_ip", "severity", "country", "rule_name"]);
  const edgeFields = new Set(["source_ip", "destination_ip", "port", "protocol", "action", "edge_type"]);

  const nodeClauses = clauses.filter(c => nodeFields.has(c.field));
  const edgeClauses = clauses.filter(c => edgeFields.has(c.field));

  let filteredEdges = edges;
  if (edgeClauses.length) {
    filteredEdges = edges.filter(e => {
      let result = true;
      for (let i = 0; i < edgeClauses.length; i++) {
        const c = edgeClauses[i];
        const m = matchClause(c, edgeFieldValue(e, c.field));
        if (i === 0) { result = m; }
        else {
          const prev = edgeClauses[i - 1];
          if (prev.conjunction === "or") result = result || m;
          else result = result && m;
        }
      }
      return result;
    });
  }

  const edgeNodeIds = new Set<string>();
  for (const e of filteredEdges) {
    edgeNodeIds.add(e.source);
    edgeNodeIds.add(e.target);
  }

  let filteredNodes = nodes;
  if (nodeClauses.length) {
    filteredNodes = nodes.filter(n => {
      let result = true;
      for (let i = 0; i < nodeClauses.length; i++) {
        const c = nodeClauses[i];
        const m = matchClause(c, nodeFieldValue(n, c.field));
        if (i === 0) { result = m; }
        else {
          const prev = nodeClauses[i - 1];
          if (prev.conjunction === "or") result = result || m;
          else result = result && m;
        }
      }
      return result;
    });
  }

  if (edgeClauses.length && !nodeClauses.length) {
    filteredNodes = nodes.filter(n => edgeNodeIds.has(n.id));
  }

  const visibleIds = new Set(filteredNodes.map(n => n.id));
  filteredEdges = filteredEdges.filter(e => visibleIds.has(e.source) && visibleIds.has(e.target));

  return { nodes: filteredNodes, edges: filteredEdges };
}

/* ═══════════════════════════════════════════════════════════════════════════
   CONSTANTS & HELPERS
   ═══════════════════════════════════════════════════════════════════════════ */

const BOUNDARY_DEVICE_TYPES = new Set(["firewall", "switch", "router"]);

const DEVICE_TYPES = [
  "firewall", "server", "switch", "router", "laptop", "workstation",
  "printer", "iot", "phone", "access_point", "unknown",
] as const;

type DeviceType = (typeof DEVICE_TYPES)[number];

const SEV: Record<string, { color: string; bg: string; order: number }> = {
  critical: { color: "#f04060", bg: "#f0406018", order: 4 },
  high:     { color: "#f07030", bg: "#f0703018", order: 3 },
  medium:   { color: "#f0a830", bg: "#f0a83018", order: 2 },
  low:      { color: "#50a0f0", bg: "#50a0f018", order: 1 },
  info:     { color: "#60809a", bg: "#60809a18", order: 0 },
};

const EDGE_STYLE: Record<string, { color: string; dash: string; width: number; label: string }> = {
  c2:      { color: "#f04060", dash: "",    width: 2.5, label: "C2 / Callback" },
  exfil:   { color: "#c040f0", dash: "",    width: 2.5, label: "Exfiltration" },
  lateral: { color: "#f07030", dash: "",    width: 2,   label: "Lateral Movement" },
  recon:   { color: "#f0a830", dash: "6,3", width: 1.5, label: "Reconnaissance" },
  infra:   { color: "#334155", dash: "2,4", width: 0.5, label: "Infrastructure" },
  normal:  { color: "#475569", dash: "",    width: 0.7, label: "Normal" },
};

const STAGE_COLORS: Record<string, string> = {
  reconnaissance:       "#f0a830",
  credential_access:    "#f07030",
  initial_access:       "#e04050",
  lateral_movement:     "#f06020",
  command_and_control:  "#f04060",
  exfiltration:         "#c040f0",
  execution:            "#d04070",
  persistence:          "#d06040",
  privilege_escalation: "#e05040",
  discovery:            "#e0a020",
  defense_evasion:      "#b0b030",
  collection:           "#a050d0",
  impact:               "#f02050",
};

const DEVICE_COLORS: Record<string, string> = {
  firewall:     "#f07030",
  server:       "#3b82f6",
  switch:       "#14b8a6",
  router:       "#22c55e",
  laptop:       "#06b6d4",
  workstation:  "#06b6d4",
  printer:      "#94a3b8",
  iot:          "#a855f7",
  phone:        "#ec4899",
  access_point: "#14b8a6",
  unknown:      "#64748b",
};

function flag(cc: string): string {
  if (!cc || cc.length !== 2) return "";
  const offset = 0x1F1E6 - 65;
  return String.fromCodePoint(
    cc.charCodeAt(0) + offset,
    cc.charCodeAt(1) + offset,
  );
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
  return String(n);
}

function fmtBytes(b: number): string {
  if (b >= 1_073_741_824) return (b / 1_073_741_824).toFixed(1) + " GB";
  if (b >= 1_048_576) return (b / 1_048_576).toFixed(1) + " MB";
  if (b >= 1024) return (b / 1024).toFixed(1) + " KB";
  return b + " B";
}

function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "\u2014";
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function stageLabel(s: string): string {
  return s.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

function deviceLabel(dt: string): string {
  return dt.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

function isBoundary(n: GNode): boolean {
  return BOUNDARY_DEVICE_TYPES.has(n.device_type || "");
}

/* ═══════════════════════════════════════════════════════════════════════════
   SVG DEVICE SHAPE RENDERERS
   ═══════════════════════════════════════════════════════════════════════════ */

function DeviceShape({
  x, y, deviceType, size, fillColor, strokeColor, strokeWidth, opacity, selected,
}: {
  x: number; y: number; deviceType: string; size: number;
  fillColor: string; strokeColor: string; strokeWidth: number;
  opacity: number; selected: boolean;
}) {
  const s = size;
  const dt = deviceType || "unknown";
  const fill = fillColor;
  const sw = strokeWidth;

  switch (dt) {
    case "firewall": {
      // Hexagon
      const pts = Array.from({ length: 6 }, (_, i) => {
        const a = (Math.PI / 3) * i - Math.PI / 2;
        return `${x + s * Math.cos(a)},${y + s * Math.sin(a)}`;
      }).join(" ");
      return (
        <polygon
          points={pts}
          fill={fill} fillOpacity={opacity * 0.25}
          stroke={strokeColor} strokeWidth={sw}
          opacity={opacity}
        />
      );
    }
    case "server": {
      // Rectangle
      const w = s * 1.4, h = s * 1.6;
      return (
        <rect
          x={x - w / 2} y={y - h / 2} width={w} height={h} rx={2}
          fill={fill} fillOpacity={opacity * 0.25}
          stroke={strokeColor} strokeWidth={sw}
          opacity={opacity}
        />
      );
    }
    case "switch": {
      // Diamond
      const pts = `${x},${y - s} ${x + s},${y} ${x},${y + s} ${x - s},${y}`;
      return (
        <polygon
          points={pts}
          fill={fill} fillOpacity={opacity * 0.25}
          stroke={strokeColor} strokeWidth={sw}
          opacity={opacity}
        />
      );
    }
    case "router": {
      // Circle with outer ring
      return (
        <g opacity={opacity}>
          <circle cx={x} cy={y} r={s} fill="none" stroke={strokeColor} strokeWidth={1} strokeDasharray="3,2" />
          <circle cx={x} cy={y} r={s * 0.7}
            fill={fill} fillOpacity={0.25}
            stroke={strokeColor} strokeWidth={sw}
          />
        </g>
      );
    }
    case "laptop": {
      // Rounded rectangle
      const w = s * 1.6, h = s * 1.1;
      return (
        <rect
          x={x - w / 2} y={y - h / 2} width={w} height={h} rx={s * 0.35}
          fill={fill} fillOpacity={opacity * 0.25}
          stroke={strokeColor} strokeWidth={sw}
          opacity={opacity}
        />
      );
    }
    case "workstation": {
      // Monitor shape: rectangle with stand
      const w = s * 1.6, h = s * 1.2;
      return (
        <g opacity={opacity}>
          <rect
            x={x - w / 2} y={y - h / 2 - 2} width={w} height={h} rx={2}
            fill={fill} fillOpacity={0.25}
            stroke={strokeColor} strokeWidth={sw}
          />
          <line x1={x} y1={y + h / 2 - 2} x2={x} y2={y + h / 2 + 3}
            stroke={strokeColor} strokeWidth={sw} />
          <line x1={x - s * 0.4} y1={y + h / 2 + 3} x2={x + s * 0.4} y2={y + h / 2 + 3}
            stroke={strokeColor} strokeWidth={sw} />
        </g>
      );
    }
    case "printer": {
      // Square
      const w = s * 1.3;
      return (
        <rect
          x={x - w / 2} y={y - w / 2} width={w} height={w} rx={1}
          fill={fill} fillOpacity={opacity * 0.25}
          stroke={strokeColor} strokeWidth={sw}
          opacity={opacity}
        />
      );
    }
    case "iot": {
      // Triangle
      const pts = `${x},${y - s} ${x + s * 0.87},${y + s * 0.5} ${x - s * 0.87},${y + s * 0.5}`;
      return (
        <polygon
          points={pts}
          fill={fill} fillOpacity={opacity * 0.25}
          stroke={strokeColor} strokeWidth={sw}
          opacity={opacity}
        />
      );
    }
    case "phone": {
      // Pill / rounded rectangle
      const w = s * 0.9, h = s * 1.7;
      return (
        <rect
          x={x - w / 2} y={y - h / 2} width={w} height={h} rx={w / 2}
          fill={fill} fillOpacity={opacity * 0.25}
          stroke={strokeColor} strokeWidth={sw}
          opacity={opacity}
        />
      );
    }
    case "access_point": {
      // Circle with wave arcs
      return (
        <g opacity={opacity}>
          <circle cx={x} cy={y} r={s * 0.5}
            fill={fill} fillOpacity={0.25}
            stroke={strokeColor} strokeWidth={sw}
          />
          <path
            d={`M ${x - s * 0.6} ${y - s * 0.3} Q ${x} ${y - s * 1.1} ${x + s * 0.6} ${y - s * 0.3}`}
            fill="none" stroke={strokeColor} strokeWidth={1} opacity={0.6}
          />
          <path
            d={`M ${x - s * 0.85} ${y - s * 0.55} Q ${x} ${y - s * 1.5} ${x + s * 0.85} ${y - s * 0.55}`}
            fill="none" stroke={strokeColor} strokeWidth={1} opacity={0.35}
          />
        </g>
      );
    }
    default: {
      // Unknown: plain circle
      return (
        <circle
          cx={x} cy={y} r={s}
          fill={fill} fillOpacity={opacity * 0.25}
          stroke={strokeColor} strokeWidth={sw}
          opacity={opacity}
        />
      );
    }
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   FIREWALL BOUNDARY FORCE LAYOUT
   ═══════════════════════════════════════════════════════════════════════════ */

function runBoundaryLayout(
  nodes: GNode[], edges: GEdge[], _clusters: Cluster[],
  W: number, H: number, iterations = 100,
): GNode[] {
  if (!nodes.length) return nodes;

  const centerX = W / 2;
  const pad = 60;

  // Separate boundary, internal, external
  const boundary: GNode[] = [];
  const internal: GNode[] = [];
  const external: GNode[] = [];

  for (const n of nodes) {
    if (isBoundary(n)) boundary.push(n);
    else if (n.type === "internal" || n.type === "infrastructure") internal.push(n);
    else external.push(n);
  }

  // Place boundary devices along center vertical line
  boundary.forEach((n, i) => {
    if (n.saved_x != null && n.saved_y != null) {
      n.x = n.saved_x; n.y = n.saved_y;
    } else {
      n.x = centerX;
      n.y = pad + ((H - 2 * pad) / Math.max(boundary.length, 1)) * (i + 0.5);
    }
    n.vx = 0; n.vy = 0;
  });

  // Internal: seed on left half
  internal.forEach((n, i) => {
    if (n.saved_x != null && n.saved_y != null) {
      n.x = n.saved_x; n.y = n.saved_y;
    } else {
      const cols = Math.ceil(Math.sqrt(internal.length));
      const row = Math.floor(i / cols);
      const col = i % cols;
      const leftW = centerX - pad * 2;
      n.x = pad + (leftW / Math.max(cols, 1)) * (col + 0.5);
      n.y = pad + ((H - 2 * pad) / Math.max(Math.ceil(internal.length / cols), 1)) * (row + 0.5);
      n.x += (Math.random() - 0.5) * 30;
      n.y += (Math.random() - 0.5) * 30;
    }
    n.vx = 0; n.vy = 0;
  });

  // External: seed on right half
  external.forEach((n, i) => {
    if (n.saved_x != null && n.saved_y != null) {
      n.x = n.saved_x; n.y = n.saved_y;
    } else {
      const cols = Math.ceil(Math.sqrt(external.length));
      const row = Math.floor(i / cols);
      const col = i % cols;
      const rightW = centerX - pad * 2;
      n.x = centerX + pad + (rightW / Math.max(cols, 1)) * (col + 0.5);
      n.y = pad + ((H - 2 * pad) / Math.max(Math.ceil(external.length / cols), 1)) * (row + 0.5);
      n.x += (Math.random() - 0.5) * 30;
      n.y += (Math.random() - 0.5) * 30;
    }
    n.vx = 0; n.vy = 0;
  });

  // Skip force sim for nodes with saved positions
  const hasSaved = nodes.filter(n => n.saved_x != null && n.saved_y != null);
  const savedIds = new Set(hasSaved.map(n => n.id));

  // Only run force on non-saved, non-boundary nodes
  const simNodes = nodes.filter(n => !savedIds.has(n.id) && !isBoundary(n));
  if (simNodes.length === 0) return nodes;

  const k = Math.sqrt((W * H) / Math.max(nodes.length, 1));
  let temp = W * 0.06;
  const nm = new Map(nodes.map(n => [n.id, n]));

  for (let iter = 0; iter < iterations; iter++) {
    // Repulsion
    for (const ni of simNodes) {
      let fx = 0, fy = 0;
      for (const nj of nodes) {
        if (ni.id === nj.id) continue;
        const dx = ni.x - nj.x || 0.01;
        const dy = ni.y - nj.y || 0.01;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.1;
        const force = (k * k) / dist;
        fx += (dx / dist) * force;
        fy += (dy / dist) * force;
      }
      ni.vx = (ni.vx + fx) * 0.85;
      ni.vy = (ni.vy + fy) * 0.85;
    }

    // Attraction along edges
    for (const e of edges) {
      const src = nm.get(e.source);
      const dst = nm.get(e.target);
      if (!src || !dst) continue;
      const srcSim = simNodes.includes(src);
      const dstSim = simNodes.includes(dst);
      if (!srcSim && !dstSim) continue;
      const dx = src.x - dst.x;
      const dy = src.y - dst.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.1;
      const strength = e.malicious ? 1.2 : 0.8;
      const force = ((dist * dist) / k) * strength * 0.5;
      const fxv = (dx / dist) * force;
      const fyv = (dy / dist) * force;
      if (srcSim) { src.vx -= fxv; src.vy -= fyv; }
      if (dstSim) { dst.vx += fxv; dst.vy += fyv; }
    }

    // Apply + constrain to correct side
    for (const n of simNodes) {
      const spd = Math.sqrt(n.vx * n.vx + n.vy * n.vy);
      if (spd > 0) {
        n.x += (n.vx / spd) * Math.min(spd, temp);
        n.y += (n.vy / spd) * Math.min(spd, temp);
      }
      // Constrain
      if (n.type === "internal" || n.type === "infrastructure") {
        n.x = Math.max(pad, Math.min(centerX - pad, n.x));
      } else {
        n.x = Math.max(centerX + pad, Math.min(W - pad, n.x));
      }
      n.y = Math.max(pad, Math.min(H - pad, n.y));
    }
    temp = Math.max(temp * 0.94, 0.5);
  }

  return nodes;
}

/* ═══════════════════════════════════════════════════════════════════════════
   FILTER BAR COMPONENT
   ═══════════════════════════════════════════════════════════════════════════ */

function FilterBar({
  value, onChange, clauses, onRemoveClause,
}: {
  value: string;
  onChange: (v: string) => void;
  clauses: FilterClause[];
  onRemoveClause: (idx: number) => void;
}) {
  const [focused, setFocused] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const tokens = value.trim().split(/\s+/);
  const lastToken = tokens[tokens.length - 1]?.toLowerCase() || "";
  const tokenCount = tokens.filter(t => t.length > 0).length;

  // Determine what to suggest based on token position in current clause
  const conjunctions = ["and", "or"];
  const clauseTokenIndex = (() => {
    let pos = 0;
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i].toLowerCase();
      if (t === "and" || t === "or") { pos = 0; continue; }
      pos++;
    }
    return pos;
  })();

  const suggestions = useMemo(() => {
    if (!focused || !value.trim()) return FILTER_FIELDS.slice(0, 6);
    if (clauseTokenIndex === 1) {
      // Expecting field name
      return FILTER_FIELDS.filter(f => f.startsWith(lastToken));
    }
    if (clauseTokenIndex === 2) {
      // Expecting operator
      return FILTER_OPS.filter(o => o.startsWith(lastToken));
    }
    if (clauseTokenIndex === 0 && tokenCount > 0) {
      // After a complete clause, suggest conjunction
      return conjunctions.filter(c => c.startsWith(lastToken));
    }
    return [];
  }, [focused, value, lastToken, clauseTokenIndex, tokenCount]);

  const applySuggestion = (s: string) => {
    const toks = value.trim().split(/\s+/);
    if (toks.length > 0 && lastToken.length > 0) {
      toks[toks.length - 1] = s;
    } else {
      toks.push(s);
    }
    onChange(toks.join(" ") + " ");
    inputRef.current?.focus();
  };

  return (
    <div className="relative">
      <div className="flex items-center gap-2 card px-3 py-2">
        <Search className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
        <input
          ref={inputRef}
          type="text"
          value={value}
          onChange={e => onChange(e.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setTimeout(() => setFocused(false), 200)}
          placeholder="Filter: source_ip eq 192.168.1.10 and port eq 443"
          className="flex-1 bg-transparent text-xs text-text-primary placeholder:text-text-muted/50 outline-none font-mono"
        />
        {value && (
          <button onClick={() => onChange("")} className="text-text-muted hover:text-text-primary">
            <X className="w-3.5 h-3.5" />
          </button>
        )}
        <button
          onClick={() => setShowHelp(!showHelp)}
          className="text-text-muted hover:text-accent"
          title="Filter syntax help"
        >
          <HelpCircle className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Autocomplete dropdown */}
      {focused && suggestions.length > 0 && (
        <div className="absolute top-full left-0 right-0 mt-1 card p-1 z-30 max-h-48 overflow-y-auto">
          {suggestions.map(s => (
            <button
              key={s}
              onMouseDown={e => { e.preventDefault(); applySuggestion(s); }}
              className="w-full text-left px-3 py-1.5 text-xs font-mono text-text-secondary hover:bg-bg-elevated rounded transition-colors"
            >
              {s}
            </button>
          ))}
        </div>
      )}

      {/* Help tooltip */}
      {showHelp && (
        <div className="absolute top-full right-0 mt-1 card p-3 z-30 w-80 text-xs text-text-secondary space-y-2">
          <div className="font-semibold text-text-primary">Filter Syntax</div>
          <div className="text-text-muted">
            <span className="font-mono">field op value [and|or field op value]*</span>
          </div>
          <div>
            <span className="font-semibold text-text-primary">Fields: </span>
            <span className="font-mono">{FILTER_FIELDS.join(", ")}</span>
          </div>
          <div>
            <span className="font-semibold text-text-primary">Operators: </span>
            <span className="font-mono">{FILTER_OPS.join(", ")}</span>
          </div>
          <div className="border-t border-border pt-2 space-y-1 text-text-muted font-mono text-2xs">
            <div>source_ip eq 192.168.1.10</div>
            <div>port eq 443 and protocol eq TCP</div>
            <div>severity eq critical or severity eq high</div>
            <div>edge_type eq c2</div>
          </div>
        </div>
      )}

      {/* Active filter pills */}
      {clauses.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mt-2">
          {clauses.map((c, i) => (
            <span key={i} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-2xs font-mono bg-accent/10 text-accent border border-accent/20">
              {c.field} {c.op} {c.value}
              {c.conjunction && (
                <span className="text-text-muted ml-1 uppercase">{c.conjunction}</span>
              )}
              <button onClick={() => onRemoveClause(i)} className="ml-0.5 hover:text-text-primary">
                <X className="w-2.5 h-2.5" />
              </button>
            </span>
          ))}
          <button
            onClick={() => onChange("")}
            className="text-2xs text-text-muted hover:text-text-primary"
          >
            Clear all
          </button>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   TIMELINE SLIDER
   ═══════════════════════════════════════════════════════════════════════════ */

function TimelineSlider({
  timeline, value, onChange, playing, onTogglePlay,
}: {
  timeline: TimelineBucket[];
  value: number;
  onChange: (v: number) => void;
  playing: boolean;
  onTogglePlay: () => void;
}) {
  if (!timeline.length) return null;
  const maxTotal = Math.max(...timeline.map(t => t.total), 1);
  const maxMal = Math.max(...timeline.map(t => t.malicious), 1);

  return (
    <div className="card p-3 space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs text-text-muted">
          <Clock className="w-3.5 h-3.5" />
          <span className="font-semibold text-text-secondary">Attack Timeline</span>
          {value < timeline.length && timeline[value] && (
            <span className="font-mono text-text-primary">
              {new Date(timeline[value].timestamp).toLocaleString([], {
                month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
              })}
            </span>
          )}
        </div>
        <button
          onClick={onTogglePlay}
          className={clsx(
            "px-2 py-0.5 rounded text-2xs font-semibold transition-colors",
            playing
              ? "bg-severity-critical/20 text-severity-critical"
              : "bg-accent/10 text-accent hover:bg-accent/20"
          )}
        >
          {playing ? "Pause" : "Replay"}
        </button>
      </div>

      {/* Mini bar chart */}
      <div className="flex items-end gap-px h-10">
        {timeline.map((t, i) => (
          <div
            key={i}
            className="flex-1 flex flex-col justify-end cursor-pointer group relative"
            onClick={() => onChange(i)}
          >
            {t.malicious > 0 && (
              <div
                className="w-full rounded-t-sm transition-all"
                style={{
                  height: `${Math.max(2, (t.malicious / maxMal) * 100)}%`,
                  backgroundColor: i <= value ? "#f04060" : "#f0406050",
                }}
              />
            )}
            <div
              className="w-full rounded-t-sm transition-all"
              style={{
                height: `${Math.max(2, (t.total / maxTotal) * 100)}%`,
                backgroundColor: i <= value
                  ? (t.malicious > 0 ? "#f0706060" : "rgb(var(--accent) / 0.6)")
                  : "rgb(var(--border-default) / 0.4)",
              }}
            />
          </div>
        ))}
      </div>

      <input
        type="range"
        min={0}
        max={timeline.length - 1}
        value={value}
        onChange={e => onChange(Number(e.target.value))}
        className="w-full h-1 appearance-none bg-bg-elevated rounded cursor-pointer
          [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-3
          [&::-webkit-slider-thumb]:h-3 [&::-webkit-slider-thumb]:rounded-full
          [&::-webkit-slider-thumb]:bg-accent [&::-webkit-slider-thumb]:shadow-glow"
      />
      <div className="flex justify-between text-2xs text-text-muted font-mono">
        <span>
          {timeline[0]
            ? new Date(timeline[0].timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
            : ""}
        </span>
        <span>
          {timeline[timeline.length - 1]
            ? new Date(timeline[timeline.length - 1].timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
            : ""}
        </span>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   ATTACK CHAIN CARD
   ═══════════════════════════════════════════════════════════════════════════ */

function ChainCard({
  chain, active, onClick,
}: {
  chain: AttackChain;
  active: boolean;
  onClick: () => void;
}) {
  const sev = SEV[chain.severity] || SEV.info;
  return (
    <button
      onClick={onClick}
      className={clsx(
        "w-full text-left p-2.5 rounded-lg border transition-all text-xs",
        active
          ? "border-severity-critical/50 bg-severity-critical/8 shadow-glow-red"
          : "border-border hover:border-border-strong bg-bg-surface hover:bg-bg-elevated"
      )}
    >
      <div className="flex items-center gap-2 mb-1.5">
        <Crosshair className="w-3 h-3 flex-shrink-0" style={{ color: sev.color }} />
        <span className="font-semibold text-text-primary truncate">
          {chain.stage_count}-Stage Attack
        </span>
        <span
          className="ml-auto badge border text-2xs"
          style={{ background: sev.bg, borderColor: sev.color + "40", color: sev.color }}
        >
          {chain.severity}
        </span>
      </div>
      <div className="flex flex-wrap gap-1 mb-1.5">
        {chain.stages.map(s => (
          <span
            key={s}
            className="px-1.5 py-0.5 rounded text-2xs font-mono"
            style={{
              backgroundColor: (STAGE_COLORS[s] || "#666") + "20",
              color: STAGE_COLORS[s] || "#999",
            }}
          >
            {stageLabel(s)}
          </span>
        ))}
      </div>
      <div className="flex items-center gap-1 text-2xs text-text-muted font-mono overflow-hidden">
        {chain.path.map((p, i) => (
          <span key={i} className="flex items-center gap-1 flex-shrink-0">
            {i > 0 && <ArrowRight className="w-2.5 h-2.5 text-text-muted/50" />}
            <span className={p.alert_count > 2 ? "text-severity-high" : "text-text-secondary"}>
              {p.ip}
            </span>
          </span>
        ))}
      </div>
    </button>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   COUNTRY ROW
   ═══════════════════════════════════════════════════════════════════════════ */

function CountryRow({ c }: { c: CountryStat }) {
  const sev = SEV[c.max_severity] || SEV.info;
  return (
    <div className="flex items-center gap-2 py-1.5 px-2 rounded hover:bg-bg-elevated text-xs transition-colors">
      <span className="text-sm flex-shrink-0">{flag(c.country_code)}</span>
      <span className="text-text-primary font-medium truncate flex-1">
        {c.country_name || c.country_code}
      </span>
      <span className="font-mono text-text-muted text-2xs">
        {c.node_count} IP{c.node_count !== 1 ? "s" : ""}
      </span>
      {c.alert_count > 0 && (
        <span
          className="font-mono text-2xs px-1.5 py-0.5 rounded"
          style={{ backgroundColor: sev.bg, color: sev.color }}
        >
          {c.alert_count}
        </span>
      )}
      {c.malicious_connections > 0 && (
        <span className="font-mono text-2xs text-severity-critical">{c.malicious_connections} mal</span>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   INVESTIGATION PANEL
   ═══════════════════════════════════════════════════════════════════════════ */

function InvestigationPanel({
  ip, hours, node, onClose, onPivot, onHostSaved,
}: {
  ip: string;
  hours: number;
  node: GNode | undefined;
  onClose: () => void;
  onPivot: (ip: string) => void;
  onHostSaved: () => void;
}) {
  const { data, isLoading } = useSWR<NodeDetail>(
    `/network/node/${ip}?hours=${hours}`,
    () => apiFetch<NodeDetail>(`/network/node/${ip}?hours=${hours}`),
  );
  const [tab, setTab] = useState<"alerts" | "connections" | "logs" | "enrichment" | "host">("alerts");

  // Host settings form state
  const [hostName, setHostName] = useState(node?.host_name || "");
  const [deviceType, setDeviceType] = useState<string>(node?.device_type || "unknown");
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState("");

  useEffect(() => {
    setHostName(node?.host_name || "");
    setDeviceType(node?.device_type || "unknown");
  }, [node?.host_name, node?.device_type]);

  const saveHost = async () => {
    setSaving(true);
    setSaveMsg("");
    try {
      await apiFetch(`/network/hosts/${ip}`, {
        method: "PUT",
        body: JSON.stringify({
          name: hostName || null,
          device_type: deviceType,
        }),
      });
      setSaveMsg("Saved");
      onHostSaved();
      setTimeout(() => setSaveMsg(""), 2000);
    } catch (err) {
      setSaveMsg("Error saving");
    } finally {
      setSaving(false);
    }
  };

  const tabs = ["alerts", "connections", "logs", "enrichment", "host"] as const;

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-2 p-3 border-b border-border">
        <Shield className="w-4 h-4 text-accent flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono font-bold text-text-primary text-sm">{ip}</span>
            {data?.type && (
              <span className={clsx(
                "badge border text-2xs",
                data.type === "internal"
                  ? "bg-accent/10 border-accent/30 text-accent"
                  : "bg-severity-medium/10 border-severity-medium/30 text-severity-medium"
              )}>
                {data.type}
              </span>
            )}
          </div>
          {node?.host_name && (
            <div className="text-2xs text-text-muted font-mono truncate">{node.host_name}</div>
          )}
        </div>
        <button onClick={onClose} className="text-text-muted hover:text-text-primary p-1">
          <X className="w-4 h-4" />
        </button>
      </div>

      {isLoading && (
        <div className="flex-1 flex items-center justify-center">
          <Loader2 className="w-5 h-5 animate-spin text-text-muted" />
        </div>
      )}

      {data && (
        <div className="flex-1 overflow-y-auto">
          {/* Summary stats */}
          <div className="grid grid-cols-3 gap-2 p-3">
            <div className="text-center p-2 rounded bg-bg-elevated">
              <div className="text-lg font-bold font-mono text-text-primary">{data.alert_count}</div>
              <div className="text-2xs text-text-muted">Alerts</div>
            </div>
            <div className="text-center p-2 rounded bg-bg-elevated">
              <div className="text-lg font-bold font-mono text-text-primary">
                {(data.connections?.outbound?.unique_peers || 0) + (data.connections?.inbound?.unique_peers || 0)}
              </div>
              <div className="text-2xs text-text-muted">Peers</div>
            </div>
            <div className="text-center p-2 rounded bg-bg-elevated">
              <div className="text-lg font-bold font-mono text-severity-critical">
                {(data.connections?.outbound?.malicious || 0) + (data.connections?.inbound?.malicious || 0)}
              </div>
              <div className="text-2xs text-text-muted">Malicious</div>
            </div>
          </div>

          {/* MITRE Techniques */}
          {data.mitre_techniques?.length > 0 && (
            <div className="px-3 pb-2">
              <div className="text-2xs text-text-muted uppercase tracking-wider font-semibold mb-1.5">
                MITRE ATT&CK
              </div>
              <div className="flex flex-wrap gap-1">
                {data.mitre_techniques.map((t: string) => (
                  <span
                    key={t}
                    className="px-1.5 py-0.5 rounded text-2xs font-mono bg-severity-high/10 text-severity-high border border-severity-high/20"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Enrichment summary */}
          {data.enrichment && Object.keys(data.enrichment).length > 0 && (
            <div className="px-3 pb-2">
              <div className="text-2xs text-text-muted uppercase tracking-wider font-semibold mb-1.5">
                Enrichment
              </div>
              <div className="bg-bg-elevated rounded-md p-2 space-y-1">
                {(data.enrichment as Record<string, Record<string, unknown>>).geoip && (
                  <>
                    {(data.enrichment as Record<string, Record<string, unknown>>).geoip.country_name && (
                      <div className="flex gap-2 text-2xs">
                        <span className="text-text-muted w-16 flex-shrink-0">Country</span>
                        <span className="text-text-primary font-mono">
                          {flag(String((data.enrichment as Record<string, Record<string, unknown>>).geoip.country_code || ""))}{" "}
                          {String((data.enrichment as Record<string, Record<string, unknown>>).geoip.country_name)}
                        </span>
                      </div>
                    )}
                    {(data.enrichment as Record<string, Record<string, unknown>>).geoip.city && (
                      <div className="flex gap-2 text-2xs">
                        <span className="text-text-muted w-16 flex-shrink-0">City</span>
                        <span className="text-text-primary font-mono">
                          {String((data.enrichment as Record<string, Record<string, unknown>>).geoip.city)},{" "}
                          {String((data.enrichment as Record<string, Record<string, unknown>>).geoip.region)}
                        </span>
                      </div>
                    )}
                  </>
                )}
                {(data.enrichment as Record<string, Record<string, unknown>>).asn && (
                  <div className="flex gap-2 text-2xs">
                    <span className="text-text-muted w-16 flex-shrink-0">ASN</span>
                    <span className="text-text-primary font-mono">
                      {String((data.enrichment as Record<string, Record<string, unknown>>).asn.asn)} &mdash;{" "}
                      {String((data.enrichment as Record<string, Record<string, unknown>>).asn.asn_org)}
                    </span>
                  </div>
                )}
                {(() => {
                  const enr = data.enrichment as Record<string, Record<string, unknown>>;
                  if (!enr.rdns || !enr.rdns.hostname) return null;
                  return (
                    <div className="flex gap-2 text-2xs">
                      <span className="text-text-muted w-16 flex-shrink-0">rDNS</span>
                      <span className="text-text-primary font-mono">
                        {String(enr.rdns.hostname)}
                      </span>
                    </div>
                  );
                })()}
              </div>
            </div>
          )}

          {/* Tabs */}
          <div className="flex border-b border-border px-3 overflow-x-auto">
            {tabs.map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={clsx(
                  "px-3 py-1.5 text-2xs font-semibold transition-colors border-b-2 capitalize whitespace-nowrap",
                  tab === t
                    ? "border-accent text-accent"
                    : "border-transparent text-text-muted hover:text-text-secondary"
                )}
              >
                {t === "host" ? "Host Settings" : t}
              </button>
            ))}
          </div>

          <div className="p-3 space-y-2">
            {/* Alerts tab */}
            {tab === "alerts" && (
              data.alerts?.length ? data.alerts.map((a) => (
                <Link
                  key={a.id}
                  href={`/alerts/${a.id}`}
                  className="block p-2 rounded bg-bg-elevated hover:bg-bg-overlay border border-border transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <span
                      className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                      style={{ backgroundColor: SEV[a.severity]?.color || "#666" }}
                    />
                    <span className="text-2xs text-text-primary truncate flex-1">{a.title}</span>
                    <span className="text-2xs text-text-muted font-mono">{timeAgo(a.created_at)}</span>
                  </div>
                  <div className="flex gap-1 mt-1">
                    <span className="text-2xs font-mono text-text-muted">{a.rule_name}</span>
                    <span className="text-2xs text-text-muted/50">|</span>
                    <span className="text-2xs font-mono" style={{ color: SEV[a.severity]?.color }}>
                      {a.severity}
                    </span>
                  </div>
                </Link>
              )) : <p className="text-2xs text-text-muted italic">No alerts for this IP</p>
            )}

            {/* Connections tab */}
            {tab === "connections" && (
              <div className="space-y-3">
                {data.connections?.outbound && (
                  <div>
                    <div className="text-2xs text-text-muted uppercase tracking-wider font-semibold mb-1">Outbound</div>
                    <div className="grid grid-cols-3 gap-2 text-2xs">
                      <div className="bg-bg-elevated rounded p-2 text-center">
                        <div className="font-mono text-text-primary font-bold">{fmtNum(data.connections.outbound.total || 0)}</div>
                        <div className="text-text-muted">Connections</div>
                      </div>
                      <div className="bg-bg-elevated rounded p-2 text-center">
                        <div className="font-mono text-text-primary font-bold">{data.connections.outbound.unique_peers || 0}</div>
                        <div className="text-text-muted">Peers</div>
                      </div>
                      <div className="bg-bg-elevated rounded p-2 text-center">
                        <div className="font-mono text-severity-critical font-bold">{data.connections.outbound.malicious || 0}</div>
                        <div className="text-text-muted">Malicious</div>
                      </div>
                    </div>
                  </div>
                )}
                {data.connections?.inbound && (
                  <div>
                    <div className="text-2xs text-text-muted uppercase tracking-wider font-semibold mb-1">Inbound</div>
                    <div className="grid grid-cols-3 gap-2 text-2xs">
                      <div className="bg-bg-elevated rounded p-2 text-center">
                        <div className="font-mono text-text-primary font-bold">{fmtNum(data.connections.inbound.total || 0)}</div>
                        <div className="text-text-muted">Connections</div>
                      </div>
                      <div className="bg-bg-elevated rounded p-2 text-center">
                        <div className="font-mono text-text-primary font-bold">{data.connections.inbound.unique_peers || 0}</div>
                        <div className="text-text-muted">Peers</div>
                      </div>
                      <div className="bg-bg-elevated rounded p-2 text-center">
                        <div className="font-mono text-severity-critical font-bold">{data.connections.inbound.malicious || 0}</div>
                        <div className="text-text-muted">Malicious</div>
                      </div>
                    </div>
                  </div>
                )}
                <div>
                  <div className="text-2xs text-text-muted uppercase tracking-wider font-semibold mb-1">Top Peers</div>
                  {data.top_peers?.map(p => (
                    <button
                      key={p.ip}
                      onClick={() => onPivot(p.ip)}
                      className="flex items-center gap-2 w-full py-1.5 px-2 rounded hover:bg-bg-elevated text-2xs transition-colors"
                    >
                      <span className="font-mono text-text-primary">{p.ip}</span>
                      <span className="ml-auto font-mono text-text-muted">{fmtNum(p.connections)}</span>
                      {p.malicious > 0 && (
                        <span className="font-mono text-severity-critical">{p.malicious} mal</span>
                      )}
                      <ChevronRight className="w-3 h-3 text-text-muted/40" />
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Logs tab */}
            {tab === "logs" && (
              data.recent_logs?.length ? (
                <div className="space-y-1">
                  {data.recent_logs.map((l) => (
                    <div
                      key={l.id}
                      className={clsx(
                        "flex items-center gap-2 py-1 px-2 rounded text-2xs font-mono",
                        l.is_malicious ? "bg-severity-critical/8" : "bg-bg-elevated"
                      )}
                    >
                      <span className={l.is_malicious ? "text-severity-critical" : "text-text-muted"}>
                        {l.protocol || "\u2014"}
                      </span>
                      <span className="text-text-secondary">:{l.port || "\u2014"}</span>
                      <span className={clsx(
                        "px-1 rounded",
                        l.action === "deny" || l.action === "block"
                          ? "bg-severity-critical/15 text-severity-critical"
                          : "text-text-muted"
                      )}>
                        {l.action || "\u2014"}
                      </span>
                      <span className="ml-auto text-text-muted">{timeAgo(l.timestamp)}</span>
                    </div>
                  ))}
                </div>
              ) : <p className="text-2xs text-text-muted italic">No recent logs</p>
            )}

            {/* Enrichment tab */}
            {tab === "enrichment" && (
              data.enrichment && Object.keys(data.enrichment).length > 0 ? (
                <div className="space-y-3">
                  {Object.entries(data.enrichment).map(([mod, d]) => (
                    <div key={mod}>
                      <div className="text-2xs text-text-muted uppercase tracking-wider font-semibold mb-1">
                        {mod}
                      </div>
                      <div className="bg-bg-elevated rounded p-2 space-y-0.5">
                        {Object.entries(d as Record<string, unknown>).map(([k, v]) => (
                          <div key={k} className="flex gap-2 text-2xs">
                            <span className="text-text-muted w-20 flex-shrink-0 font-mono">{k}</span>
                            <span className="text-text-primary font-mono break-all">
                              {typeof v === "object" ? JSON.stringify(v) : String(v ?? "\u2014")}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ) : <p className="text-2xs text-text-muted italic">No enrichment data</p>
            )}

            {/* Host Settings tab */}
            {tab === "host" && (
              <div className="space-y-4">
                <div>
                  <label className="text-2xs text-text-muted uppercase tracking-wider font-semibold block mb-1.5">
                    Display Name
                  </label>
                  <input
                    type="text"
                    value={hostName}
                    onChange={e => setHostName(e.target.value)}
                    placeholder="e.g. Core-FW-01"
                    className="w-full ti-input text-xs py-1.5"
                  />
                </div>
                <div>
                  <label className="text-2xs text-text-muted uppercase tracking-wider font-semibold block mb-1.5">
                    Device Type
                  </label>
                  <select
                    value={deviceType}
                    onChange={e => setDeviceType(e.target.value)}
                    className="w-full ti-input text-xs py-1.5"
                  >
                    {DEVICE_TYPES.map(dt => (
                      <option key={dt} value={dt}>{deviceLabel(dt)}</option>
                    ))}
                  </select>
                </div>
                <div className="flex items-center gap-2 text-2xs text-text-muted">
                  <MapPin className="w-3 h-3" />
                  <span>
                    Position: {node?.saved_x != null ? `(${Math.round(node.saved_x)}, ${Math.round(node.saved_y ?? 0)})` : "Auto"}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={saveHost}
                    disabled={saving}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold bg-accent/15 text-accent hover:bg-accent/25 transition-colors disabled:opacity-50"
                  >
                    {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
                    Save Host
                  </button>
                  {saveMsg && (
                    <span className={clsx(
                      "text-2xs font-semibold",
                      saveMsg === "Saved" ? "text-green-400" : "text-severity-critical"
                    )}>
                      {saveMsg}
                    </span>
                  )}
                </div>
                <div className="border-t border-border pt-3">
                  <div className="text-2xs text-text-muted">
                    Drag the node on the map to set its position. Position is saved automatically when you release the mouse.
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   FUZZY SEARCH HELPER
   ═══════════════════════════════════════════════════════════════════════════ */

function fuzzyMatch(query: string, text: string): boolean {
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  if (t.includes(q)) return true;
  // Character-by-character subsequence match
  let qi = 0;
  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] === q[qi]) qi++;
  }
  return qi === q.length;
}

/* ═══════════════════════════════════════════════════════════════════════════
   MAIN PAGE COMPONENT
   ═══════════════════════════════════════════════════════════════════════════ */

export default function NetworkPage() {
  // ── State ──────────────────────────────────────────────────────────────────
  const [hours, setHours] = useState(24);
  const [sevFilter, setSevFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [countryFilter, setCountryFilter] = useState("all");
  const [showInfra, setShowInfra] = useState(false);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<GEdge | null>(null);
  const [hoveredNode, setHoveredNode] = useState<GNode | null>(null);
  const [activeChain, setActiveChain] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });
  const [timelineIdx, setTimelineIdx] = useState(999);
  const [playing, setPlaying] = useState(false);
  const [layoutNodes, setLayoutNodes] = useState<GNode[]>([]);
  const [rightPanel, setRightPanel] = useState<"chains" | "countries" | null>("chains");
  const [filterExpr, setFilterExpr] = useState("");
  const [draggingNode, setDraggingNode] = useState<string | null>(null);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });

  // [IMPROVEMENT 6] Search bar state
  const [searchQuery, setSearchQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchDropdownIdx, setSearchDropdownIdx] = useState(0);
  const searchInputRef = useRef<HTMLInputElement>(null);

  // [IMPROVEMENT 7] Minimap drag state
  const [minimapDragging, setMinimapDragging] = useState(false);

  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const minimapRef = useRef<SVGSVGElement>(null);

  // [IMPROVEMENT 1] Responsive canvas dimensions
  const [canvasSize, setCanvasSize] = useState({ w: 960, h: 660 });
  const W = canvasSize.w;
  const H = canvasSize.h;

  // [IMPROVEMENT 1] ResizeObserver on SVG container
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        if (width > 0 && height > 0) {
          setCanvasSize({ w: Math.round(width), h: Math.round(height) });
        }
      }
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // ── Filter parsing ─────────────────────────────────────────────────────────
  const filterClauses = useMemo(() => parseFilterExpr(filterExpr), [filterExpr]);

  const removeFilterClause = useCallback((idx: number) => {
    const clauses = parseFilterExpr(filterExpr);
    clauses.splice(idx, 1);
    // Rebuild expression
    if (clauses.length === 0) { setFilterExpr(""); return; }
    // Fix conjunctions
    const parts: string[] = [];
    clauses.forEach((c, i) => {
      parts.push(`${c.field} ${c.op} ${c.value}`);
      if (i < clauses.length - 1) {
        parts.push(c.conjunction || "and");
      }
    });
    setFilterExpr(parts.join(" "));
  }, [filterExpr]);

  // ── Data fetching ──────────────────────────────────────────────────────────
  const params = new URLSearchParams({
    hours: String(hours),
    timeline_buckets: "24",
    ...(sevFilter !== "all" ? { severity: sevFilter } : {}),
    ...(typeFilter !== "all" ? { node_type: typeFilter } : {}),
    ...(showInfra ? { show_infra: "true" } : {}),
  });

  const { data, isLoading, error, mutate } = useSWR<GraphData>(
    `/network/graph?${params}`,
    () => apiFetch<GraphData>(`/network/graph?${params}`),
    { refreshInterval: 60000 },
  );

  // ── Timeline init ──────────────────────────────────────────────────────────
  useEffect(() => {
    if (data?.timeline?.length) setTimelineIdx(data.timeline.length - 1);
  }, [data?.timeline?.length]);

  // ── Replay animation ──────────────────────────────────────────────────────
  useEffect(() => {
    if (!playing || !data?.timeline?.length) return;
    const interval = setInterval(() => {
      setTimelineIdx(prev => {
        if (prev >= (data?.timeline?.length || 1) - 1) {
          setPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 600);
    return () => clearInterval(interval);
  }, [playing, data?.timeline?.length]);

  // ── Node / edge pre-filter (country) ───────────────────────────────────────
  const preFilteredNodes = useMemo(() => {
    if (!data?.nodes) return [];
    let nodes = data.nodes;
    if (countryFilter !== "all") {
      nodes = nodes.filter(n =>
        n.country_code === countryFilter || n.type === "internal" || n.collapsed
      );
    }
    return nodes;
  }, [data?.nodes, countryFilter]);

  const preFilteredEdges = useMemo(() => {
    if (!data?.edges) return [];
    const visibleIds = new Set(preFilteredNodes.map(n => n.id));
    return data.edges.filter(e => visibleIds.has(e.source) && visibleIds.has(e.target));
  }, [data?.edges, preFilteredNodes]);

  // ── Apply PAN-OS filter ────────────────────────────────────────────────────
  const { nodes: filteredNodes, edges: filteredEdges } = useMemo(
    () => applyFilters(preFilteredNodes, preFilteredEdges, filterClauses),
    [preFilteredNodes, preFilteredEdges, filterClauses],
  );

  // ── Run boundary layout ────────────────────────────────────────────────────
  useEffect(() => {
    if (!filteredNodes.length) { setLayoutNodes([]); return; }
    const cloned = filteredNodes.map(n => ({ ...n, vx: 0, vy: 0 }));
    const result = runBoundaryLayout(cloned, filteredEdges, data?.clusters || [], W, H, 120);
    setLayoutNodes([...result]);
  }, [filteredNodes, filteredEdges, data?.clusters, W, H]);

  // ── Timeline-based visibility ──────────────────────────────────────────────
  const visibleNodes = useMemo(() => {
    if (!data?.timeline?.length || timelineIdx >= data.timeline.length - 1) return layoutNodes;
    const cutoff = data.timeline[timelineIdx]?.timestamp;
    if (!cutoff) return layoutNodes;
    const cutoffTs = new Date(cutoff).getTime();
    return layoutNodes.map(n => ({
      ...n,
      _visible: !n.last_alert_at || new Date(n.last_alert_at).getTime() <= cutoffTs || !n.has_alert,
    }));
  }, [layoutNodes, timelineIdx, data?.timeline]);

  const visibleEdges = useMemo(() => {
    if (!data?.timeline?.length || timelineIdx >= data.timeline.length - 1) return filteredEdges;
    const cutoff = data.timeline[timelineIdx]?.timestamp;
    if (!cutoff) return filteredEdges;
    const cutoffTs = new Date(cutoff).getTime();
    return filteredEdges.filter(e => {
      if (!e.first_seen) return true;
      return new Date(e.first_seen).getTime() <= cutoffTs;
    });
  }, [filteredEdges, timelineIdx, data?.timeline]);

  const nodeMap = useMemo(() => new Map(visibleNodes.map(n => [n.id, n])), [visibleNodes]);

  // ── Attack chain ───────────────────────────────────────────────────────────
  const chainIps = useMemo(() => {
    if (!activeChain || !data?.attack_chains) return new Set<string>();
    const chain = data.attack_chains.find(c => c.id === activeChain);
    if (!chain) return new Set<string>();
    return new Set(chain.path.map(p => p.ip));
  }, [activeChain, data?.attack_chains]);

  const chainEdges = useMemo(() => {
    if (!chainIps.size) return new Set<string>();
    const set = new Set<string>();
    for (const e of visibleEdges) {
      if (chainIps.has(e.source) && chainIps.has(e.target)) set.add(`${e.source}->${e.target}`);
    }
    return set;
  }, [chainIps, visibleEdges]);

  // ── [IMPROVEMENT 2] Edge grouping for parallel edge offset ─────────────────
  const edgeGroups = useMemo(() => {
    const groups = new Map<string, { edges: GEdge[]; indices: number[] }>();
    visibleEdges.forEach((edge, i) => {
      const key = [edge.source, edge.target].sort().join("|");
      if (!groups.has(key)) groups.set(key, { edges: [], indices: [] });
      const g = groups.get(key)!;
      g.edges.push(edge);
      g.indices.push(i);
    });
    return groups;
  }, [visibleEdges]);

  // ── [IMPROVEMENT 6] Search matches ─────────────────────────────────────────
  const searchMatches = useMemo(() => {
    if (!searchQuery.trim() || !visibleNodes.length) return [];
    return visibleNodes
      .filter(n => {
        const q = searchQuery.trim();
        return fuzzyMatch(q, n.ip) || fuzzyMatch(q, n.host_name || "") || fuzzyMatch(q, n.label || "");
      })
      .slice(0, 8);
  }, [searchQuery, visibleNodes]);

  // ── Pan / Zoom handlers ────────────────────────────────────────────────────
  const svgPoint = useCallback((clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const rect = svg.getBoundingClientRect();
    return {
      x: (clientX - rect.left - pan.x) / zoom,
      y: (clientY - rect.top - pan.y) / zoom,
    };
  }, [pan, zoom]);

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    const nodeEl = (e.target as SVGElement).closest("[data-node]");
    if (nodeEl) {
      const nodeId = nodeEl.getAttribute("data-node") || "";
      const pt = svgPoint(e.clientX, e.clientY);
      const n = nodeMap.get(nodeId);
      if (n) {
        setDraggingNode(nodeId);
        setDragOffset({ x: pt.x - n.x, y: pt.y - n.y });
        e.preventDefault();
      }
      return;
    }
    setIsPanning(true);
    setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  }, [pan, svgPoint, nodeMap]);

  const onMouseMove = useCallback((e: React.MouseEvent) => {
    if (draggingNode) {
      const pt = svgPoint(e.clientX, e.clientY);
      setLayoutNodes(prev => prev.map(n =>
        n.id === draggingNode ? { ...n, x: pt.x - dragOffset.x, y: pt.y - dragOffset.y } : n
      ));
      return;
    }
    if (!isPanning) return;
    setPan({ x: e.clientX - panStart.x, y: e.clientY - panStart.y });
  }, [draggingNode, isPanning, panStart, svgPoint, dragOffset]);

  const onMouseUp = useCallback(async () => {
    if (draggingNode) {
      const n = layoutNodes.find(n => n.id === draggingNode);
      if (n) {
        try {
          await apiFetch(`/network/hosts/${n.ip}`, {
            method: "PUT",
            body: JSON.stringify({
              x_position: Math.round(n.x),
              y_position: Math.round(n.y),
            }),
          });
        } catch {
          // silent
        }
      }
      setDraggingNode(null);
      return;
    }
    setIsPanning(false);
  }, [draggingNode, layoutNodes]);

  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    setZoom(z => Math.max(0.2, Math.min(4, z - e.deltaY * 0.001)));
  }, []);

  const resetView = useCallback(() => { setZoom(1); setPan({ x: 0, y: 0 }); }, []);

  // ── [IMPROVEMENT 8] Fit all nodes into view ────────────────────────────────
  const fitAll = useCallback(() => {
    if (!visibleNodes.length || W === 0 || H === 0) return;
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    for (const n of visibleNodes) {
      minX = Math.min(minX, n.x);
      maxX = Math.max(maxX, n.x);
      minY = Math.min(minY, n.y);
      maxY = Math.max(maxY, n.y);
    }
    const pad = 60;
    const bw = maxX - minX + pad * 2;
    const bh = maxY - minY + pad * 2;
    const newZoom = Math.max(0.2, Math.min(2, Math.min(W / bw, H / bh)));
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    setZoom(newZoom);
    setPan({ x: W / 2 - cx * newZoom, y: H / 2 - cy * newZoom });
  }, [visibleNodes, W, H]);

  // ── [IMPROVEMENT 8] Keyboard shortcuts ─────────────────────────────────────
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      const isInput = target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.tagName === "SELECT";

      // Ctrl+K / Cmd+K: focus search regardless
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen(true);
        setTimeout(() => searchInputRef.current?.focus(), 50);
        return;
      }

      if (isInput) return;

      switch (e.key) {
        case "f":
        case "F":
          e.preventDefault();
          fitAll();
          break;
        case "Escape":
          e.preventDefault();
          if (searchOpen) {
            setSearchOpen(false);
            setSearchQuery("");
          } else {
            setSelectedIp(null);
          }
          break;
        case "+":
        case "=":
          e.preventDefault();
          setZoom(z => Math.min(4, z + 0.3));
          break;
        case "-":
          e.preventDefault();
          setZoom(z => Math.max(0.2, z - 0.3));
          break;
        case "ArrowUp":
          e.preventDefault();
          setPan(p => ({ ...p, y: p.y + 50 }));
          break;
        case "ArrowDown":
          e.preventDefault();
          setPan(p => ({ ...p, y: p.y - 50 }));
          break;
        case "ArrowLeft":
          e.preventDefault();
          setPan(p => ({ ...p, x: p.x + 50 }));
          break;
        case "ArrowRight":
          e.preventDefault();
          setPan(p => ({ ...p, x: p.x - 50 }));
          break;
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [fitAll, searchOpen]);

  // ── [IMPROVEMENT 6] Search result selection ────────────────────────────────
  const selectSearchResult = useCallback((node: GNode) => {
    setZoom(2.5);
    setPan({ x: W / 2 - node.x * 2.5, y: H / 2 - node.y * 2.5 });
    setSelectedIp(node.id);
    setSearchOpen(false);
    setSearchQuery("");
  }, [W, H]);

  // ── [IMPROVEMENT 6] Search keyboard navigation ────────────────────────────
  const onSearchKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSearchDropdownIdx(prev => Math.min(prev + 1, searchMatches.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSearchDropdownIdx(prev => Math.max(prev - 1, 0));
    } else if (e.key === "Enter" && searchMatches.length > 0) {
      e.preventDefault();
      selectSearchResult(searchMatches[searchDropdownIdx] || searchMatches[0]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      setSearchOpen(false);
      setSearchQuery("");
    }
  }, [searchMatches, searchDropdownIdx, selectSearchResult]);

  // ── [IMPROVEMENT 7] Minimap mouse handlers ────────────────────────────────
  const MINIMAP_W = 160;
  const MINIMAP_H = 120;

  const minimapPan = useCallback((clientX: number, clientY: number) => {
    const el = minimapRef.current;
    if (!el || !visibleNodes.length) return;
    const rect = el.getBoundingClientRect();
    // Node bounding box
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    for (const n of visibleNodes) {
      minX = Math.min(minX, n.x);
      maxX = Math.max(maxX, n.x);
      minY = Math.min(minY, n.y);
      maxY = Math.max(maxY, n.y);
    }
    const padMm = 20;
    const bw = maxX - minX + padMm * 2;
    const bh = maxY - minY + padMm * 2;
    const mmScale = Math.min(MINIMAP_W / bw, MINIMAP_H / bh);
    // Where did user click in node-space coords?
    const mmX = (clientX - rect.left) / mmScale + (minX - padMm);
    const mmY = (clientY - rect.top) / mmScale + (minY - padMm);
    setPan({ x: W / 2 - mmX * zoom, y: H / 2 - mmY * zoom });
  }, [visibleNodes, zoom, W, H]);

  const onMinimapMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setMinimapDragging(true);
    minimapPan(e.clientX, e.clientY);
  }, [minimapPan]);

  useEffect(() => {
    if (!minimapDragging) return;
    const onMove = (e: MouseEvent) => { minimapPan(e.clientX, e.clientY); };
    const onUp = () => { setMinimapDragging(false); };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [minimapDragging, minimapPan]);

  // ── Node rendering helpers ─────────────────────────────────────────────────
  function nodeSize(n: GNode): number {
    if (isBoundary(n)) return 22;
    if (n.collapsed) return 16;
    const base = 7;
    const threat = Math.min(n.threat_score, 100);
    return base + (threat / 100) * 13;
  }

  function nodeOpacity(n: GNode): number {
    if (n._visible === false) return 0.1;
    if (chainIps.size > 0) return chainIps.has(n.id) ? 1 : 0.12;
    if (n.collapsed) return 0.4;
    if (n.threat_score >= 50) return 1;
    if (n.threat_score >= 20) return 0.85;
    if (n.has_alert) return 0.75;
    return 0.3;
  }

  function nodeStroke(n: GNode): string {
    if (selectedIp === n.id) return "#ffffff";
    if (chainIps.has(n.id)) return "#f04060";
    if (n.ti_match) return "#f04060";
    const dt = n.device_type || "unknown";
    return DEVICE_COLORS[dt] || DEVICE_COLORS.unknown;
  }

  function nodeFill(n: GNode): string {
    if (n.collapsed) return "#475569";
    if (n.has_alert) return SEV[n.severity]?.color || "#60809a";
    const dt = n.device_type || "unknown";
    if (DEVICE_COLORS[dt]) return DEVICE_COLORS[dt];
    if (n.type === "internal") return "#38bdf8";
    return "#64748b";
  }

  // ── [IMPROVEMENT 9] Label visibility helper ────────────────────────────────
  function shouldShowLabel(n: GNode): boolean {
    if (zoom >= 1.2) return true;
    if (selectedIp === n.id) return true;
    if (n.threat_score >= 60) return true;
    if (isBoundary(n)) return true;
    return false;
  }

  // ── Stats ──────────────────────────────────────────────────────────────────
  const alertedNodes = visibleNodes.filter(n => n.has_alert && !n.collapsed).length;
  const malEdges = visibleEdges.filter(e => e.malicious).length;
  const c2Edges = visibleEdges.filter(e => e.edge_type === "c2").length;
  const countries = data?.countries || [];

  const onHostSaved = useCallback(() => {
    mutate();
  }, [mutate]);

  const centerX = W / 2;

  // ── [IMPROVEMENT 5] Heatmap glow gradient IDs ─────────────────────────────
  const heatmapGradients = useMemo(() => {
    const gradients: { id: string; color: string }[] = [];
    const seen = new Set<string>();
    for (const n of visibleNodes) {
      if (n.threat_score < 40 || n.collapsed) continue;
      let glowColor = "#f0a830"; // medium default
      if (n.severity === "critical") glowColor = "#f04060";
      else if (n.severity === "high") glowColor = "#f07030";
      const gid = `heatglow-${n.severity}`;
      if (!seen.has(gid)) {
        seen.add(gid);
        gradients.push({ id: gid, color: glowColor });
      }
    }
    return gradients;
  }, [visibleNodes]);

  // ── [IMPROVEMENT 7] Minimap computed data ─────────────────────────────────
  const minimapData = useMemo(() => {
    if (!visibleNodes.length) return null;
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    for (const n of visibleNodes) {
      minX = Math.min(minX, n.x);
      maxX = Math.max(maxX, n.x);
      minY = Math.min(minY, n.y);
      maxY = Math.max(maxY, n.y);
    }
    const padMm = 20;
    const bw = maxX - minX + padMm * 2;
    const bh = maxY - minY + padMm * 2;
    const mmScale = Math.min(MINIMAP_W / bw, MINIMAP_H / bh);
    // Viewport rect in node-space
    const vpLeft = (-pan.x) / zoom;
    const vpTop = (-pan.y) / zoom;
    const vpW = W / zoom;
    const vpH = H / zoom;
    // Convert to minimap coords
    const vpRectX = (vpLeft - (minX - padMm)) * mmScale;
    const vpRectY = (vpTop - (minY - padMm)) * mmScale;
    const vpRectW = vpW * mmScale;
    const vpRectH = vpH * mmScale;
    return {
      minX: minX - padMm, minY: minY - padMm, mmScale,
      vpRectX, vpRectY, vpRectW, vpRectH,
    };
  }, [visibleNodes, pan, zoom, W, H]);

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════════════════════

  return (
    <div className="space-y-3">
      {/* ═══ HEADER ═══ */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold text-text-primary flex items-center gap-2">
            <Crosshair className="w-5 h-5 text-severity-critical" />
            Network Map
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Firewall boundary layout with device-type aware visualization
          </p>
        </div>
        <button onClick={() => mutate()} className="btn-ghost text-xs flex items-center gap-1.5">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* ═══ PAN-OS FILTER BAR ═══ */}
      <FilterBar
        value={filterExpr}
        onChange={setFilterExpr}
        clauses={filterClauses}
        onRemoveClause={removeFilterClause}
      />

      {/* ═══ CONTROLS BAR ═══ */}
      <div className="card p-3 flex flex-wrap items-center gap-3">
        <Filter className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />

        <div className="flex items-center gap-1.5">
          <label className="text-2xs text-text-muted">Window</label>
          <select
            value={hours}
            onChange={e => setHours(Number(e.target.value))}
            className="ti-input text-xs py-1"
          >
            {[1, 6, 12, 24, 48, 72, 168].map(h => (
              <option key={h} value={h}>{h < 24 ? `${h}h` : `${h / 24}d`}</option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-1.5">
          <label className="text-2xs text-text-muted">Min Severity</label>
          <select
            value={sevFilter}
            onChange={e => setSevFilter(e.target.value)}
            className="ti-input text-xs py-1"
          >
            <option value="all">All</option>
            {["critical", "high", "medium", "low"].map(s => (
              <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-1.5">
          <label className="text-2xs text-text-muted">Type</label>
          <select
            value={typeFilter}
            onChange={e => setTypeFilter(e.target.value)}
            className="ti-input text-xs py-1"
          >
            <option value="all">All</option>
            <option value="internal">Internal</option>
            <option value="external">External</option>
          </select>
        </div>

        <div className="flex items-center gap-1.5">
          <label className="text-2xs text-text-muted">Country</label>
          <select
            value={countryFilter}
            onChange={e => setCountryFilter(e.target.value)}
            className="ti-input text-xs py-1"
          >
            <option value="all">All Countries</option>
            {countries.map(c => (
              <option key={c.country_code} value={c.country_code}>
                {flag(c.country_code)} {c.country_name || c.country_code} ({c.node_count})
              </option>
            ))}
          </select>
        </div>

        <label className="flex items-center gap-1.5 text-2xs text-text-muted cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showInfra}
            onChange={e => setShowInfra(e.target.checked)}
            className="rounded border-border text-accent"
          />
          Show Infrastructure
        </label>

        {/* Stats badges */}
        <div className="ml-auto flex items-center gap-3 text-2xs text-text-muted">
          <span><span className="text-text-primary font-mono">{data?.node_count ?? 0}</span> hosts</span>
          <span><span className="text-text-primary font-mono">{data?.edge_count ?? 0}</span> flows</span>
          {(data?.chain_count ?? 0) > 0 && (
            <span className="text-severity-critical font-semibold">
              <span className="font-mono">{data?.chain_count}</span> attack chains
            </span>
          )}
          {(data?.infra_collapsed ?? 0) > 0 && (
            <span><span className="font-mono">{data?.infra_collapsed}</span> collapsed</span>
          )}
        </div>
      </div>

      {/* ═══ MAIN AREA: Graph + Side Panel ═══ */}
      <div className="flex gap-3" style={{ minHeight: 660 }}>

        {/* ── Graph Canvas ── */}
        <div
          ref={containerRef}
          className="flex-1 card overflow-hidden relative"
          style={{ minHeight: 660 }}
        >
          {isLoading && (
            <div className="absolute inset-0 flex items-center justify-center bg-bg-surface/80 z-20">
              <Loader2 className="w-6 h-6 animate-spin text-text-muted" />
            </div>
          )}
          {error && (
            <div className="absolute inset-0 flex items-center justify-center gap-2 text-text-muted text-sm z-20">
              <AlertTriangle className="w-4 h-4 text-severity-high" /> Failed to load network data
            </div>
          )}
          {!isLoading && !error && visibleNodes.length === 0 && (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 text-text-muted z-20">
              <Network className="w-10 h-10 opacity-25" />
              <span className="text-sm">No network data for the selected filters</span>
            </div>
          )}

          {/* [IMPROVEMENT 6] Search bar overlay */}
          <div className="absolute top-3 left-12 z-20" style={{ width: 240 }}>
            <div className="relative">
              <div className={clsx(
                "flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border transition-all text-xs",
                searchOpen
                  ? "bg-bg-surface border-accent/50 shadow-glow"
                  : "bg-bg-surface/80 border-border hover:border-border-strong"
              )}>
                <Search className="w-3 h-3 text-text-muted flex-shrink-0" />
                <input
                  ref={searchInputRef}
                  type="text"
                  value={searchQuery}
                  onChange={e => { setSearchQuery(e.target.value); setSearchDropdownIdx(0); }}
                  onFocus={() => setSearchOpen(true)}
                  onBlur={() => setTimeout(() => setSearchOpen(false), 200)}
                  onKeyDown={onSearchKeyDown}
                  placeholder="Search hosts... (Ctrl+K)"
                  className="flex-1 bg-transparent text-xs text-text-primary placeholder:text-text-muted/50 outline-none font-mono min-w-0"
                />
                {searchQuery && (
                  <button
                    onMouseDown={e => { e.preventDefault(); setSearchQuery(""); }}
                    className="text-text-muted hover:text-text-primary"
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>
              {/* Search dropdown */}
              {searchOpen && searchQuery.trim() && searchMatches.length > 0 && (
                <div className="absolute top-full left-0 right-0 mt-1 card p-1 max-h-56 overflow-y-auto">
                  {searchMatches.map((n, i) => {
                    const sevInfo = SEV[n.severity] || SEV.info;
                    return (
                      <button
                        key={n.id}
                        onMouseDown={e => { e.preventDefault(); selectSearchResult(n); }}
                        className={clsx(
                          "w-full text-left px-2.5 py-1.5 rounded text-xs transition-colors flex items-center gap-2",
                          i === searchDropdownIdx
                            ? "bg-accent/10 text-accent"
                            : "text-text-secondary hover:bg-bg-elevated"
                        )}
                      >
                        <span
                          className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                          style={{ backgroundColor: sevInfo.color }}
                        />
                        <span className="font-mono truncate flex-1">{n.host_name || n.ip}</span>
                        {n.host_name && (
                          <span className="text-2xs text-text-muted font-mono">{n.ip}</span>
                        )}
                        {n.country_code && (
                          <span className="text-2xs">{flag(n.country_code)}</span>
                        )}
                      </button>
                    );
                  })}
                </div>
              )}
              {searchOpen && searchQuery.trim() && searchMatches.length === 0 && (
                <div className="absolute top-full left-0 right-0 mt-1 card p-3 text-2xs text-text-muted italic text-center">
                  No matching hosts
                </div>
              )}
            </div>
          </div>

          {/* Zoom controls */}
          <div className="absolute top-3 left-3 flex flex-col gap-1 z-10">
            <button
              onClick={() => setZoom(z => Math.min(4, z + 0.25))}
              className="w-7 h-7 card flex items-center justify-center hover:border-accent/40 text-text-muted hover:text-text-primary"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoom(z => Math.max(0.2, z - 0.25))}
              className="w-7 h-7 card flex items-center justify-center hover:border-accent/40 text-text-muted hover:text-text-primary"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={fitAll}
              className="w-7 h-7 card flex items-center justify-center hover:border-accent/40 text-text-muted hover:text-text-primary"
              title="Fit all nodes (F)"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Legend */}
          <div className="absolute bottom-10 left-3 card p-2.5 z-10 space-y-1 text-2xs text-text-muted max-h-64 overflow-y-auto">
            <div className="font-semibold text-text-secondary mb-1">Edge Types</div>
            {Object.entries(EDGE_STYLE)
              .filter(([k]) => k !== "infra" || showInfra)
              .map(([key, s]) => (
                <div key={key} className="flex items-center gap-1.5">
                  <svg width="24" height="6">
                    <line
                      x1="0" y1="3" x2="24" y2="3"
                      stroke={s.color}
                      strokeWidth={Math.max(s.width, 1.5)}
                      strokeDasharray={s.dash || "none"}
                    />
                  </svg>
                  <span>{s.label}</span>
                </div>
              ))}
            <div className="border-t border-border mt-1 pt-1 font-semibold text-text-secondary">
              Device Shapes
            </div>
            <div className="flex items-center gap-1.5">
              <svg width="14" height="14" viewBox="0 0 14 14">
                <polygon
                  points="7,1 12.5,4 12.5,10 7,13 1.5,10 1.5,4"
                  fill="none" stroke={DEVICE_COLORS.firewall} strokeWidth={1.2}
                />
              </svg>
              <span>Firewall</span>
            </div>
            <div className="flex items-center gap-1.5">
              <svg width="14" height="14" viewBox="0 0 14 14">
                <rect x="2" y="1" width="10" height="12" rx="1" fill="none" stroke={DEVICE_COLORS.server} strokeWidth={1.2} />
              </svg>
              <span>Server</span>
            </div>
            <div className="flex items-center gap-1.5">
              <svg width="14" height="14" viewBox="0 0 14 14">
                <polygon points="7,1 13,7 7,13 1,7" fill="none" stroke={DEVICE_COLORS.switch} strokeWidth={1.2} />
              </svg>
              <span>Switch</span>
            </div>
            <div className="flex items-center gap-1.5">
              <svg width="14" height="14" viewBox="0 0 14 14">
                <circle cx="7" cy="7" r="5" fill="none" stroke={DEVICE_COLORS.router} strokeWidth={1.2} />
              </svg>
              <span>Router</span>
            </div>
            <div className="flex items-center gap-1.5">
              <svg width="14" height="14" viewBox="0 0 14 14">
                <polygon points="7,2 12,12 2,12" fill="none" stroke={DEVICE_COLORS.iot} strokeWidth={1.2} />
              </svg>
              <span>IoT</span>
            </div>
            <div className="text-text-muted/60 mt-0.5">Size = threat score</div>
          </div>

          {/* [IMPROVEMENT 8] Keyboard shortcuts hint */}
          <div className="absolute bottom-3 left-3 z-10 text-2xs text-text-muted/50 font-mono select-none pointer-events-none">
            F Fit All | Esc Deselect | +/- Zoom | Arrows Pan
          </div>

          {/* Edge hover tooltip */}
          {hoveredEdge && (() => {
            const style = EDGE_STYLE[hoveredEdge.edge_type] || EDGE_STYLE.normal;
            return (
              <div className="absolute top-3 right-3 card p-2.5 z-10 text-2xs space-y-1 max-w-xs pointer-events-none">
                <div className="font-mono text-text-primary font-semibold">
                  {hoveredEdge.source} &rarr; {hoveredEdge.target}
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className="px-1.5 py-0.5 rounded font-semibold"
                    style={{ backgroundColor: style.color + "20", color: style.color }}
                  >
                    {style.label}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-text-muted">
                  <span>Protocol</span>
                  <span className="text-text-secondary font-mono">{hoveredEdge.protocol || "\u2014"}</span>
                  <span>Port</span>
                  <span className="text-text-secondary font-mono">{hoveredEdge.port || "\u2014"}</span>
                  <span>Connections</span>
                  <span className="text-text-secondary font-mono">{fmtNum(hoveredEdge.count)}</span>
                  <span>Action</span>
                  <span className="text-text-secondary font-mono">{hoveredEdge.action || "\u2014"}</span>
                  {(hoveredEdge.bytes_sent ?? 0) > 0 && (
                    <>
                      <span>Bytes Sent</span>
                      <span className="text-text-secondary font-mono">{fmtBytes(hoveredEdge.bytes_sent ?? 0)}</span>
                    </>
                  )}
                  {hoveredEdge.malicious && (
                    <>
                      <span className="text-severity-critical">Malicious</span>
                      <span className="text-severity-critical font-mono">{hoveredEdge.malicious_count}</span>
                    </>
                  )}
                  <span>First Seen</span>
                  <span className="text-text-secondary font-mono">{timeAgo(hoveredEdge.first_seen)}</span>
                  <span>Last Seen</span>
                  <span className="text-text-secondary font-mono">{timeAgo(hoveredEdge.last_seen)}</span>
                </div>
              </div>
            );
          })()}

          {/* Node hover tooltip */}
          {hoveredNode && !selectedIp && (
            <div className="absolute top-3 right-3 card p-2.5 z-10 text-2xs space-y-1 max-w-xs pointer-events-none">
              <div className="flex items-center gap-2">
                <span className="font-mono text-text-primary font-semibold">
                  {hoveredNode.host_name || hoveredNode.ip || hoveredNode.label}
                </span>
                {hoveredNode.host_name && (
                  <span className="text-text-muted font-mono">{hoveredNode.ip}</span>
                )}
                {hoveredNode.country_code && (
                  <span>{flag(hoveredNode.country_code)} {hoveredNode.country_name}</span>
                )}
              </div>
              {hoveredNode.device_type && hoveredNode.device_type !== "unknown" && (
                <div className="flex items-center gap-1.5">
                  <span
                    className="px-1.5 py-0.5 rounded font-mono text-2xs"
                    style={{
                      backgroundColor: (DEVICE_COLORS[hoveredNode.device_type] || "#666") + "20",
                      color: DEVICE_COLORS[hoveredNode.device_type] || "#999",
                    }}
                  >
                    {deviceLabel(hoveredNode.device_type)}
                  </span>
                </div>
              )}
              <div className="flex gap-1.5">
                <span
                  className="badge border"
                  style={{
                    background: SEV[hoveredNode.severity]?.bg,
                    borderColor: (SEV[hoveredNode.severity]?.color || "#666") + "40",
                    color: SEV[hoveredNode.severity]?.color,
                  }}
                >
                  {hoveredNode.severity}
                </span>
                <span className="badge border bg-bg-elevated border-border text-text-muted">
                  Score: {hoveredNode.threat_score}
                </span>
              </div>
              {hoveredNode.rules_triggered?.length > 0 && (
                <div className="text-text-muted">
                  Rules: <span className="text-text-secondary">{hoveredNode.rules_triggered.join(", ")}</span>
                </div>
              )}
              {(hoveredNode.attack_stages?.length ?? 0) > 0 && (
                <div className="flex gap-1 flex-wrap">
                  {hoveredNode.attack_stages!.map(s => (
                    <span
                      key={s}
                      className="px-1 py-0.5 rounded text-2xs"
                      style={{
                        backgroundColor: (STAGE_COLORS[s] || "#666") + "20",
                        color: STAGE_COLORS[s] || "#999",
                      }}
                    >
                      {stageLabel(s)}
                    </span>
                  ))}
                </div>
              )}
              <div className="text-text-muted/60 text-2xs">Click to investigate, drag to reposition</div>
            </div>
          )}

          {/* ── SVG Graph ── */}
          <svg
            ref={svgRef}
            width="100%"
            height="100%"
            className="select-none"
            style={{
              cursor: draggingNode ? "grabbing" : isPanning ? "grabbing" : "grab",
              minHeight: 660,
              position: "absolute",
              inset: 0,
            }}
            onMouseDown={onMouseDown}
            onMouseMove={onMouseMove}
            onMouseUp={onMouseUp}
            onMouseLeave={onMouseUp}
            onWheel={onWheel}
          >
            <defs>
              {/* Arrow markers per edge type */}
              {Object.entries(EDGE_STYLE).map(([key, s]) => (
                <marker
                  key={key}
                  id={`arrow-${key}`}
                  markerWidth="6" markerHeight="6" refX="5" refY="3"
                  orient="auto"
                >
                  <path d="M0,0 L0,6 L6,3 z" fill={s.color} />
                </marker>
              ))}
              {/* Glow filters */}
              <filter id="glow-red">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
              <filter id="glow-blue">
                <feGaussianBlur stdDeviation="2" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
              <filter id="glow-selected">
                <feGaussianBlur stdDeviation="4" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>

              {/* [IMPROVEMENT 5] Severity heatmap radial gradients */}
              {heatmapGradients.map(g => (
                <radialGradient key={g.id} id={g.id} cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor={g.color} stopOpacity="0.5" />
                  <stop offset="70%" stopColor={g.color} stopOpacity="0.15" />
                  <stop offset="100%" stopColor={g.color} stopOpacity="0" />
                </radialGradient>
              ))}

              {/* C2 pulse animation + [IMPROVEMENT 4] flow dash animation */}
              <style>{`
                @keyframes c2pulse { 0%,100% { stroke-opacity: 0.9; } 50% { stroke-opacity: 0.3; } }
                .c2-edge { animation: c2pulse 2s ease-in-out infinite; }
                @keyframes nodePulse { 0%,100% { opacity: 0.4; } 50% { opacity: 0; } }
                .threat-pulse { animation: nodePulse 2.5s ease-in-out infinite; }
                @keyframes flowDash { to { stroke-dashoffset: -12; } }
                .flow-animate { stroke-dasharray: 8,4; animation: flowDash 1s linear infinite; }
              `}</style>
            </defs>

            <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
              {/* Firewall boundary line */}
              <line
                x1={centerX} y1={20} x2={centerX} y2={H - 20}
                stroke="#475569" strokeWidth={1} strokeDasharray="8,4" opacity={0.4}
              />
              <rect
                x={centerX - 30} y={6} width={60} height={16} rx={3}
                fill="#1e293b" stroke="#475569" strokeWidth={0.5} opacity={0.8}
              />
              <text
                x={centerX} y={17}
                textAnchor="middle" fontSize="8" fill="#94a3b8"
                className="font-mono select-none pointer-events-none"
              >
                BOUNDARY
              </text>

              {/* Cluster backgrounds */}
              {data?.clusters?.map(cluster => {
                const clusterNodes = cluster.node_ids
                  .map(id => nodeMap.get(id))
                  .filter(Boolean) as GNode[];
                if (clusterNodes.length < 2) return null;
                const cx = clusterNodes.reduce((s, n) => s + n.x, 0) / clusterNodes.length;
                const cy = clusterNodes.reduce((s, n) => s + n.y, 0) / clusterNodes.length;
                let maxDist = 0;
                for (const n of clusterNodes) {
                  const d = Math.sqrt((n.x - cx) ** 2 + (n.y - cy) ** 2);
                  if (d > maxDist) maxDist = d;
                }
                const r = maxDist + 40;
                const clColor = cluster.has_attack_chain
                  ? "#f0406010"
                  : cluster.type === "internal" ? "#38bdf808" : "#64748b06";
                const borderColor = cluster.has_attack_chain
                  ? "#f0406025"
                  : cluster.type === "internal" ? "#38bdf815" : "#64748b10";
                return (
                  <g key={cluster.id}>
                    <circle cx={cx} cy={cy} r={r} fill={clColor} stroke={borderColor} strokeWidth={1} />
                    <text
                      x={cx} y={cy - r + 12}
                      textAnchor="middle" fontSize="8" fill="#64748b" fillOpacity={0.5}
                      className="font-mono select-none pointer-events-none"
                    >
                      {cluster.label}
                    </text>
                  </g>
                );
              })}

              {/* Edges — [IMPROVEMENT 2] parallel offset + [IMPROVEMENT 3] volume width + [IMPROVEMENT 4] flow animation */}
              {Array.from(edgeGroups.values()).map(group => {
                const count = group.edges.length;
                return group.edges.map((edge, idx) => {
                  const src = nodeMap.get(edge.source);
                  const dst = nodeMap.get(edge.target);
                  if (!src || !dst) return null;
                  const style = EDGE_STYLE[edge.edge_type] || EDGE_STYLE.normal;
                  const isChainEdge = chainEdges.has(`${edge.source}->${edge.target}`);
                  const edgeOpacity = chainIps.size > 0
                    ? (isChainEdge ? 1 : 0.06)
                    : (edge.malicious ? 0.8 : 0.35);

                  const dx = dst.x - src.x;
                  const dy = dst.y - src.y;
                  const len = Math.sqrt(dx * dx + dy * dy) || 1;
                  // Normal vector perpendicular to the edge line
                  const nx = -dy / len;
                  const ny = dx / len;
                  const srcR = nodeSize(src);
                  const dstR = nodeSize(dst);
                  const sx = src.x + (dx / len) * srcR;
                  const sy = src.y + (dy / len) * srcR;
                  const ex = dst.x - (dx / len) * (dstR + 6);
                  const ey = dst.y - (dy / len) * (dstR + 6);

                  // [IMPROVEMENT 3] Edge thickness by volume
                  const baseWidth = isChainEdge ? style.width * 1.8 : style.width;
                  const volumeWidth = baseWidth * (0.5 + Math.min(Math.log2(edge.count + 1) / 8, 2.5));

                  // [IMPROVEMENT 4] Flow animation for threat edges
                  const isThreatEdge =
                    edge.edge_type === "c2" ||
                    edge.edge_type === "exfil" ||
                    edge.edge_type === "lateral" ||
                    (edge.edge_type === "recon" && edge.malicious);

                  // [IMPROVEMENT 2] Parallel edge offset
                  if (count > 1) {
                    const offsetPx = (idx - (count - 1) / 2) * 8;
                    const mx = (sx + ex) / 2 + nx * offsetPx;
                    const my = (sy + ey) / 2 + ny * offsetPx;
                    return (
                      <path
                        key={`${edge.source}-${edge.target}-${idx}`}
                        d={`M ${sx} ${sy} Q ${mx} ${my} ${ex} ${ey}`}
                        fill="none"
                        stroke={style.color}
                        strokeWidth={volumeWidth}
                        strokeDasharray={isThreatEdge ? undefined : (style.dash || "none")}
                        markerEnd={`url(#arrow-${edge.edge_type})`}
                        opacity={edgeOpacity}
                        filter={isChainEdge ? "url(#glow-red)" : undefined}
                        className={clsx(
                          isThreatEdge && "flow-animate",
                          edge.edge_type === "c2" && "c2-edge",
                        ) || undefined}
                        onMouseEnter={() => setHoveredEdge(edge)}
                        onMouseLeave={() => setHoveredEdge(null)}
                        style={{ cursor: "pointer" }}
                      />
                    );
                  }

                  // Single edge — render as line
                  return (
                    <line
                      key={`${edge.source}-${edge.target}-${idx}`}
                      x1={sx} y1={sy} x2={ex} y2={ey}
                      stroke={style.color}
                      strokeWidth={volumeWidth}
                      strokeDasharray={isThreatEdge ? undefined : (style.dash || "none")}
                      markerEnd={`url(#arrow-${edge.edge_type})`}
                      opacity={edgeOpacity}
                      filter={isChainEdge ? "url(#glow-red)" : undefined}
                      className={clsx(
                        isThreatEdge && "flow-animate",
                        edge.edge_type === "c2" && "c2-edge",
                      ) || undefined}
                      onMouseEnter={() => setHoveredEdge(edge)}
                      onMouseLeave={() => setHoveredEdge(null)}
                      style={{ cursor: "pointer" }}
                    />
                  );
                });
              })}

              {/* Nodes */}
              {visibleNodes.map(n => {
                const s = nodeSize(n);
                const op = nodeOpacity(n);
                const fill = nodeFill(n);
                const stroke = nodeStroke(n);
                const sw = selectedIp === n.id ? 2.5 : (n.ti_match ? 2 : 1.2);
                const dt = n.device_type || "unknown";
                const isSelected = selectedIp === n.id;
                const showLabel = shouldShowLabel(n);

                return (
                  <g
                    key={n.id}
                    data-node={n.id}
                    style={{ cursor: draggingNode === n.id ? "grabbing" : "pointer" }}
                    onClick={e => {
                      if (draggingNode) return;
                      e.stopPropagation();
                      setSelectedIp(prev => prev === n.id ? null : n.id);
                    }}
                    onMouseEnter={() => { if (!draggingNode) setHoveredNode(n); }}
                    onMouseLeave={() => setHoveredNode(null)}
                  >
                    {/* [IMPROVEMENT 5] Severity heatmap glow */}
                    {n.threat_score >= 40 && !n.collapsed && (() => {
                      const glowId = `heatglow-${n.severity}`;
                      const glowSize = s * (1.5 + n.threat_score / 100);
                      const glowOpacity = n.threat_score / 200;
                      return (
                        <circle
                          cx={n.x} cy={n.y} r={glowSize}
                          fill={`url(#${glowId})`}
                          opacity={glowOpacity}
                          className="pointer-events-none"
                        />
                      );
                    })()}

                    {/* Threat pulse ring for high-threat nodes */}
                    {n.threat_score >= 60 && !n.collapsed && (
                      <circle
                        cx={n.x} cy={n.y} r={s + 6}
                        fill="none" stroke={SEV[n.severity]?.color || "#f04060"}
                        strokeWidth={1}
                        className="threat-pulse"
                      />
                    )}

                    {/* Selected glow */}
                    {isSelected && (
                      <circle
                        cx={n.x} cy={n.y} r={s + 4}
                        fill="none" stroke="#ffffff" strokeWidth={1.5}
                        opacity={0.4}
                        filter="url(#glow-selected)"
                      />
                    )}

                    {/* Device shape */}
                    <DeviceShape
                      x={n.x} y={n.y}
                      deviceType={dt}
                      size={s}
                      fillColor={fill}
                      strokeColor={stroke}
                      strokeWidth={sw}
                      opacity={op}
                      selected={isSelected}
                    />

                    {/* TI match indicator */}
                    {n.ti_match && (
                      <circle
                        cx={n.x + s * 0.7} cy={n.y - s * 0.7} r={3}
                        fill="#f04060" stroke="#1e293b" strokeWidth={1}
                      />
                    )}

                    {/* Alert count badge */}
                    {n.alert_count > 0 && !n.collapsed && (
                      <g>
                        <circle
                          cx={n.x + s * 0.65} cy={n.y + s * 0.65} r={5}
                          fill={SEV[n.severity]?.color || "#f07030"}
                          stroke="#0f172a" strokeWidth={1}
                        />
                        <text
                          x={n.x + s * 0.65} y={n.y + s * 0.65 + 3}
                          textAnchor="middle" fontSize="6" fill="#ffffff" fontWeight="bold"
                          className="select-none pointer-events-none"
                        >
                          {n.alert_count > 9 ? "9+" : n.alert_count}
                        </text>
                      </g>
                    )}

                    {/* [IMPROVEMENT 9] Label with smart hiding + opacity transition */}
                    <text
                      x={n.x} y={n.y + s + 11}
                      textAnchor="middle" fontSize="8"
                      fill={op > 0.3 ? "#94a3b8" : "#475569"}
                      className="font-mono select-none pointer-events-none"
                      style={{
                        opacity: showLabel ? 1 : 0,
                        transition: "opacity 0.15s ease-in-out",
                      }}
                    >
                      {n.host_name || n.label || n.ip}
                    </text>
                    {/* Show IP below label if host_name is set */}
                    {n.host_name && (
                      <text
                        x={n.x} y={n.y + s + 20}
                        textAnchor="middle" fontSize="6.5"
                        fill="#475569"
                        className="font-mono select-none pointer-events-none"
                        style={{
                          opacity: showLabel ? 1 : 0,
                          transition: "opacity 0.15s ease-in-out",
                        }}
                      >
                        {n.ip}
                      </text>
                    )}

                    {/* Collapsed member count */}
                    {n.collapsed && n.member_count && (
                      <text
                        x={n.x} y={n.y + 4}
                        textAnchor="middle" fontSize="9" fill="#94a3b8" fontWeight="bold"
                        className="select-none pointer-events-none"
                      >
                        {n.member_count}
                      </text>
                    )}
                  </g>
                );
              })}
            </g>
          </svg>

          {/* [IMPROVEMENT 7] Minimap */}
          {visibleNodes.length > 0 && minimapData && (
            <div
              className="absolute bottom-3 right-3 z-10 rounded-md overflow-hidden border border-border"
              style={{
                width: MINIMAP_W,
                height: MINIMAP_H,
                backgroundColor: "rgba(15, 23, 42, 0.85)",
              }}
            >
              <svg
                ref={minimapRef}
                width={MINIMAP_W}
                height={MINIMAP_H}
                className="select-none"
                style={{ cursor: minimapDragging ? "grabbing" : "pointer" }}
                onMouseDown={onMinimapMouseDown}
              >
                {/* Nodes as tiny dots */}
                {visibleNodes.map(n => {
                  const mx = (n.x - minimapData.minX) * minimapData.mmScale;
                  const my = (n.y - minimapData.minY) * minimapData.mmScale;
                  let dotColor = "#475569";
                  if (n.severity === "critical") dotColor = "#f04060";
                  else if (n.severity === "high") dotColor = "#f07030";
                  else if (n.severity === "medium") dotColor = "#f0a830";
                  else if (n.has_alert) dotColor = "#50a0f0";
                  else if (n.type === "internal") dotColor = "#38bdf8";
                  return (
                    <circle
                      key={n.id}
                      cx={mx} cy={my}
                      r={n.threat_score >= 50 ? 3 : 2}
                      fill={dotColor}
                      opacity={0.8}
                    />
                  );
                })}
                {/* Viewport rectangle */}
                <rect
                  x={minimapData.vpRectX}
                  y={minimapData.vpRectY}
                  width={minimapData.vpRectW}
                  height={minimapData.vpRectH}
                  fill="rgba(56, 189, 248, 0.08)"
                  stroke="rgba(56, 189, 248, 0.4)"
                  strokeWidth={1}
                  rx={2}
                />
              </svg>
            </div>
          )}
        </div>

        {/* ── Right Side Panel ── */}
        <div
          className={clsx(
            "flex flex-col transition-all duration-200",
            selectedIp ? "w-80" : "w-72",
          )}
          style={{ minHeight: 660 }}
        >
          {/* Investigation panel when node is selected */}
          {selectedIp ? (
            <div className="card flex-1 overflow-hidden flex flex-col" style={{ maxHeight: H || 660 }}>
              <InvestigationPanel
                ip={selectedIp}
                hours={hours}
                node={nodeMap.get(selectedIp)}
                onClose={() => setSelectedIp(null)}
                onPivot={ip => setSelectedIp(ip)}
                onHostSaved={onHostSaved}
              />
            </div>
          ) : (
            <div className="space-y-3">
              {/* Panel tabs */}
              <div className="card p-0">
                <div className="flex border-b border-border">
                  <button
                    onClick={() => setRightPanel(rightPanel === "chains" ? null : "chains")}
                    className={clsx(
                      "flex-1 px-3 py-2 text-xs font-semibold transition-colors text-center",
                      rightPanel === "chains"
                        ? "text-severity-critical bg-severity-critical/5 border-b-2 border-severity-critical"
                        : "text-text-muted hover:text-text-secondary border-b-2 border-transparent"
                    )}
                  >
                    Attack Chains {(data?.chain_count ?? 0) > 0 && (
                      <span className="ml-1 font-mono">({data?.chain_count})</span>
                    )}
                  </button>
                  <button
                    onClick={() => setRightPanel(rightPanel === "countries" ? null : "countries")}
                    className={clsx(
                      "flex-1 px-3 py-2 text-xs font-semibold transition-colors text-center",
                      rightPanel === "countries"
                        ? "text-accent bg-accent/5 border-b-2 border-accent"
                        : "text-text-muted hover:text-text-secondary border-b-2 border-transparent"
                    )}
                  >
                    Countries {(data?.country_count ?? 0) > 0 && (
                      <span className="ml-1 font-mono">({data?.country_count})</span>
                    )}
                  </button>
                </div>

                {/* Attack Chains */}
                {rightPanel === "chains" && (
                  <div className="p-2 space-y-2 max-h-72 overflow-y-auto">
                    {data?.attack_chains?.length ? (
                      data.attack_chains.map(chain => (
                        <ChainCard
                          key={chain.id}
                          chain={chain}
                          active={activeChain === chain.id}
                          onClick={() => setActiveChain(prev => prev === chain.id ? null : chain.id)}
                        />
                      ))
                    ) : (
                      <p className="text-2xs text-text-muted italic p-2">No attack chains detected</p>
                    )}
                  </div>
                )}

                {/* Countries */}
                {rightPanel === "countries" && (
                  <div className="p-2 space-y-0.5 max-h-72 overflow-y-auto">
                    {countries.length ? (
                      countries.map(c => <CountryRow key={c.country_code} c={c} />)
                    ) : (
                      <p className="text-2xs text-text-muted italic p-2">No country data</p>
                    )}
                  </div>
                )}
              </div>

              {/* Timeline */}
              {data?.timeline && data.timeline.length > 0 && (
                <TimelineSlider
                  timeline={data.timeline}
                  value={timelineIdx}
                  onChange={setTimelineIdx}
                  playing={playing}
                  onTogglePlay={() => {
                    if (!playing && timelineIdx >= (data?.timeline?.length || 1) - 1) {
                      setTimelineIdx(0);
                    }
                    setPlaying(!playing);
                  }}
                />
              )}

              {/* Quick stats card */}
              <div className="card p-3 space-y-2">
                <div className="text-2xs text-text-muted uppercase tracking-wider font-semibold">Quick Stats</div>
                <div className="grid grid-cols-2 gap-2 text-2xs">
                  <div className="bg-bg-elevated rounded p-2 text-center">
                    <div className="font-mono text-text-primary font-bold text-sm">{alertedNodes}</div>
                    <div className="text-text-muted">Alerted Hosts</div>
                  </div>
                  <div className="bg-bg-elevated rounded p-2 text-center">
                    <div className="font-mono text-severity-critical font-bold text-sm">{malEdges}</div>
                    <div className="text-text-muted">Malicious Flows</div>
                  </div>
                  <div className="bg-bg-elevated rounded p-2 text-center">
                    <div className="font-mono text-severity-critical font-bold text-sm">{c2Edges}</div>
                    <div className="text-text-muted">C2 Connections</div>
                  </div>
                  <div className="bg-bg-elevated rounded p-2 text-center">
                    <div className="font-mono text-text-primary font-bold text-sm">
                      {visibleNodes.filter(n => isBoundary(n)).length}
                    </div>
                    <div className="text-text-muted">Boundary Devices</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
