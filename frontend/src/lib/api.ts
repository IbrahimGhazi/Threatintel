/**
 * TI Platform API client
 *
 * All calls include the X-API-Key header from NEXT_PUBLIC_API_KEY.
 * Base URL is NEXT_PUBLIC_API_URL (default "/api", proxied by nginx).
 */

const API_BASE = (
  typeof process !== "undefined" ? process.env.NEXT_PUBLIC_API_URL : undefined
) ?? "/api";

const API_KEY = (
  typeof process !== "undefined" ? process.env.NEXT_PUBLIC_API_KEY : undefined
) ?? "";

function buildHeaders(extra?: Record<string, string>): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY,
    ...extra,
  };
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: buildHeaders(init?.headers as Record<string, string>),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// ── Core types ────────────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type AlertStatus = "open" | "acknowledged" | "resolved" | "false_positive";

export interface Alert {
  id:               string;
  title:            string;
  description?:     string;
  severity:         Severity;
  status:           AlertStatus;
  rule_name?:       string;
  source_service?:  string;
  indicator_value?: string;
  indicator_type?:  string;
  context?:         AlertContext | Record<string, unknown>;
  created_at:       string;
  updated_at:       string;
}

export interface AlertContext {
  attack_type?:     string;
  event_count?:     number;
  stages?:          string[];
  event_chain?:     IncidentEvent[];
  mitre_attack?:    MitreAttack[];
  affected_hosts?:  string[];
  affected_host?:   string;
  source_ip?:       string;
  destination_ip?:  string;
  time_window?:     { start?: string; end?: string; duration_secs?: number };
  [key: string]:    unknown;
}

export interface AlertContextDetail extends AlertContext {
  /** The raw Alert object embedded in the detail response */
  alert:         Alert;
  /** The inner context sub-object (same shape as AlertContext) */
  context:       AlertContext;
  related_logs?: unknown[];
}

export interface IncidentEvent {
  timestamp?:       string;
  stage?:           string;
  action?:          string;
  outcome?:         string;
  status?:          string;
  summary?:         string;
  src_ip?:          string;
  source_ip?:       string;   // alias used by some correlation outputs
  dst_ip?:          string;
  destination_ip?:  string;   // alias used by some correlation outputs
  dst_port?:        number;
  destination_port?: number;  // alias used by some correlation outputs
  program?:         string;
  hostname?:        string;
  log_id?:          string;
}

export interface MitreAttack {
  tactic?:       string;
  technique?:    string;
  technique_id?: string;
}

/** Extended MITRE ATT&CK mapping with tactic ID and ATT&CK URL. */
export interface MitreAttackMapping {
  tactic:         string;
  tactic_id?:     string;
  technique:      string;
  technique_id?:  string;
  subtechnique?:  string;
  url?:           string;
}

export interface Indicator {
  id:                string;
  type:              string;
  value:             string;
  normalized_value?: string;
  severity:          Severity;
  confidence:        number;
  tags?:             string[];
  active?:           boolean;
  false_positive?:   boolean;
  first_seen?:       string;
  last_seen?:        string;
  sources?:          IndicatorSource[];
  enrichment?:       Record<string, unknown>;
  created_at:        string;
  updated_at:        string;
}

export interface IndicatorSource {
  source_name:      string;
  confidence:       number;
  source_category?: string;
  last_seen?:       string;
  raw_data?:        Record<string, unknown>;
}

export interface LogEntry {
  id:              string;
  source_type:     string;
  source_name?:    string;
  source_ip?:      string;
  raw_log?:        string;
  parsed?:         Record<string, unknown>;
  extracted_iocs?: Record<string, unknown>;
  matched_iocs?:   unknown[];
  indicator_ids?:  string[];
  is_malicious:    boolean;
  log_timestamp?:  string;
  processed_at:    string;
}

export interface DashboardStats {
  total_alerts:     number;
  open_alerts:      number;
  critical_alerts:  number;
  indicators_total: number;
  logs_today:       number;
  match_rate:       number;
  // Extended shape returned by /api/stats dashboard endpoint
  indicators?:         {
    total:      number;
    active:     number;
    recent_24h: number;
    by_type:    Record<string, number>;
    by_severity: Record<string, number>;
  };
  alerts?: {
    total:       number;
    by_status:   Record<string, number>;
    by_severity: Record<string, number>;
  };
  feeds?: Array<{ id: string; name: string; status: string; [key: string]: unknown }>;
  top_tags?:           Array<{ tag: string; count: number }>;
  ingestion_timeline?: Array<{ date: string; total: number; matched: number }>;
}

// ── Tuning types ──────────────────────────────────────────────────────────────

export type SuggestionStatus = "pending" | "accepted" | "rejected" | "auto_applied";

export interface TuningSuggestion {
  id:               string;
  suggestion_type:  string;
  category:         string;
  entity_type?:     string;
  entity_value?:    string;
  rule_name:        string;
  current_value?:   Record<string, unknown>;
  suggested_value?: Record<string, unknown>;
  rationale:        string;
  confidence:       number;      // 0.0 – 1.0
  trigger_count:    number;
  status:           SuggestionStatus;
  auto_apply_at?:   string;
  applied_at?:      string;
  rejected_at?:     string;
  created_at:       string;
  updated_at:       string;
}

export interface AdaptiveRuleChange {
  id:               string;
  suggestion_id?:   string;
  change_type:      string;
  rule_name:        string;
  entity_type?:     string;
  entity_value?:    string;
  previous_value?:  Record<string, unknown>;
  new_value?:       Record<string, unknown>;
  applied_by:       string;
  reason?:          string;
  reverted_at?:     string;
  reverted_by?:     string;
  created_at:       string;
}

export interface BehavioralBaseline {
  entity_type:   string;
  entity_value:  string;
  metric:        string;
  category:      string;
  mean:          number;
  std_dev:       number;
  sample_count:  number;
  min_observed?: number;
  max_observed?: number;
  p95?:          number;
  last_updated:  string;
}

export interface TuningStats {
  pending:          number;
  accepted:         number;
  rejected:         number;
  auto_applied:     number;
  baselines_total:  number;
  changes_total:    number;
}

// ── Alert functions ───────────────────────────────────────────────────────────

export function getAlerts(params: {
  status?:   string;
  severity?: string;
  limit?:    number;
  offset?:   number;
} = {}): Promise<{ items: Alert[]; total: number }> {
  const qs = new URLSearchParams();
  if (params.status)   qs.set("status",   params.status);
  if (params.severity) qs.set("severity", params.severity);
  if (params.limit)    qs.set("limit",    String(params.limit));
  if (params.offset)   qs.set("offset",   String(params.offset));
  return apiFetch(`/alerts?${qs}`);
}

export function getAlertContext(id: string): Promise<AlertContextDetail> {
  return apiFetch(`/alerts/${id}/context`);
}

export function acknowledgeAlert(id: string, analyst?: string): Promise<void> {
  return apiFetch(`/alerts/${id}/acknowledge`, {
    method: "POST",
    body: JSON.stringify({ analyst }),
  });
}

export function resolveAlert(id: string): Promise<void> {
  return apiFetch(`/alerts/${id}/resolve`, { method: "POST" });
}

// ── Tuning functions ──────────────────────────────────────────────────────────

export function getTuningStats(): Promise<TuningStats> {
  return apiFetch("/tuning/stats");
}

export function getTuningSuggestions(params: {
  status?:   string;
  category?: string;
  limit?:    number;
  offset?:   number;
} = {}): Promise<{ items: TuningSuggestion[]; total: number }> {
  const qs = new URLSearchParams();
  if (params.status)   qs.set("status",   params.status);
  if (params.category) qs.set("category", params.category);
  if (params.limit)    qs.set("limit",    String(params.limit));
  if (params.offset)   qs.set("offset",   String(params.offset));
  return apiFetch(`/tuning/suggestions?${qs}`);
}

export function acceptSuggestion(id: string): Promise<TuningSuggestion> {
  return apiFetch(`/tuning/suggestions/${id}/accept`, { method: "POST" });
}

export function rejectSuggestion(id: string): Promise<TuningSuggestion> {
  return apiFetch(`/tuning/suggestions/${id}/reject`, { method: "POST" });
}

export function getAdaptiveChanges(params: {
  limit?:  number;
  offset?: number;
} = {}): Promise<{ items: AdaptiveRuleChange[]; total: number }> {
  const qs = new URLSearchParams();
  if (params.limit)  qs.set("limit",  String(params.limit));
  if (params.offset) qs.set("offset", String(params.offset));
  return apiFetch(`/tuning/changes?${qs}`);
}

export function revertChange(id: string): Promise<AdaptiveRuleChange> {
  return apiFetch(`/tuning/changes/${id}/revert`, { method: "POST" });
}

export function getBehavioralBaselines(params: {
  entity_value?: string;
  category?:     string;
  limit?:        number;
  offset?:       number;
} = {}): Promise<{ items: BehavioralBaseline[]; total: number }> {
  const qs = new URLSearchParams();
  if (params.entity_value) qs.set("entity_value", params.entity_value);
  if (params.category)     qs.set("category",     params.category);
  if (params.limit)        qs.set("limit",         String(params.limit));
  if (params.offset)       qs.set("offset",        String(params.offset));
  return apiFetch(`/tuning/baselines?${qs}`);
}

// ── Tuning config ─────────────────────────────────────────────────────────────

export interface TuningConfigEntry {
  value:       string;
  description: string;
  updated_at:  string;
}

export interface TuningConfig {
  auto_apply_delay_hours: TuningConfigEntry;
  auto_apply_confidence:  TuningConfigEntry;
}

export function getTuningConfig(): Promise<TuningConfig> {
  return apiFetch("/tuning/config");
}

export function updateTuningConfig(
  body: Partial<{ auto_apply_delay_hours: number; auto_apply_confidence: number }>
): Promise<TuningConfig> {
  return apiFetch("/tuning/config", {
    method:  "PATCH",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(body),
  });
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

export function getDashboardStats(): Promise<DashboardStats> {
  return apiFetch("/stats/dashboard");
}

// ── Indicators ────────────────────────────────────────────────────────────────

export function getIndicators(params: {
  q?:        string;
  type?:     string;
  severity?: string;
  limit?:    number;
  offset?:   number;
} = {}): Promise<{ items: Indicator[]; total: number }> {
  const qs = new URLSearchParams();
  if (params.q)        qs.set("q",        params.q);
  if (params.type)     qs.set("type",     params.type);
  if (params.severity) qs.set("severity", params.severity);
  if (params.limit)    qs.set("limit",    String(params.limit));
  if (params.offset)   qs.set("offset",   String(params.offset));
  return apiFetch(`/indicators?${qs}`);
}

export function getIndicator(id: string): Promise<Indicator> {
  return apiFetch(`/indicators/${id}`);
}

export function markFalsePositive(id: string): Promise<void> {
  return apiFetch(`/indicators/${id}/false-positive`, { method: "POST" });
}

export function deleteIndicator(id: string): Promise<void> {
  return apiFetch(`/indicators/${id}`, { method: "DELETE" });
}

// ── Alerts timeline ───────────────────────────────────────────────────────────

export interface AlertTimelinePoint {
  bucket:   string;
  severity: string;
  count:    number;
}

export interface AlertTimelineByRule {
  bucket:    string;
  rule_name: string;
  count:     number;
}

export interface AlertTimeline {
  by_severity: AlertTimelinePoint[];
  by_rule:     AlertTimelineByRule[];
}

export function getAlertsTimeline(params: {
  days?:     number;
  interval?: "hour" | "day";
} = {}): Promise<AlertTimeline> {
  const qs = new URLSearchParams();
  if (params.days)     qs.set("days",     String(params.days));
  if (params.interval) qs.set("interval", params.interval);
  return apiFetch(`/stats/alerts-timeline?${qs}`);
}

// ── Logs ──────────────────────────────────────────────────────────────────────

export function getLogs(params: {
  source_type?:    string;
  malicious_only?: boolean;
  source_ip?:      string;
  limit?:          number;
  offset?:         number;
} = {}): Promise<LogEntry[]> {
  const qs = new URLSearchParams();
  if (params.source_type)    qs.set("source_type",    params.source_type);
  if (params.malicious_only) qs.set("malicious_only", "true");
  if (params.source_ip)      qs.set("source_ip",      params.source_ip);
  if (params.limit)          qs.set("limit",          String(params.limit));
  if (params.offset)         qs.set("offset",         String(params.offset));
  return apiFetch(`/logs?${qs}`);
}

// ── Sandbox ───────────────────────────────────────────────────────────────────

export interface SandboxResult {
  id:              string;
  file_sha256:     string;
  file_name?:      string;
  file_type?:      string;
  file_size?:      number;
  status:          "pending" | "running" | "completed" | "failed";
  verdict?:        string;
  malware_score?:  number;
  malware_family?: string;
  sandbox_engine?: string;
  error?:          string;
  extracted_iocs?: Record<string, unknown>;
  report?:         Record<string, unknown>;
  submitted_at?:   string;
  created_at:      string;
  updated_at:      string;
}

export function getSandboxResults(params: {
  limit?:  number;
  offset?: number;
} = {}): Promise<SandboxResult[]> {
  const qs = new URLSearchParams();
  if (params.limit)  qs.set("limit",  String(params.limit));
  if (params.offset) qs.set("offset", String(params.offset));
  return apiFetch(`/sandbox?${qs}`);
}

// ── Feeds ─────────────────────────────────────────────────────────────────────

export interface Feed {
  id:               string;
  name:             string;
  display_name?:    string;
  description?:     string;
  enabled:          boolean;
  poll_interval:    number;
  last_run_at?:     string;
  last_success_at?: string;
  last_error?:      string;
  total_ingested:   number;
  config?:          Record<string, unknown>;
}

export function getFeeds(): Promise<Feed[]> {
  return apiFetch("/feeds");
}

export function updateFeed(id: string, data: Partial<Feed>): Promise<Feed> {
  return apiFetch(`/feeds/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

// ── EDL ───────────────────────────────────────────────────────────────────────

export interface EDLConfig {
  id:             string;
  slug:           string;
  name?:          string;
  description?:   string;
  indicator_type: string;
  min_confidence: number;
  min_severity:   string;
  format:         string;
  cached_count?:  number;
  max_age_days?:  number;
  last_built_at?: string;
}

export interface EDLPreviewResponse {
  preview:  string[];   // array of indicator strings
  total:    number;
}

export function getEDLConfigs(): Promise<EDLConfig[]> {
  return apiFetch("/edl");
}

export function previewEDL(id: string): Promise<EDLPreviewResponse> {
  return apiFetch(`/edl/${id}/preview`);
}

// ── Whitelist ─────────────────────────────────────────────────────────────────

/** The kind/category string for a whitelist entry. */
export type WhitelistEntryKind = "ip" | "cidr" | "hostname" | "rule_name" | "indicator_value";

/**
 * A full whitelist entry object as returned by the API.
 * Named `WhitelistEntryType` for compatibility with existing page imports.
 */
export interface WhitelistEntryType {
  id:           string;
  entry_type:   WhitelistEntryKind;
  value:        string;
  scope_rule?:  string;
  reason?:      string;
  created_by?:  string;
  expires_at?:  string;
  enabled:      boolean;
  source_alert_id?: string;
  created_at:   string;
}

export interface CreateWhitelistBody {
  entry_type:       WhitelistEntryKind | string;
  value:            string;
  scope_rule?:      string | null;
  reason?:          string | null;
  expires_at?:      string | null;
  created_by?:      string;
  source_alert_id?: string;
}

export function getWhitelist(params: {
  entry_type?: string;
  limit?:      number;
  offset?:     number;
} = {}): Promise<{ items: WhitelistEntryType[]; total: number }> {
  const qs = new URLSearchParams();
  if (params.entry_type) qs.set("entry_type", params.entry_type);
  if (params.limit)      qs.set("limit",  String(params.limit));
  if (params.offset)     qs.set("offset", String(params.offset));
  return apiFetch(`/whitelist?${qs}`);
}

export function createWhitelistEntry(body: CreateWhitelistBody): Promise<WhitelistEntryType> {
  return apiFetch("/whitelist", { method: "POST", body: JSON.stringify(body) });
}

export function deleteWhitelistEntry(id: string): Promise<void> {
  return apiFetch(`/whitelist/${id}`, { method: "DELETE" });
}

export function whitelistFromAlert(alertId: string, body: CreateWhitelistBody): Promise<WhitelistEntryType> {
  return apiFetch(`/alerts/${alertId}/whitelist`, { method: "POST", body: JSON.stringify(body) });
}
