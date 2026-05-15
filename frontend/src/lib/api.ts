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

export type SuggestionStatus = "pending" | "accepted" | "rejected" | "auto_applied" | "observed";

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
  entity_type:       string;
  entity_value:      string;
  metric:            string;
  category:          string;
  method?:           string;
  mean:              number;
  std_dev:           number;
  sample_count:      number;
  min_observed?:     number;
  max_observed?:     number;
  p95?:              number;
  confidence_score?: number;
  last_updated:      string;
}

export interface TuningStats {
  pending:          number;
  accepted:         number;
  rejected:         number;
  auto_applied:     number;
  observed:         number;
  baselines_total:  number;
  changes_total:    number;
  learning_mode:    "on" | "off";
  enforcement_mode: "transparent" | "blocking";
}

// ── Learning types ───────────────────────────────────────────────────────────

export interface LearningMethodStatus {
  confidence:         number;
  baselines:          number;
  total_samples:      number;
  coverage?:          number;
  total_observations?: number;
  subnets?:           number;
  total_peers?:       number;
}

export interface LearningCategoryStatus {
  baselines:       number;
  avg_confidence:  number;
  samples:         number;
}

export interface LearningStatus {
  overall_confidence: number;
  total_entities:     number;
  total_metrics:      number;
  learning_mode:      "on" | "off";
  enforcement_mode:   "transparent" | "blocking";
  started_at?:        string;
  methods:            Record<string, LearningMethodStatus>;
  categories:         Record<string, LearningCategoryStatus>;
  maturity:           string;
}

// ── Log search types ─────────────────────────────────────────────────────────

export interface FilterCondition {
  field:    string;
  operator: string;
  value:    string;
}

export interface FilterGroup {
  logic:      "AND" | "OR";
  conditions: FilterCondition[];
}

export interface LogSearchQuery {
  filters:  FilterGroup[];
  order_by?: string;
  order?:    string;
  offset?:   number;
  limit?:    number;
}

export interface LogSearchResult {
  items: LogEntry[];
  total: number;
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

// ── Incident types & functions ───────────────────────────────────────────────

export type IncidentStatus = "open" | "investigating" | "resolved" | "closed";

export interface Incident {
  id:            string;
  title:         string;
  description?:  string;
  severity:      Severity;
  status:        IncidentStatus;
  source_ip?:    string;
  attack_type?:  string;
  mitre_tactics: string[];
  total_events:  number;
  first_seen:    string;
  last_seen:     string;
  created_at:    string;
  updated_at:    string;
}

export interface IncidentDetail extends Incident {
  alerts: Alert[];
}

export function getIncidents(params: {
  status?:      string;
  severity?:    string;
  attack_type?: string;
  limit?:       number;
  offset?:      number;
} = {}): Promise<{ items: Incident[]; total: number }> {
  const qs = new URLSearchParams();
  if (params.status)      qs.set("status",      params.status);
  if (params.severity)    qs.set("severity",    params.severity);
  if (params.attack_type) qs.set("attack_type", params.attack_type);
  if (params.limit)       qs.set("limit",       String(params.limit));
  if (params.offset)      qs.set("offset",      String(params.offset));
  return apiFetch(`/incidents?${qs}`);
}

export function getIncident(id: string): Promise<IncidentDetail> {
  return apiFetch(`/incidents/${id}`);
}

export function resolveIncident(id: string, notes?: string): Promise<Incident> {
  return apiFetch(`/incidents/${id}/resolve`, {
    method: "POST",
    body: JSON.stringify({ notes }),
  });
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

// ── Learning functions ───────────────────────────────────────────────────────

export function getLearningStatus(): Promise<LearningStatus> {
  return apiFetch("/tuning/learning/status");
}

export function setLearningMode(body: {
  learning_mode?: "on" | "off";
  enforcement_mode?: "transparent" | "blocking";
}): Promise<LearningStatus> {
  return apiFetch("/tuning/learning/mode", {
    method: "PATCH",
    body:   JSON.stringify(body),
  });
}

export function resetBaselines(): Promise<{ status: string; message: string }> {
  return apiFetch("/tuning/learning/reset", { method: "POST" });
}

// ── Log search ───────────────────────────────────────────────────────────────

export function searchLogs(query: LogSearchQuery): Promise<LogSearchResult> {
  return apiFetch("/logs/search", {
    method: "POST",
    body:   JSON.stringify(query),
  });
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
// ──────────────────────────────────────────────────────────────────────────────
// URL Intel (URLBert classifier) dashboard API helpers.
// Append this block to services/frontend/src/lib/api.ts
// ──────────────────────────────────────────────────────────────────────────────

export type UrlVerdict = "benign" | "suspicious" | "malicious" | "error";

export interface UrlIntelStats {
  total: number;
  counts: {
    benign: number;
    suspicious: number;
    malicious: number;
    errors: number;
  };
  avg_confidence: number;
  avg_risk_score: number;
  total_hits: number;
  recent_volume: { last_hour: number; last_24h: number };
  labeled: number;
  labeled_correct: number;
  top_domains: Array<{
    domain: string;
    prediction: UrlVerdict;
    hits: number;
    avg_conf: number;
  }>;
}

export interface UrlIntelHistogram {
  buckets: Array<{
    bucket: number;
    range: string;
    benign: number;
    suspicious: number;
    malicious: number;
  }>;
}

export interface UrlIntelAccuracy {
  labeled_total: number;
  overall_accuracy: number;
  per_class: Record<
    string,
    { tp: number; fp: number; fn: number;
      precision: number; recall: number; f1: number; support: number }
  >;
  labels: string[];
  // Model Health fields (added when the confusion matrix UI was removed).
  last_labeled_at: string | null;
  total_labels: number;
  accuracy_history: { date: string; accuracy: number | null }[];
}

export interface UrlIntelRecentRow {
  id: number;
  url: string;
  domain: string | null;
  prediction: UrlVerdict;
  confidence: number;
  risk_score: number;
  ml_probability: number;
  hit_count: number;
  first_seen: string;
  last_seen: string;
  ground_truth: UrlVerdict | null;
  labeled_at: string | null;
  labeled_by: string | null;
}

export interface UrlIntelRecentPage {
  total: number;
  offset: number;
  limit: number;
  items: UrlIntelRecentRow[];
}

export async function getUrlIntelStats(): Promise<UrlIntelStats> {
  return apiFetch<UrlIntelStats>("/url-intel/stats");
}

export async function getUrlIntelHistogram(): Promise<UrlIntelHistogram> {
  return apiFetch<UrlIntelHistogram>("/url-intel/histogram");
}



export async function submitUrlIntelFeedback(
  url: string,
  ground_truth: UrlVerdict,
  labeled_by = "operator",
): Promise<{ status: string; id: number; url: string; prediction: string; ground_truth: string }> {
  return apiFetch("/url-intel/feedback", {
    method: "POST",
    body: JSON.stringify({ url, ground_truth, labeled_by }),
  });
}

export async function clearUrlIntelFeedback(row_id: number): Promise<{ status: string }> {
  return apiFetch(`/url-intel/feedback/${row_id}`, { method: "DELETE" });
}

export interface IndicatorCacheStats {
  hits: number;
  negative_hits: number;
  misses: number;
  errors: number;
  sets_hit: number;
  sets_miss: number;
  invalidations: number;
  total_reads: number;
  hit_ratio: number;
  namespace: string;
  ttl_hit_seconds: number;
  ttl_miss_seconds: number;
}

export async function getIndicatorCacheStats(): Promise<IndicatorCacheStats> {
  return apiFetch<IndicatorCacheStats>("/indicators/cache/stats");
}
// ──────────────────────────────────────────────────────────────────────────────
// Web Content Analysis — extensions to the URL-Intel API helpers.
// Append this block to services/frontend/src/lib/api.ts.
// ──────────────────────────────────────────────────────────────────────────────

export type ContentVerdict = "benign" | "suspicious" | "malicious" | "error";

// Augment the existing UrlIntelRecentRow / UrlIntelStats interfaces with
// the web-content-analysis fields (TS declaration merging).
export interface UrlIntelRecentRow {
  content_verdict?: ContentVerdict | null;
  content_risk_score?: number | null;
  content_analyzed_at?: string | null;
  original_prediction?: string | null;
  override_reason?: string | null;
}

export interface UrlIntelStats {
  content?: UrlIntelContentStats;
}

export interface UrlIntelContentStats {
  analyzed: number;
  counts: { benign: number; suspicious: number; malicious: number; errors: number };
  overrides_total: number;
  overrides_to_benign: number;
  overrides_to_malicious: number;
}

export interface UrlContentSignal {
  weight: number;
  detail: string;
}

export interface UrlContentIndicators {
  phishing: {
    login_form_count: number;
    password_input_count: number;
    hidden_form_count: number;
    forms_posting_external: number;
    forms_posting_http_on_https_page: number;
    suspicious_form_action_samples: string[];
    suspicious_title_keywords: string[];
    brand_keywords_in_title: string[];
    brand_keywords_in_body: string[];
    brand_domain_mismatch: boolean;
  };
  js_obfuscation: {
    eval_calls: number;
    new_function_calls: number;
    atob_calls: number;
    btoa_calls: number;
    unescape_calls: number;
    fromCharCode_calls: number;
    hex_escape_count: number;
    unicode_escape_count: number;
    percent_encoded_runs: number;
    long_hex_blobs: number;
    long_b64_blobs: number;
    obfuscated_identifiers: number;
    document_write_calls: number;
    document_write_script_tag: boolean;
    innerHTML_writes: number;
    dynamic_script_creation: number;
    clipboard_access: boolean;
    key_event_listeners: number;
    fingerprinting: {
      canvas: boolean; webgl: boolean; audio: boolean;
      navigator: boolean; fonts: boolean;
    };
    crypto_miner_tokens: string[];
    wasm_loading: boolean;
    inline_script_count: number;
    external_script_count: number;
    largest_inline_script_size: number;
    largest_inline_script_entropy: number;
  };
  hidden_dom: {
    total_iframes: number;
    hidden_iframes: number;
    external_iframe_srcs: string[];
    invisible_overlays: number;
    fullpage_invisible_els: number;
    display_none_elements: number;
    visibility_hidden_elements: number;
    objects_or_embeds: number;
  };
  redirects: {
    chain_length: number;
    chain: string[];
    distinct_redirect_domains: string[];
    cross_domain_hops: number;
    meta_refresh: { delay: number; url: string | null } | null;
    js_location_assignments: number;
  };
  external_resources: {
    external_domain_count: number;
    external_domains_sample: string[];
    third_party_script_count: number;
    third_party_scripts_sample: string[];
    scripts_from_ip: string[];
    scripts_from_suspicious_tld: string[];
    final_url_suspicious_tld: boolean;
    final_url_is_ip: boolean;
  };
  links: {
    total_links: number;
    external_links: number;
    links_to_ip: number;
    shortener_links: Array<{ href: string; text: string }>;
    mismatched_anchor_url: Array<{ text: string; href: string }>;
    executable_file_links: string[];
  };
  malware_delivery: {
    auto_download_attr_links: number;
    content_disposition_attachment: boolean;
    executable_file_links_count: number;
    executable_file_links_sample: string[];
    dynamic_script_injection: boolean;
    meta_refresh_present: boolean;
  };
  page_complexity: {
    html_size: number;
    script_count: number;
    inline_script_count: number;
    external_script_count: number;
    iframe_count: number;
    form_count: number;
    external_domain_count: number;
    redirect_count: number;
    link_count: number;
  };
  final_apex: string;
  final_host: string;
  status_code: number | null;
  tls_ok: boolean | null;
  title: string | null;
  extractor_version: string;
}

export interface UrlContentAnalysisRow {
  id: number;
  analyzed_at: string;
  final_url: string | null;
  status_code: number | null;
  load_time_ms: number | null;
  html_sha256: string | null;
  html_size: number | null;
  title: string | null;
  redirect_count: number | null;
  external_origin_count: number | null;
  script_count: number | null;
  inline_script_count: number | null;
  signals: Record<string, UrlContentSignal>;
  network_summary: {
    origins?: string[];
    origin_count?: number;
    redirect_chain?: string[];
    external_scripts_sample?: string[];
    console_errors_sample?: string[];
  } | null;
  content_risk_score: number;
  content_verdict: ContentVerdict;
  analyzer_version: string;
  error: string | null;
  indicators: UrlContentIndicators | null;
}

export interface UrlContentAnalysisBundle {
  reputation: {
    id: number;
    url: string;
    domain: string | null;
    prediction: string;
    confidence: number;
    risk_score: number;
    content_verdict: ContentVerdict | null;
    content_analyzed_at: string | null;
    original_prediction: string | null;
    override_reason: string | null;
  };
  latest: UrlContentAnalysisRow | null;
  history: Array<{
    id: number;
    analyzed_at: string;
    content_verdict: ContentVerdict;
    content_risk_score: number;
  }>;
}

export async function getUrlContentAnalysis(rowId: number): Promise<UrlContentAnalysisBundle> {
  return apiFetch<UrlContentAnalysisBundle>(`/url-intel/content/${rowId}`);
}

export async function requestUrlContentAnalysis(url: string): Promise<{ status: string }> {
  return apiFetch(`/url-intel/content/analyze`, {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}

// ──────────────────────────────────────────────────────────────────────────────
// URL Intel v2 additions — combined-verdict, pipeline, heatmap, tags, lifecycle
// Append this block to services/frontend/src/lib/api.ts
// ──────────────────────────────────────────────────────────────────────────────

// Declaration merging: augment the existing interfaces with v2 fields.
export interface UrlIntelStats {
  combined?: {
    analyzed: number;
    counts: { benign: number; suspicious: number; malicious: number };
    ge_threshold: number;
  };
  pipeline?: {
    url_classified: number;
    content_analyzed: number;
    combined_gated: number;
    combined_ge_thr: number;
    active_indicators: number;
    feed_confirmed: number;
  };
  drift?: {
    overrides_to_benign: number;
    overrides_to_malicious: number;
    deactivated_24h: number;
    upserted_24h: number;
  };
  gate_diagnostics?: {
    ml_bad_content_ok: number;
    ml_ok_content_bad: number;
    both_bad: number;
    both_ok: number;
    ml_bad_content_pending: number;
  };
  indicators?: {
    total: number;
    active: number;
    inactive: number;
    active_feed_confirmed: number;
    active_combined_gate: number;
  };
  feed_hits?: {
    urlhaus: number;
    openphish: number;
    spamhaus_dbl: number;
    gsb: number;
    combined_only: number;
    authoritative_feed: number;
  };
  threshold_config?: {
    w_ml: number;
    w_content: number;
    threshold_malicious: number;
    threshold_suspicious: number;
  };
}

export interface UrlIntelRecentRow {
  combined_score?: number | null;
  combined_verdict?: UrlVerdict | null;
  indicator_active?: boolean | null;
  indicator_tags?: string[] | null;
}

export interface UrlIntelModelInfo {
  classifier: {
    name: string;
    version: string;
    [k: string]: any;
  };
  gate: {
    w_ml: number;
    w_content: number;
    threshold_malicious: number;
    threshold_suspicious: number;
    feed_tags: string[];
  };
}

export interface UrlIntelCombinedHistogram {
  buckets: Array<{
    bucket: number; range: string;
    benign: number; suspicious: number; malicious: number;
  }>;
  threshold_malicious: number;
  threshold_suspicious: number;
}

export interface UrlIntelHeatmap {
  ml_buckets: string[];
  content_buckets: string[];
  grid: number[][];            // grid[ml_bucket][content_bucket] = count
  threshold_malicious: number;
  w_ml: number;
  w_content: number;
}

export interface UrlIntelIndicatorTags {
  tags: Array<{ tag: string; count: number }>;
}

export interface UrlIntelIndicatorLifecycleEvent {
  id: number;
  value: string;
  event: "upsert" | "deactivate";
  active: boolean;
  severity: string | null;
  confidence: number;
  tags: string[];
  last_seen: string;
  first_seen: string;
}

export interface UrlIntelIndicatorLifecycle {
  window_minutes: number;
  events: UrlIntelIndicatorLifecycleEvent[];
}

export async function getUrlIntelModelInfo(): Promise<UrlIntelModelInfo> {
  return apiFetch<UrlIntelModelInfo>("/url-intel/model-info");
}

export async function getUrlIntelCombinedHistogram(): Promise<UrlIntelCombinedHistogram> {
  return apiFetch<UrlIntelCombinedHistogram>("/url-intel/combined-histogram");
}

export async function getUrlIntelHeatmap(): Promise<UrlIntelHeatmap> {
  return apiFetch<UrlIntelHeatmap>("/url-intel/heatmap");
}

export async function getUrlIntelIndicatorTags(): Promise<UrlIntelIndicatorTags> {
  return apiFetch<UrlIntelIndicatorTags>("/url-intel/indicator-tags");
}

export async function getUrlIntelIndicatorLifecycle(
  minutes = 60, limit = 30,
): Promise<UrlIntelIndicatorLifecycle> {
  return apiFetch<UrlIntelIndicatorLifecycle>(
    `/url-intel/indicator-lifecycle?minutes=${minutes}&limit=${limit}`);
}

// v2 /accuracy signature now takes a basis parameter. Override the old
// implementation by re-exporting this function from the same module.
export async function getUrlIntelAccuracy(
  basis: "ml" | "content" | "combined" = "ml",
): Promise<UrlIntelAccuracy> {
  return apiFetch<UrlIntelAccuracy>(`/url-intel/accuracy?basis=${basis}`);
}

// v2 /recent gains combined_only filter.
export async function getUrlIntelRecent(params: {
  prediction?: UrlVerdict;
  labeled?: boolean;
  only_mispredictions?: boolean;
  combined_only?: boolean;
  q?: string;
  offset?: number;
  limit?: number;
} = {}): Promise<UrlIntelRecentPage> {
  const q = new URLSearchParams();
  if (params.prediction) q.set("prediction", params.prediction);
  if (params.labeled !== undefined) q.set("labeled", String(params.labeled));
  if (params.only_mispredictions) q.set("only_mispredictions", "true");
  if (params.combined_only) q.set("combined_only", "true");
  if (params.q) q.set("q", params.q);
  if (params.offset !== undefined) q.set("offset", String(params.offset));
  if (params.limit !== undefined) q.set("limit", String(params.limit));
  return apiFetch<UrlIntelRecentPage>(`/url-intel/recent?${q.toString()}`);
}
