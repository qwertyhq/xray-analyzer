// API Types

export interface Stats {
  total_requests: number;
  total_blacklist: number;
  nodes_total: number;
  nodes_connected: number;
  total_unique_users: number;
  online_users: number;
}

export interface NodeStats {
  node_id: string;
  total_requests: number;
  blacklist_hits: number;
  unique_users: number;
  online_users: number;
  last_seen: string;
  last_batch_time: string;
  last_batch_count: number;
  is_connected: boolean;
}

export interface UserStats {
  node_id: string;
  username: string;
  total_requests: number;
  blacklist_hits: number;
  unique_destinations: number;
  last_seen: string;
  last_ip?: string;
  last_blacklist_hit?: string;
  last_blacklist_domain?: string;
}

export interface HourlyStats {
  hour: string;
  total_requests: number;
  blacklist_hits: number;
  unique_users: number;
}

export interface UserDetails {
  user_email: string;
  display_name?: string;
  total_requests: number;
  total_blacklist_hits: number;
  nodes: UserNodeStats[];
  recent_matches: BlacklistMatchInfo[];
  total_threats?: number;
  threats_by_type?: Record<string, number>;
  recent_threats?: UserThreatInfo[];
  risk_level?: string;
  risk_score?: number;
  remna_uuid?: string;
  remna_status?: string;
  remna_used_traffic?: number;
  remna_traffic_limit?: number;
  remna_traffic_percent?: number;
  remna_hwid_count?: number;
  remna_hwid_limit?: number;
  remna_online_at?: string;
  remna_expire_at?: string;
  remna_telegram_id?: number;
  remna_description?: string;
}

export interface UserThreatInfo {
  node_id: string;
  destination: string;
  threat_type: string;
  source: string;
  confidence: number;
  description?: string;
  source_ip?: string;
  matched_at: string;
}

export interface UserNodeStats {
  node_id: string;
  total_requests: number;
  blacklist_hits: number;
  unique_destinations: number;
  last_seen: string;
  last_blacklist_hit?: string;
  last_blacklist_domain?: string;
}

export interface UserIPHistory {
  ip_address: string;
  node_id?: string;
  country_code?: string;
  country_name?: string;
  city?: string;
  first_seen: string;
  last_seen: string;
  request_count: number;
}

export interface SubscriptionAbuse {
  user_email: string;
  user_uuid?: string;
  username?: string;
  unique_ips: number;
  unique_nodes: number;
  unique_hwids: number;
  unique_countries: number;
  countries: string[];
  nodes: string[];
  total_requests: number;
  last_seen: string;
  ips: AbuseIPInfo[];
  hwids?: HWIDInfo[];
  abuse_score: number;
}

export interface AbuseIPInfo {
  ip: string;
  country_code: string;
  city: string;
  node_id?: string;
  request_count: number;
  last_seen: string;
}

export interface HWIDInfo {
  hwid: string;
  platform?: string;
  device_model?: string;
  created_at: string;
}

export interface BlacklistMatchInfo {
  node_id: string;
  user_email?: string;
  display_name?: string;
  source_ip: string;
  destination: string;
  matched_rule: string;
  timestamp: string;
}

export interface BlacklistAnalytics {
  total_hits: number;
  unique_users: number;
  unique_domains: number;
  top_domains: DomainStats[];
  top_users: UserBlacklistStats[];
  recent_matches: BlacklistMatchInfo[];
  hourly_stats: HourlyBlacklistStats[];
}

export interface DomainStats {
  domain: string;
  matched_rule: string;
  hit_count: number;
  unique_users: number;
}

export interface UserBlacklistStats {
  user_email: string;
  username: string;
  hit_count: number;
  unique_domains: number;
  top_domains: string[];
  last_ip: string;
}

export interface HourlyBlacklistStats {
  hour: string;
  hit_count: number;
}

export interface StatsAnomaly {
  type: "blacklist_spike" | "traffic_spike" | "user_spike";
  hour: string;
  user_email?: string;
  node_id?: string;
  value: number;
  baseline: number;
  deviation: number;
  message: string;
}

export interface Alert {
  id: number;
  type: string;
  node_id: string;
  user_email: string;
  source_ip?: string;
  destination?: string;
  count: number;
  message: string;
  created_at: string;
  sent: boolean;
}

export interface UserDestination {
  node_id: string;
  destination: string;
  request_count: number;
  first_seen: string;
  last_seen: string;
  categories: string[];
}

export interface PaginatedResponse<T> {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface UserDestinationsResponse extends PaginatedResponse<UserDestination> {
  destinations: UserDestination[];
}

export interface PaginatedAlertsResponse extends PaginatedResponse<Alert> {
  alerts: Alert[];
}

export type TimeRange = "1h" | "6h" | "24h" | "7d" | "30d" | "custom";

// Threat Intelligence types
export type ThreatType = 
  | "malware" | "c2" | "phishing" | "adware" | "tracker" | "botnet" | "ransomware" 
  | "porn" | "gambling" | "social" | "fakenews" | "torrent" | "tor"
  // BlockList Project categories
  | "abuse" | "ads" | "crypto" | "drugs" | "fraud" | "piracy" | "scam" | "redirect" | "tiktok" | "tracking";

export type ThreatSource = 
  | "urlhaus" | "feodo" | "threatfox" | "sslbl" | "stevenblack" 
  | "porn-blocklist" | "gambling-blocklist" | "social-blocklist" | "fakenews-blocklist" 
  | "torrent-trackers" | "tor-exit-nodes"
  // BlockList Project sources
  | "blocklist-abuse" | "blocklist-ads" | "blocklist-crypto" | "blocklist-drugs" 
  | "blocklist-fraud" | "blocklist-malware" | "blocklist-phishing" | "blocklist-piracy" 
  | "blocklist-porn" | "blocklist-scam" | "blocklist-redirect" | "blocklist-tiktok" 
  | "blocklist-torrent" | "blocklist-tracking" | "blocklist-ransomware";

export interface ThreatMatch {
  id: number;
  user_email?: string; // fallback, typically username is used
  username?: string;
  node_id: string;
  source_ip: string;
  destination: string;
  threat_type: ThreatType;
  source: ThreatSource;
  confidence: number;
  description?: string;
  matched_at: string;
}

export interface ThreatStats {
  total_indicators: number;
  indicators_by_type: Record<string, number>;
  indicators_by_source: Record<string, number>;
  total_matches: number;
  matches_24h: number;
  last_updated: string;
}

export interface FeedStatus {
  source: ThreatSource;
  last_update: string;
  next_update: string;
  indicators: number;
  status: "ok" | "error" | "updating";
  error?: string;
}

export interface CategoryUserStats {
  user_email: string;
  username: string;
  category: string;
  match_count: number;
  domains: string[]; // Top visited domains in this category
}

export type CategoryTopUsers = Record<string, CategoryUserStats[]>;

// IP Info types
export interface IPInfo {
  ip: string;
  country: string;
  country_code: string;
  region: string;
  city: string;
  isp: string;
  org: string;
  as: string;
  mobile: boolean;
  proxy: boolean;
  hosting: boolean;
  lat: number;
  lon: number;
  cached_at: string;
}

// Time-based threat statistics
export interface HourlyThreatStats {
  hour: string;
  total_count: number;
  by_type: Record<string, number>;
  unique_users: number;
}

export interface DailyThreatStats {
  day: string;
  total_count: number;
  by_type: Record<string, number>;
  unique_users: number;
}

export interface TimeStats {
  hourly: HourlyThreatStats[];
  daily: DailyThreatStats[];
}

// GeoIP statistics types
export interface GeoStats {
  country_code: string;
  country_name: string;
  threat_type: string;
  match_count: number;
  unique_users: number;
  last_match?: string;
}

export interface CountryStats {
  country_code: string;
  country_name: string;
  total_matches: number;
  unique_users: number;
  top_threat: string;
}

export interface GeoSummary {
  total_countries: number;
  top_countries: CountryStats[];
  by_threat_type: Record<string, GeoStats[]>;
}

// Anomaly detection types
export type AnomalyType = 
  | "activity_spike"
  | "night_activity"
  | "new_user_high_vol"
  | "geo_anomaly"
  | "threat_burst"
  | "multiple_countries"
  | "blacklist_spike"
  | "traffic_spike"
  | "user_spike"
  | "user_blacklist_spike";

export type AnomalySeverity = "low" | "medium" | "high" | "critical";

export interface Anomaly {
  id: string;
  type: AnomalyType;
  severity: AnomalySeverity;
  user_email?: string;
  description: string;
  details?: Record<string, unknown>;
  detected_at: string;
  resolved: boolean;
}

export interface AnomalySummary {
  total_anomalies: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
  recent_anomalies: Anomaly[];
  affected_users: number;
  threat_burst_count: number;
}

// User Risk Profile types
export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface RiskFactor {
  type: string;
  description: string;
  weight: number;
  detected_at: string;
}

export interface UserRiskProfile {
  user_email: string;
  username?: string;
  risk_level: RiskLevel;
  risk_score: number;
  total_matches: number;
  threats_by_type: Record<string, number>;
  unique_countries: number;
  anomaly_count: number;
  last_activity: string;
  first_seen: string;
  days_active: number;
  top_domains: string[];
  risk_factors: RiskFactor[];
  trend_direction: "up" | "down" | "stable";
}

export interface UserRiskSummary {
  total_users: number;
  by_risk_level: Record<string, number>;
  high_risk_users: UserRiskProfile[];
  recent_escalations: number;
  average_risk_score: number;
}

// DNS Analysis types
export interface DomainStats {
  domain: string;
  total_hits: number;
  unique_users: number;
  threat_types: string[];
  sources: string[];
  first_seen: string;
  last_seen: string;
  risk_level: RiskLevel;
  category_hits: Record<string, number>;
}

export interface HourlyDNS {
  hour: string;
  total_queries: number;
  blocked_queries: number;
  unique_users: number;
}

export interface DailyDNS {
  day: string;
  total_queries: number;
  blocked_queries: number;
  unique_users: number;
}

export interface DNSQueryStats {
  total_queries: number;
  blocked_queries: number;
  block_rate: number;
  unique_domains_all: number;
  unique_domains_bad: number;
  top_domains: DomainStats[];
  top_blocked_types: Record<string, number>;
  hourly_stats: HourlyDNS[];
  daily_stats: DailyDNS[];
}

export interface UserDNSStats {
  user_email: string;
  total_queries: number;
  blocked_queries: number;
  block_rate: number;
  top_domains: string[];
  risk_level: RiskLevel;
}

export interface DNSAnalysisSummary {
  query_stats: DNSQueryStats | null;
  top_bad_domains: DomainStats[];
  top_users_by_dns: UserDNSStats[];
  category_breakdown: Record<string, number>;
  trend_direction: "up" | "down" | "stable";
  risk_score: number;
}

// Report types
export type ReportType = "summary" | "threat_summary" | "user_risk" | "geo_analysis" | "dns_analysis" | "detailed" | "user" | "incident" | "compliance";
export type ReportFormat = "json" | "csv" | "html" | "pdf";
export type ReportStatus = "pending" | "generating" | "completed" | "failed";

export interface ReportSection {
  title: string;
  content: string;
  order: number;
}

export interface ReportThreat {
  type: string;
  source: string;
  count: number;
  blocked: boolean;
}

export interface ReportUser {
  email: string;
  threat_count: number;
  risk_score: number;
}

export interface ReportCountry {
  country: string;
  code: string;
  count: number;
}

export interface ReportStats {
  total_threats: number;
  blocked_threats: number;
  unique_users: number;
  unique_countries: number;
  high_risk_users: number;
  dns_queries: number;
  suspicious_domains: number;
}

export interface Report {
  id: string;
  type: ReportType;
  format: ReportFormat;
  title: string;
  description?: string;
  start_date: string;
  end_date: string;
  generated_at: string;
  status: ReportStatus;
  sections?: ReportSection[];
  top_threats?: ReportThreat[];
  top_users?: ReportUser[];
  top_countries?: ReportCountry[];
  summary: ReportStats;
}

export interface ReportConfig {
  type: ReportType;
  format: ReportFormat;
  title: string;
  description?: string;
  start_date: string;
  end_date: string;
}

export interface ReportSummary {
  total_reports: number;
  completed_reports: number;
  pending_reports: number;
  last_generated?: string;
  reports: Report[];
}

// Remnawave Types
export interface RemnawaveStats {
  enabled: boolean;
  totalUsers: number;
  activeUsers: number;
  disabledUsers: number;
  limitedUsers: number;
  expiredUsers: number;
  totalTrafficUsed: number;
  onlineLastHour: number;
  onlineLast24h: number;
  neverOnline: number;
  usersWithHwidLimit: number;
  hwidStats?: {
    totalDevices: number;
    uniqueUsers: number;
    platformBreakdown: Record<string, number>;
  };
  lastSync: string;
}

export interface RemnawaveAbuseUser {
  uuid: string;
  username: string;
  email?: string;
  status: string;
  deviceCount: number;
  deviceLimit: number;
  excessDevices: number;
  platforms: string[];
  lastActivity?: string;
  devices: RemnawaveHwidDevice[];
  parsedNote?: ParsedNote;
}

export interface RemnawaveHwidDevice {
  hwid: string;
  platform?: string;
  osVersion?: string;
  deviceModel?: string;
  userAgent?: string;
  createdAt: string;
}

// Remnawave Online Stats (more accurate than log-based)
export interface RemnawaveOnlineStats {
  now: number;          // Last 5 min
  recent: number;       // Last 15 min
  lastHour: number;     // Last hour
  last24h: number;      // Last 24 hours
  neverOnline: number;  // Never been online
  totalActive: number;  // Total active users
  onlineUsers: RemnawaveOnlineUser[];
  lastSync: string;
  syncInterval: string;
}

export interface RemnawaveOnlineUser {
  uuid: string;
  username: string;
  email?: string;
  onlineAt: string;
  minutesAgo: number;
  lastConnectedNode?: string;
  countryCode?: string;
  status: string;
  parsedRealName?: string;
}

export interface RemnawaveUser {
  uuid: string;
  username: string;
  email?: string;
  status: "ACTIVE" | "DISABLED" | "LIMITED" | "EXPIRED";
  used_traffic_bytes: number;
  traffic_limit_bytes: number;
  traffic_percent: number;
  hwid_device_count: number;
  hwid_device_limit?: number;
  hwid_exceeds_limit: boolean;
  online_at?: string;
  expire_at: string;
  last_connected_node?: string;
  tag?: string;
  telegram_id?: number;
  description?: string;
  parsed_real_name?: string;
  parsed_phone?: string;
  parsed_telegram_user?: string;
  parsed_plan?: string;
}

export interface RemnawaveUserDetails {
  uuid: string;
  short_uuid: string;
  username: string;
  email?: string;
  status: string;
  used_traffic_bytes: number;
  traffic_limit_bytes: number;
  expire_at: string;
  online_at?: string;
  tag?: string;
  telegram_id?: number;
  description?: string;
  parsed_note?: ParsedNote;
  hwid_devices: HwidDevice[];
  hwid_device_limit?: number;
  subscription_url: string;
  created_at: string;
}

export interface ParsedNote {
  real_name?: string;
  phone?: string;
  telegram_user?: string;
  payment_info?: string;
  plan?: string;
  expiry_date?: string;
  notes?: string;
  custom?: Record<string, string>;
  raw_text?: string;
}

export interface HwidDevice {
  hwid: string;
  platform?: string;
  os_version?: string;
  device_model?: string;
  user_agent?: string;
  created_at: string;
}

export interface RemnawaveAbuser {
  uuid: string;
  username: string;
  email?: string;
  status: string;
  hwid_device_count: number;
  hwid_device_limit?: number;
  excess_devices: number;
  device_platforms: string[];
  parsed_real_name?: string;
  parsed_phone?: string;
  description?: string;
}

export interface RemnawaveAbuseResponse {
  total_abusers: number;
  abusers: RemnawaveAbuser[];
}
