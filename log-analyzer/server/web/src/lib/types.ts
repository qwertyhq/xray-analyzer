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
  user_email: string;
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
  total_requests: number;
  total_blacklist_hits: number;
  nodes: UserNodeStats[];
  recent_matches: BlacklistMatchInfo[];
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

export interface BlacklistMatchInfo {
  node_id: string;
  user_email?: string;
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
  hit_count: number;
  unique_domains: number;
  top_domains: string[];
  last_ip: string;
}

export interface HourlyBlacklistStats {
  hour: string;
  hit_count: number;
}

export interface Anomaly {
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
export type ThreatType = "malware" | "c2" | "phishing" | "adware" | "tracker" | "botnet" | "ransomware" | "porn" | "gambling" | "social" | "fakenews" | "torrent" | "tor";
export type ThreatSource = "urlhaus" | "feodo" | "threatfox" | "sslbl" | "stevenblack" | "porn-blocklist" | "gambling-blocklist" | "social-blocklist" | "fakenews-blocklist" | "torrent-trackers" | "tor-exit-nodes";

export interface ThreatMatch {
  id: number;
  user_email: string;
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
  category: string;
  match_count: number;
  domains: string[]; // Top visited domains in this category
}

export type CategoryTopUsers = Record<string, CategoryUserStats[]>;
