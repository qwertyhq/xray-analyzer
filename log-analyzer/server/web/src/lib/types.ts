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
  source_ip: string;
  destination: string;
  matched_rule: string;
  timestamp: string;
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

export type TimeRange = "1h" | "6h" | "24h" | "7d" | "30d" | "custom";
