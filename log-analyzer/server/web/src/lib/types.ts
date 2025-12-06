// API Types

export interface Stats {
  total_requests: number;
  total_blacklist: number;
  nodes_total: number;
  nodes_connected: number;
  total_unique_users: number;
}

export interface NodeStats {
  node_id: string;
  total_requests: number;
  blacklist_hits: number;
  unique_users: number;
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
