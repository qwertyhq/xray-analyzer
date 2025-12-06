package models

import "time"

// LogEntry represents a single log entry from an agent
type LogEntry struct {
	Timestamp   time.Time `json:"ts"`
	SourceIP    string    `json:"src_ip"`
	SourcePort  int       `json:"src_port"`
	Protocol    string    `json:"proto"`
	Destination string    `json:"dst"`
	Inbound     string    `json:"inbound"`
	Outbound    string    `json:"outbound"`
	UserEmail   string    `json:"user"`
	Status      string    `json:"status"`
}

// LogBatch represents a batch of log entries from an agent
type LogBatch struct {
	NodeID    string     `json:"node_id"`
	Timestamp time.Time  `json:"ts"`
	Entries   []LogEntry `json:"entries"`
	Count     int        `json:"count"`
}

// ServerMessage represents a message from server to agent
type ServerMessage struct {
	Type      string `json:"type"`
	Processed int    `json:"processed,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Alert represents an alert to be sent
type Alert struct {
	ID          int64     `json:"id"`
	Type        string    `json:"type"`
	NodeID      string    `json:"node_id"`
	UserEmail   string    `json:"user_email"`
	SourceIP    string    `json:"source_ip"`
	Destination string    `json:"destination"`
	Count       int       `json:"count"`
	Message     string    `json:"message"`
	CreatedAt   time.Time `json:"created_at"`
	Sent        bool      `json:"sent"`
}

// UserStats represents aggregated stats for a user
type UserStats struct {
	NodeID              string    `json:"node_id"`
	UserEmail           string    `json:"user_email"`
	TotalRequests       int64     `json:"total_requests"`
	BlacklistHits       int64     `json:"blacklist_hits"`
	UniqueDestinations  int       `json:"unique_destinations"`
	LastSeen            time.Time `json:"last_seen"`
	LastIP              string    `json:"last_ip,omitempty"`
	LastBlacklistHit    time.Time `json:"last_blacklist_hit,omitempty"`
	LastBlacklistDomain string    `json:"last_blacklist_domain,omitempty"`
}

// NodeStats represents aggregated stats for a node
type NodeStats struct {
	NodeID         string    `json:"node_id"`
	TotalRequests  int64     `json:"total_requests"`
	BlacklistHits  int64     `json:"blacklist_hits"`
	UniqueUsers    int       `json:"unique_users"`
	OnlineUsers    int       `json:"online_users"`
	LastSeen       time.Time `json:"last_seen"`
	IsConnected    bool      `json:"is_connected"`
	LastBatchTime  time.Time `json:"last_batch_time"`
	LastBatchCount int       `json:"last_batch_count"`
}

// BlacklistMatch represents a matched blacklist entry
type BlacklistMatch struct {
	ID          int64     `json:"id"`
	NodeID      string    `json:"node_id"`
	UserEmail   string    `json:"user_email"`
	SourceIP    string    `json:"source_ip"`
	Destination string    `json:"destination"`
	MatchedRule string    `json:"matched_rule"`
	Timestamp   time.Time `json:"timestamp"`
}

// HourlyStats represents hourly aggregated statistics
type HourlyStats struct {
	Hour          time.Time `json:"hour"`
	TotalRequests int64     `json:"total_requests"`
	BlacklistHits int64     `json:"blacklist_hits"`
	UniqueUsers   int       `json:"unique_users"`
}

// UserDetails represents detailed info about a user
type UserDetails struct {
	UserEmail          string               `json:"user_email"`
	TotalRequests      int64                `json:"total_requests"`
	TotalBlacklistHits int64                `json:"total_blacklist_hits"`
	Nodes              []UserNodeStats      `json:"nodes"`
	RecentMatches      []BlacklistMatchInfo `json:"recent_matches"`
}

// UserNodeStats represents user stats per node
type UserNodeStats struct {
	NodeID              string    `json:"node_id"`
	TotalRequests       int64     `json:"total_requests"`
	BlacklistHits       int64     `json:"blacklist_hits"`
	UniqueDestinations  int       `json:"unique_destinations"`
	LastSeen            time.Time `json:"last_seen"`
	LastBlacklistHit    time.Time `json:"last_blacklist_hit,omitempty"`
	LastBlacklistDomain string    `json:"last_blacklist_domain,omitempty"`
}

// BlacklistMatchInfo represents a blacklist match for display
type BlacklistMatchInfo struct {
	NodeID      string    `json:"node_id"`
	UserEmail   string    `json:"user_email,omitempty"`
	SourceIP    string    `json:"source_ip"`
	Destination string    `json:"destination"`
	MatchedRule string    `json:"matched_rule"`
	Timestamp   time.Time `json:"timestamp"`
}

// BlacklistAnalytics represents detailed blacklist analytics
type BlacklistAnalytics struct {
	TotalHits     int64                  `json:"total_hits"`
	UniqueUsers   int                    `json:"unique_users"`
	UniqueDomains int                    `json:"unique_domains"`
	TopDomains    []DomainStats          `json:"top_domains"`
	TopUsers      []UserBlacklistStats   `json:"top_users"`
	RecentMatches []BlacklistMatchInfo   `json:"recent_matches"`
	HourlyStats   []HourlyBlacklistStats `json:"hourly_stats"`
}

// DomainStats represents stats for a blocked domain
type DomainStats struct {
	Domain      string `json:"domain"`
	MatchedRule string `json:"matched_rule"`
	HitCount    int64  `json:"hit_count"`
	UniqueUsers int    `json:"unique_users"`
}

// UserBlacklistStats represents a user's blacklist activity
type UserBlacklistStats struct {
	UserEmail     string   `json:"user_email"`
	HitCount      int64    `json:"hit_count"`
	UniqueDomains int      `json:"unique_domains"`
	TopDomains    []string `json:"top_domains"`
	LastIP        string   `json:"last_ip"`
}

// HourlyBlacklistStats represents hourly blacklist stats
type HourlyBlacklistStats struct {
	Hour     time.Time `json:"hour"`
	HitCount int64     `json:"hit_count"`
}

// GlobalStats represents aggregated global statistics
type GlobalStats struct {
	TotalRequests      int64 `json:"total_requests"`
	TotalBlacklistHits int64 `json:"total_blacklist"`
	TotalNodes         int   `json:"nodes_total"`
	NodesConnected     int   `json:"nodes_connected"`
	TotalUniqueUsers   int   `json:"total_unique_users"`
	OnlineUsers        int   `json:"online_users"`
}

// Anomaly represents a detected anomaly
type Anomaly struct {
	Type      string    `json:"type"` // blacklist_spike, traffic_spike, user_spike
	Hour      time.Time `json:"hour"`
	UserEmail string    `json:"user_email,omitempty"`
	NodeID    string    `json:"node_id,omitempty"`
	Value     int64     `json:"value"`
	Baseline  int64     `json:"baseline"`
	Deviation float64   `json:"deviation"`
	Message   string    `json:"message"`
}

// UserDestination represents a destination visited by a user
type UserDestination struct {
	NodeID       string    `json:"node_id"`
	Destination  string    `json:"destination"`
	RequestCount int64     `json:"request_count"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// UserDestinationsResponse represents paginated destinations response
type UserDestinationsResponse struct {
	Destinations []UserDestination `json:"destinations"`
	Total        int               `json:"total"`
	Page         int               `json:"page"`
	PageSize     int               `json:"page_size"`
	TotalPages   int               `json:"total_pages"`
}

// PaginatedAlertsResponse represents paginated alerts response
type PaginatedAlertsResponse struct {
	Alerts     []Alert `json:"alerts"`
	Total      int     `json:"total"`
	Page       int     `json:"page"`
	PageSize   int     `json:"page_size"`
	TotalPages int     `json:"total_pages"`
}
