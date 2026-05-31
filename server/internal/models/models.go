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

// Alert categories group alert Types into themes so they can be routed to
// dedicated Telegram forum topics (message_thread_id). Several alert Types may
// share one category — e.g. port scans and brute-force both map to "scan".
const (
	AlertCategoryBlacklist = "blacklist" // user exceeded blacklist-request threshold
	AlertCategoryThreat    = "threat"    // threat-intel match (malware/c2/phishing/botnet/…)
	AlertCategoryScan      = "scan"      // port scan / brute-force activity
)

// Alert represents an alert to be sent
type Alert struct {
	ID    int64  `json:"id"`
	Type  string `json:"type"`
	// Category groups the alert Type into a theme for Telegram topic routing.
	// One of AlertCategory*. Empty falls back to the default topic/chat.
	Category    string    `json:"category,omitempty"`
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
	UserEmail           string    `json:"-"` // internal use only, not exposed in JSON
	DisplayName         string    `json:"username"`
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
	DisplayName        string               `json:"display_name,omitempty"`
	TotalRequests      int64                `json:"total_requests"`
	TotalBlacklistHits int64                `json:"total_blacklist_hits"`
	Nodes              []UserNodeStats      `json:"nodes"`
	RecentMatches      []BlacklistMatchInfo `json:"recent_matches"`
	// Threat intel
	TotalThreats  int64            `json:"total_threats"`
	ThreatsByType map[string]int64 `json:"threats_by_type,omitempty"`
	RecentThreats []UserThreatInfo `json:"recent_threats,omitempty"`
	RiskLevel     string           `json:"risk_level,omitempty"`
	RiskScore     int              `json:"risk_score,omitempty"`
	// Remnawave data
	RemnaUUID         string  `json:"remna_uuid,omitempty"`
	RemnaStatus       string  `json:"remna_status,omitempty"`
	RemnaUsedTraffic  int64   `json:"remna_used_traffic,omitempty"`
	RemnaTrafficLimit int64   `json:"remna_traffic_limit,omitempty"`
	RemnaTrafficPct   float64 `json:"remna_traffic_percent,omitempty"`
	RemnaHwidCount    int     `json:"remna_hwid_count,omitempty"`
	RemnaHwidLimit    *int    `json:"remna_hwid_limit,omitempty"`
	RemnaOnlineAt     string  `json:"remna_online_at,omitempty"`
	RemnaExpireAt     string  `json:"remna_expire_at,omitempty"`
	RemnaTelegramID   *int64  `json:"remna_telegram_id,omitempty"`
	RemnaDescription  string  `json:"remna_description,omitempty"`
}

// UserThreatInfo represents a threat match for the user profile view
type UserThreatInfo struct {
	NodeID      string    `json:"node_id"`
	Destination string    `json:"destination"`
	ThreatType  string    `json:"threat_type"`
	Source      string    `json:"source"`
	Confidence  int       `json:"confidence"`
	Description string    `json:"description,omitempty"`
	SourceIP    string    `json:"source_ip,omitempty"`
	MatchedAt   time.Time `json:"matched_at"`
}

// PaginatedUserThreatsResponse is a paginated slice of threat matches for a
// single user filtered by threat_type.
type PaginatedUserThreatsResponse struct {
	Matches    []UserThreatInfo `json:"matches"`
	Total      int              `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalPages int              `json:"total_pages"`
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
	DisplayName string    `json:"display_name,omitempty"`
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
	Username      string   `json:"username"`
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

// GlobalStats represents aggregated global statistics. User counts are
// sourced from `remna_users` which the analyzer syncs from the Remnawave
// panel API every 5 minutes.
type GlobalStats struct {
	TotalRequests      int64 `json:"total_requests"`
	TotalBlacklistHits int64 `json:"total_blacklist"`
	TotalNodes         int   `json:"nodes_total"`
	NodesConnected     int   `json:"nodes_connected"`

	// Total + status breakdown (matches Remnawave panel "Пользователи" card)
	TotalUniqueUsers int `json:"total_unique_users"`
	ActiveUsers      int `json:"active_users"`
	DisabledUsers    int `json:"disabled_users"`
	ExpiredUsers     int `json:"expired_users"`
	LimitedUsers     int `json:"limited_users"`

	// Online breakdown by recency window (matches Remnawave "Онлайн" card).
	// OnlineUsers = users seen in last 1 minute → matches "В сети".
	OnlineUsers    int `json:"online_users"`
	OnlineLastHour int `json:"online_last_hour"`
	OnlineLast24h  int `json:"online_last_24h"`
	NeverOnline    int `json:"never_online"`
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
	// Categories aggregates distinct threat_type / blacklist labels for this
	// destination across all of the user's records (e.g. ["ads", "tracking"]).
	Categories []string `json:"categories"`
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

// PaginatedBlacklistMatchesResponse represents paginated blacklist matches response
type PaginatedBlacklistMatchesResponse struct {
	Matches    []BlacklistMatchInfo `json:"matches"`
	Total      int                  `json:"total"`
	Page       int                  `json:"page"`
	PageSize   int                  `json:"page_size"`
	TotalPages int                  `json:"total_pages"`
}

// SubscriptionAbuse represents a user suspected of sharing their subscription
type SubscriptionAbuse struct {
	UserEmail       string     `json:"user_email"`
	UserUUID        string     `json:"user_uuid,omitempty"`
	Username        string     `json:"username,omitempty"`
	UniqueIPs       int        `json:"unique_ips"`
	UniqueNodes     int        `json:"unique_nodes"`
	UniqueHWIDs     int        `json:"unique_hwids"`
	UniqueCountries int        `json:"unique_countries"`
	Countries       []string   `json:"countries"`
	Nodes           []string   `json:"nodes"`
	TotalRequests   int64      `json:"total_requests"`
	LastSeen        time.Time  `json:"last_seen"`
	IPs             []IPInfo   `json:"ips"`
	HWIDs           []HWIDInfo `json:"hwids,omitempty"`
	AbuseScore      int        `json:"abuse_score"` // Combined risk score 0-100
}

// IPInfo represents basic IP information for abuse detection
type IPInfo struct {
	IP           string    `json:"ip"`
	CountryCode  string    `json:"country_code"`
	City         string    `json:"city"`
	NodeID       string    `json:"node_id,omitempty"`
	RequestCount int64     `json:"request_count"`
	LastSeen     time.Time `json:"last_seen"`
}

// HWIDInfo represents HWID device information
type HWIDInfo struct {
	HWID        string    `json:"hwid"`
	Platform    string    `json:"platform,omitempty"`
	DeviceModel string    `json:"device_model,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}
