package threatintel

import "time"

// ThreatType represents the type of threat
type ThreatType string

const (
	ThreatTypeMalware    ThreatType = "malware"
	ThreatTypeC2         ThreatType = "c2"
	ThreatTypePhishing   ThreatType = "phishing"
	ThreatTypeAdware     ThreatType = "adware"
	ThreatTypeTracker    ThreatType = "tracker"
	ThreatTypeBotnet     ThreatType = "botnet"
	ThreatTypeRansomware ThreatType = "ransomware"
	// Content category types
	ThreatTypePorn     ThreatType = "porn"
	ThreatTypeGambling ThreatType = "gambling"
	ThreatTypeSocial   ThreatType = "social"
	ThreatTypeFakeNews ThreatType = "fakenews"
	// P2P
	ThreatTypeTorrent ThreatType = "torrent"
	// Anonymization
	ThreatTypeTor ThreatType = "tor"
	// BlockList Project categories
	ThreatTypeAbuse    ThreatType = "abuse"
	ThreatTypeAds      ThreatType = "ads"
	ThreatTypeCrypto   ThreatType = "crypto"
	ThreatTypeDrugs    ThreatType = "drugs"
	ThreatTypeFraud    ThreatType = "fraud"
	ThreatTypePiracy   ThreatType = "piracy"
	ThreatTypeScam     ThreatType = "scam"
	ThreatTypeRedirect ThreatType = "redirect"
	ThreatTypeTikTok   ThreatType = "tiktok"
	ThreatTypeTracking ThreatType = "tracking"
)

// ThreatSource represents the source of threat data
type ThreatSource string

const (
	SourceURLhaus      ThreatSource = "urlhaus"
	SourceFeodoTracker ThreatSource = "feodo"
	SourceThreatFox    ThreatSource = "threatfox"
	SourceSSLBlacklist ThreatSource = "sslbl"
	SourceStevenBlack  ThreatSource = "stevenblack"
	// Content category sources (StevenBlack extensions)
	SourcePorn     ThreatSource = "porn-blocklist"
	SourceGambling ThreatSource = "gambling-blocklist"
	SourceSocial   ThreatSource = "social-blocklist"
	SourceFakeNews ThreatSource = "fakenews-blocklist"
	// P2P sources
	SourceTorrent ThreatSource = "torrent-trackers"
	// Anonymization sources
	SourceTor ThreatSource = "tor-exit-nodes"
	// BlockList Project - comprehensive category blocklists
	SourceBlockListAbuse      ThreatSource = "blocklist-abuse"
	SourceBlockListAds        ThreatSource = "blocklist-ads"
	SourceBlockListCrypto     ThreatSource = "blocklist-crypto"
	SourceBlockListDrugs      ThreatSource = "blocklist-drugs"
	SourceBlockListFraud      ThreatSource = "blocklist-fraud"
	SourceBlockListMalware    ThreatSource = "blocklist-malware"
	SourceBlockListPhishing   ThreatSource = "blocklist-phishing"
	SourceBlockListPiracy     ThreatSource = "blocklist-piracy"
	SourceBlockListPorn       ThreatSource = "blocklist-porn"
	SourceBlockListScam       ThreatSource = "blocklist-scam"
	SourceBlockListRedirect   ThreatSource = "blocklist-redirect"
	SourceBlockListTikTok     ThreatSource = "blocklist-tiktok"
	SourceBlockListTorrent    ThreatSource = "blocklist-torrent"
	SourceBlockListTracking   ThreatSource = "blocklist-tracking"
	SourceBlockListRansomware ThreatSource = "blocklist-ransomware"
)

// ThreatIndicator represents an indicator of compromise (IOC)
type ThreatIndicator struct {
	ID          int64        `json:"id"`
	Indicator   string       `json:"indicator"` // domain, IP, or URL
	Type        string       `json:"type"`      // domain, ip, url
	ThreatType  ThreatType   `json:"threat_type"`
	Source      ThreatSource `json:"source"`
	Confidence  int          `json:"confidence"` // 0-100
	Description string       `json:"description,omitempty"`
	Tags        []string     `json:"tags,omitempty"`
	FirstSeen   time.Time    `json:"first_seen"`
	LastSeen    time.Time    `json:"last_seen"`
	CreatedAt   time.Time    `json:"created_at"`
}

// ThreatMatch represents a match between user traffic and threat intel
type ThreatMatch struct {
	ID          int64        `json:"id"`
	UserEmail   string       `json:"user_email"`
	NodeID      string       `json:"node_id"`
	SourceIP    string       `json:"source_ip"`
	Destination string       `json:"destination"`
	IndicatorID int64        `json:"indicator_id"`
	ThreatType  ThreatType   `json:"threat_type"`
	Source      ThreatSource `json:"source"`
	Confidence  int          `json:"confidence"`
	Description string       `json:"description,omitempty"`
	MatchedAt   time.Time    `json:"matched_at"`
}

// ThreatStats represents threat intelligence statistics
type ThreatStats struct {
	TotalIndicators    int64            `json:"total_indicators"`
	IndicatorsByType   map[string]int64 `json:"indicators_by_type"`
	IndicatorsBySource map[string]int64 `json:"indicators_by_source"`
	TotalMatches       int64            `json:"total_matches"`
	MatchesLast24h     int64            `json:"matches_24h"`
	LastUpdated        time.Time        `json:"last_updated"`
}

// URLhausEntry represents an entry from URLhaus API
type URLhausEntry struct {
	ID          string `json:"id"`
	URLhausLink string `json:"urlhaus_link"`
	URL         string `json:"url"`
	URLStatus   string `json:"url_status"`
	Host        string `json:"host"`
	DateAdded   string `json:"date_added"`
	Threat      string `json:"threat"`
	Blacklists  struct {
		SpamhausDBL string `json:"spamhaus_dbl"`
		Surbl       string `json:"surbl"`
	} `json:"blacklists"`
	Reporter string   `json:"reporter"`
	Larted   string   `json:"larted"`
	Tags     []string `json:"tags"`
}

// URLhausResponse represents URLhaus API response
type URLhausResponse struct {
	QueryStatus string         `json:"query_status"`
	URLs        []URLhausEntry `json:"urls,omitempty"`
	URLCount    int            `json:"url_count,omitempty"`
	Host        string         `json:"host,omitempty"`
	Blacklists  struct {
		SpamhausDBL string `json:"spamhaus_dbl"`
		Surbl       string `json:"surbl"`
	} `json:"blacklists,omitempty"`
}

// FeodoEntry represents a Feodo Tracker entry
type FeodoEntry struct {
	IPAddress  string `json:"ip_address"`
	Port       int    `json:"port"`
	Status     string `json:"status"`
	Hostname   string `json:"hostname,omitempty"`
	ASNumber   int    `json:"as_number"`
	ASName     string `json:"as_name"`
	Country    string `json:"country"`
	FirstSeen  string `json:"first_seen"`
	LastOnline string `json:"last_online"`
	Malware    string `json:"malware"`
}

// ThreatFoxIOC represents a ThreatFox IOC
type ThreatFoxIOC struct {
	ID               string   `json:"id"`
	IOC              string   `json:"ioc"`
	IOCType          string   `json:"ioc_type"`
	ThreatType       string   `json:"threat_type"`
	ThreatTypeDesc   string   `json:"threat_type_desc"`
	Malware          string   `json:"malware"`
	MalwarePrintable string   `json:"malware_printable"`
	MalwareAlias     string   `json:"malware_alias"`
	MalwareMalpedia  string   `json:"malware_malpedia"`
	Confidence       int      `json:"confidence_level"`
	FirstSeen        string   `json:"first_seen"`
	LastSeen         string   `json:"last_seen"`
	Reporter         string   `json:"reporter"`
	Reference        string   `json:"reference"`
	Tags             []string `json:"tags"`
}

// ThreatFoxResponse represents ThreatFox API response
type ThreatFoxResponse struct {
	QueryStatus string         `json:"query_status"`
	Data        []ThreatFoxIOC `json:"data,omitempty"`
}

// FeedStatus represents the status of a threat feed
type FeedStatus struct {
	Source     ThreatSource `json:"source"`
	LastUpdate time.Time    `json:"last_update"`
	NextUpdate time.Time    `json:"next_update"`
	Indicators int64        `json:"indicators"`
	Status     string       `json:"status"` // ok, error, updating
	Error      string       `json:"error,omitempty"`
}

// HourlyThreatStats represents threat statistics for a single hour
type HourlyThreatStats struct {
	Hour        string           `json:"hour"` // Format: 2025-12-07T14
	TotalCount  int64            `json:"total_count"`
	ByType      map[string]int64 `json:"by_type"`
	UniqueUsers int64            `json:"unique_users"`
}

// DailyThreatStats represents threat statistics for a single day
type DailyThreatStats struct {
	Day         string           `json:"day"` // Format: 2025-12-07
	TotalCount  int64            `json:"total_count"`
	ByType      map[string]int64 `json:"by_type"`
	UniqueUsers int64            `json:"unique_users"`
}

// TimeAnalytics represents time-based threat analytics
type TimeAnalytics struct {
	HourlyStats []*HourlyThreatStats `json:"hourly_stats"`
	DailyStats  []*DailyThreatStats  `json:"daily_stats"`
	PeakHour    string               `json:"peak_hour"`
	PeakDay     string               `json:"peak_day"`
	Trends      map[string]float64   `json:"trends"` // category -> growth rate
}

// GeoStats represents threat statistics by country
type GeoStats struct {
	CountryCode string    `json:"country_code"`
	CountryName string    `json:"country_name"`
	ThreatType  string    `json:"threat_type"`
	MatchCount  int64     `json:"match_count"`
	UniqueUsers int64     `json:"unique_users"`
	LastMatch   time.Time `json:"last_match,omitempty"`
}

// GeoSummary provides aggregated geographic analysis
type GeoSummary struct {
	TotalCountries int                    `json:"total_countries"`
	TopCountries   []*CountryStats        `json:"top_countries"`
	ByThreatType   map[string][]*GeoStats `json:"by_threat_type"`
}

// CountryStats aggregates all threat types for a country
type CountryStats struct {
	CountryCode  string `json:"country_code"`
	CountryName  string `json:"country_name"`
	TotalMatches int64  `json:"total_matches"`
	UniqueUsers  int64  `json:"unique_users"`
	TopThreat    string `json:"top_threat"` // Most common threat type
}

// UserLocation tracks user access locations
type UserLocation struct {
	UserEmail    string    `json:"user_email"`
	CountryCode  string    `json:"country_code"`
	CountryName  string    `json:"country_name"`
	City         string    `json:"city,omitempty"`
	LastSeen     time.Time `json:"last_seen"`
	RequestCount int64     `json:"request_count"`
}

// AnomalyType represents the type of detected anomaly
type AnomalyType string

const (
	AnomalyActivitySpike     AnomalyType = "activity_spike"     // Unusual spike in activity
	AnomalyNightActivity     AnomalyType = "night_activity"     // Activity during unusual hours
	AnomalyNewUserHighVolume AnomalyType = "new_user_high_vol"  // New user with high activity
	AnomalyGeoAnomaly        AnomalyType = "geo_anomaly"        // Access from unusual location
	AnomalyThreatBurst       AnomalyType = "threat_burst"       // Multiple threats in short time
	AnomalyMultipleCountries AnomalyType = "multiple_countries" // User from multiple countries
)

// AnomalySeverity indicates the severity of the anomaly
type AnomalySeverity string

const (
	SeverityLow      AnomalySeverity = "low"
	SeverityMedium   AnomalySeverity = "medium"
	SeverityHigh     AnomalySeverity = "high"
	SeverityCritical AnomalySeverity = "critical"
)

// Anomaly represents a detected anomaly
type Anomaly struct {
	ID          string          `json:"id"`
	Type        AnomalyType     `json:"type"`
	Severity    AnomalySeverity `json:"severity"`
	UserEmail   string          `json:"user_email,omitempty"`
	Description string          `json:"description"`
	Details     map[string]any  `json:"details,omitempty"`
	DetectedAt  time.Time       `json:"detected_at"`
	Resolved    bool            `json:"resolved"`
}

// AnomalySummary provides overview of detected anomalies
type AnomalySummary struct {
	TotalAnomalies   int            `json:"total_anomalies"`
	BySeverity       map[string]int `json:"by_severity"`
	ByType           map[string]int `json:"by_type"`
	RecentAnomalies  []*Anomaly     `json:"recent_anomalies"`
	AffectedUsers    int            `json:"affected_users"`
	ThreatBurstCount int            `json:"threat_burst_count"`
}

// RiskLevel represents the risk level of a user
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// UserRiskProfile represents the risk profile of a user
type UserRiskProfile struct {
	UserEmail       string         `json:"user_email"`
	RiskLevel       RiskLevel      `json:"risk_level"`
	RiskScore       int            `json:"risk_score"` // 0-100
	TotalMatches    int            `json:"total_matches"`
	ThreatsByType   map[string]int `json:"threats_by_type"`
	UniqueCountries int            `json:"unique_countries"`
	AnomalyCount    int            `json:"anomaly_count"`
	LastActivity    time.Time      `json:"last_activity"`
	FirstSeen       time.Time      `json:"first_seen"`
	DaysActive      int            `json:"days_active"`
	TopDomains      []string       `json:"top_domains"`
	RiskFactors     []RiskFactor   `json:"risk_factors"`
	TrendDirection  string         `json:"trend_direction"` // "up", "down", "stable"
}

// RiskFactor represents a specific risk factor contributing to user's risk score
type RiskFactor struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Weight      int    `json:"weight"` // Points added to risk score
	DetectedAt  string `json:"detected_at"`
}

// UserRiskSummary provides an overview of user risk profiles
type UserRiskSummary struct {
	TotalUsers        int                `json:"total_users"`
	ByRiskLevel       map[string]int     `json:"by_risk_level"`
	HighRiskUsers     []*UserRiskProfile `json:"high_risk_users"`
	RecentEscalations int                `json:"recent_escalations"` // Users whose risk increased in last 24h
	AverageRiskScore  float64            `json:"average_risk_score"`
}

// DomainStats represents statistics for a single domain
type DomainStats struct {
	Domain       string         `json:"domain"`
	TotalHits    int            `json:"total_hits"`
	UniqueUsers  int            `json:"unique_users"`
	ThreatTypes  []string       `json:"threat_types"`
	Sources      []string       `json:"sources"`
	FirstSeen    time.Time      `json:"first_seen"`
	LastSeen     time.Time      `json:"last_seen"`
	RiskLevel    RiskLevel      `json:"risk_level"`
	CategoryHits map[string]int `json:"category_hits"`
}

// DNSQueryStats represents DNS query statistics
type DNSQueryStats struct {
	TotalQueries     int64          `json:"total_queries"`
	BlockedQueries   int64          `json:"blocked_queries"`
	BlockRate        float64        `json:"block_rate"`
	UniqueDomainsAll int            `json:"unique_domains_all"`
	UniqueDomainsBad int            `json:"unique_domains_bad"`
	TopDomains       []*DomainStats `json:"top_domains"`
	TopBlockedTypes  map[string]int `json:"top_blocked_types"`
	HourlyStats      []*HourlyDNS   `json:"hourly_stats"`
	DailyStats       []*DailyDNS    `json:"daily_stats"`
}

// HourlyDNS represents hourly DNS statistics
type HourlyDNS struct {
	Hour           string `json:"hour"`
	TotalQueries   int64  `json:"total_queries"`
	BlockedQueries int64  `json:"blocked_queries"`
	UniqueUsers    int    `json:"unique_users"`
}

// DailyDNS represents daily DNS statistics
type DailyDNS struct {
	Day            string `json:"day"`
	TotalQueries   int64  `json:"total_queries"`
	BlockedQueries int64  `json:"blocked_queries"`
	UniqueUsers    int    `json:"unique_users"`
}

// DomainCategory represents a domain categorization result
type DomainCategory struct {
	Domain     string     `json:"domain"`
	Category   ThreatType `json:"category"`
	Source     string     `json:"source"`
	Confidence int        `json:"confidence"`
	AddedAt    time.Time  `json:"added_at"`
}

// DNSAnalysisSummary provides a comprehensive DNS analysis overview
type DNSAnalysisSummary struct {
	QueryStats        *DNSQueryStats  `json:"query_stats"`
	TopBadDomains     []*DomainStats  `json:"top_bad_domains"`
	TopUsersByDNS     []*UserDNSStats `json:"top_users_by_dns"`
	CategoryBreakdown map[string]int  `json:"category_breakdown"`
	TrendDirection    string          `json:"trend_direction"` // "up", "down", "stable"
	RiskScore         int             `json:"risk_score"`      // Overall DNS risk 0-100
}

// UserDNSStats represents DNS statistics for a user
type UserDNSStats struct {
	UserEmail      string    `json:"user_email"`
	TotalQueries   int64     `json:"total_queries"`
	BlockedQueries int64     `json:"blocked_queries"`
	BlockRate      float64   `json:"block_rate"`
	TopDomains     []string  `json:"top_domains"`
	RiskLevel      RiskLevel `json:"risk_level"`
}
