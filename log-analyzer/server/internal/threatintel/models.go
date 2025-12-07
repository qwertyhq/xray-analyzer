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
