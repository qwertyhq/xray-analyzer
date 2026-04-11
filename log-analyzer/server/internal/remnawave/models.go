package remnawave

import "time"

// User represents a Remnawave user
type User struct {
	UUID                   string          `json:"uuid"`
	ID                     int64           `json:"id"`
	ShortUUID              string          `json:"shortUuid"`
	Username               string          `json:"username"`
	Status                 string          `json:"status"` // ACTIVE, DISABLED, LIMITED, EXPIRED
	TrafficLimitBytes      int64           `json:"trafficLimitBytes"`
	TrafficLimitStrategy   string          `json:"trafficLimitStrategy"` // NO_RESET, DAY, WEEK, MONTH
	SubLastUserAgent       *string         `json:"subLastUserAgent"`
	SubLastOpenedAt        *time.Time      `json:"subLastOpenedAt"`
	ExpireAt               time.Time       `json:"expireAt"`
	SubRevokedAt           *time.Time      `json:"subRevokedAt"`
	LastTrafficResetAt     *time.Time      `json:"lastTrafficResetAt"`
	Description            *string         `json:"description"` // Note field with user metadata
	Tag                    *string         `json:"tag"`
	TelegramID             *int64          `json:"telegramId"`
	Email                  *string         `json:"email"`
	HwidDeviceLimit        *int            `json:"hwidDeviceLimit"`
	LastTriggeredThreshold int             `json:"lastTriggeredThreshold"`
	CreatedAt              time.Time       `json:"createdAt"`
	UpdatedAt              time.Time       `json:"updatedAt"`
	ActiveInternalSquads   []InternalSquad `json:"activeInternalSquads"`
	ExternalSquadUUID      *string         `json:"externalSquadUuid"`
	SubscriptionURL        string          `json:"subscriptionUrl"`

	// Nested userTraffic object (new in API v2.3.x)
	UserTraffic *UserTraffic `json:"userTraffic"`

	// Legacy fields - for backwards compatibility, populated from UserTraffic
	UsedTrafficBytes    int64          `json:"-"`
	LifetimeUsedTraffic int64          `json:"-"`
	OnlineAt            *time.Time     `json:"-"`
	FirstConnectedAt    *time.Time     `json:"-"`
	LastConnectedNode   *ConnectedNode `json:"-"`

	// Parsed metadata from Description/Note field
	ParsedNote *ParsedNote `json:"-"`
}

// UserTraffic represents the nested traffic data in user response
type UserTraffic struct {
	UsedTrafficBytes         int64      `json:"usedTrafficBytes"`
	LifetimeUsedTrafficBytes int64      `json:"lifetimeUsedTrafficBytes"`
	OnlineAt                 *time.Time `json:"onlineAt"`
	FirstConnectedAt         *time.Time `json:"firstConnectedAt"`
	LastConnectedNodeUUID    *string    `json:"lastConnectedNodeUuid"`
}

// PopulateFromTraffic copies data from UserTraffic to legacy fields for compatibility
func (u *User) PopulateFromTraffic() {
	if u.UserTraffic != nil {
		u.UsedTrafficBytes = u.UserTraffic.UsedTrafficBytes
		u.LifetimeUsedTraffic = u.UserTraffic.LifetimeUsedTrafficBytes
		u.OnlineAt = u.UserTraffic.OnlineAt
		u.FirstConnectedAt = u.UserTraffic.FirstConnectedAt
	}
}

// ParsedNote represents parsed metadata from user's Description/Note field
type ParsedNote struct {
	RealName     string            `json:"real_name,omitempty"`
	Phone        string            `json:"phone,omitempty"`
	TelegramUser string            `json:"telegram_user,omitempty"`
	PaymentInfo  string            `json:"payment_info,omitempty"`
	Plan         string            `json:"plan,omitempty"`
	ExpiryDate   string            `json:"expiry_date,omitempty"`
	Notes        string            `json:"notes,omitempty"`
	USID         string            `json:"us_id,omitempty"` // Xray log user ID from US_ID: <number>
	Custom       map[string]string `json:"custom,omitempty"`
	RawText      string            `json:"raw_text,omitempty"`
}

// InternalSquad represents a user's internal squad assignment
type InternalSquad struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// ConnectedNode represents the last node a user connected to
type ConnectedNode struct {
	ConnectedAt time.Time `json:"connectedAt"`
	NodeName    string    `json:"nodeName"`
	CountryCode string    `json:"countryCode"`
}

// UsersResponse represents the response from GET /api/users
type UsersResponse struct {
	Users []User `json:"users"`
	Total int    `json:"total"`
}

// HwidDevice represents a hardware device associated with a user
type HwidDevice struct {
	Hwid        string    `json:"hwid"`
	UserUUID    string    `json:"userUuid"`
	Platform    *string   `json:"platform"` // iOS, Android, Windows, etc.
	OSVersion   *string   `json:"osVersion"`
	DeviceModel *string   `json:"deviceModel"`
	UserAgent   *string   `json:"userAgent"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// HwidDevicesResponse represents the response from GET /api/hwid/devices
type HwidDevicesResponse struct {
	Devices []HwidDevice `json:"devices"`
	Total   int          `json:"total"`
}

// HwidStats represents HWID statistics
type HwidStats struct {
	ByPlatform []PlatformCount `json:"byPlatform"`
	ByApp      []AppCount      `json:"byApp"`
	Stats      HwidStatsInfo   `json:"stats"`
}

// PlatformCount represents device count by platform
type PlatformCount struct {
	Platform string `json:"platform"`
	Count    int    `json:"count"`
}

// AppCount represents device count by app
type AppCount struct {
	App   string `json:"app"`
	Count int    `json:"count"`
}

// HwidStatsInfo represents overall HWID statistics
type HwidStatsInfo struct {
	TotalUniqueDevices        int     `json:"totalUniqueDevices"`
	TotalHwidDevices          int     `json:"totalHwidDevices"`
	AverageHwidDevicesPerUser float64 `json:"averageHwidDevicesPerUser"`
}

// SubscriptionRequest represents a subscription request history record
type SubscriptionRequest struct {
	ID        int       `json:"id"`
	UserUUID  string    `json:"userUuid"`
	RequestIP *string   `json:"requestIp"`
	UserAgent *string   `json:"userAgent"`
	RequestAt time.Time `json:"requestAt"`
}

// SubscriptionRequestsResponse represents the response from GET /api/subscription-request-history
type SubscriptionRequestsResponse struct {
	Records []SubscriptionRequest `json:"records"`
	Total   int                   `json:"total"`
}

// SubscriptionRequestStats represents subscription request statistics
type SubscriptionRequestStats struct {
	ByParsedApp []AppCount        `json:"byParsedApp"`
	HourlyStats []HourlyStatEntry `json:"hourlyRequestStats"`
}

// HourlyStatEntry represents hourly request count
type HourlyStatEntry struct {
	DateTime     time.Time `json:"dateTime"`
	RequestCount int       `json:"requestCount"`
}

// Node represents a Remnawave node
type Node struct {
	UUID              string     `json:"uuid"`
	Name              string     `json:"name"`
	Address           string     `json:"address"`
	Port              *int       `json:"port"`
	CountryCode       string     `json:"countryCode"`
	IsDisabled        bool       `json:"isDisabled"`
	IsConnected       bool       `json:"isConnected"`
	IsConnecting      bool       `json:"isConnecting"`
	TrafficUsedBytes  *int64     `json:"trafficUsedBytes"`
	TrafficLimitBytes *int64     `json:"trafficLimitBytes"`
	UsersOnline       *int       `json:"usersOnline"`
	XrayVersion       *string    `json:"xrayVersion"`
	NodeVersion       *string    `json:"nodeVersion"`
	XrayUptime        any        `json:"xrayUptime"`
	LastStatusChange  *time.Time `json:"lastStatusChange"`
	LastStatusMessage *string    `json:"lastStatusMessage"`
	ViewPosition      int        `json:"viewPosition"`
	Tags              []string   `json:"tags"`
	CreatedAt         time.Time  `json:"createdAt"`
	UpdatedAt         time.Time  `json:"updatedAt"`
}

// IsEnabled returns true if node is enabled (inverse of IsDisabled)
func (n *Node) IsEnabled() bool {
	return !n.IsDisabled
}

// GetOnlineUsers returns online users count, defaulting to 0 if nil
func (n *Node) GetOnlineUsers() int {
	if n.UsersOnline == nil {
		return 0
	}
	return *n.UsersOnline
}

// GetTrafficUsed returns traffic used, defaulting to 0 if nil
func (n *Node) GetTrafficUsed() int64 {
	if n.TrafficUsedBytes == nil {
		return 0
	}
	return *n.TrafficUsedBytes
}

// NodesResponse represents the response from GET /api/nodes
type NodesResponse struct {
	Nodes []Node `json:"nodes"`
}

// NodeUsage represents node usage statistics for a time period
type NodeUsage struct {
	NodeUUID                   string `json:"nodeUuid"`
	NodeName                   string `json:"nodeName"`
	NodeCountryCode            string `json:"nodeCountryCode"`
	Total                      int64  `json:"total"`
	TotalDownload              int64  `json:"totalDownload"`
	TotalUpload                int64  `json:"totalUpload"`
	HumanReadableTotal         string `json:"humanReadableTotal"`
	HumanReadableTotalDownload string `json:"humanReadableTotalDownload"`
	HumanReadableTotalUpload   string `json:"humanReadableTotalUpload"`
	Date                       string `json:"date"`
}

// SystemStats represents system statistics from Remnawave
type SystemStats struct {
	CPU         CPUInfo         `json:"cpu"`
	Memory      MemoryInfo      `json:"memory"`
	Uptime      int64           `json:"uptime"`
	Timestamp   int64           `json:"timestamp"`
	Users       UserStatsInfo   `json:"users"`
	OnlineStats OnlineStatsInfo `json:"onlineStats"`
	Nodes       NodesInfo       `json:"nodes"`
}

// CPUInfo represents CPU information
type CPUInfo struct {
	Cores         int `json:"cores"`
	PhysicalCores int `json:"physicalCores"`
}

// MemoryInfo represents memory information
type MemoryInfo struct {
	Total     int64 `json:"total"`
	Free      int64 `json:"free"`
	Used      int64 `json:"used"`
	Active    int64 `json:"active"`
	Available int64 `json:"available"`
}

// UserStatsInfo represents user statistics
type UserStatsInfo struct {
	StatusCounts map[string]int `json:"statusCounts"`
	TotalUsers   int            `json:"totalUsers"`
}

// OnlineStatsInfo represents online user statistics
type OnlineStatsInfo struct {
	LastDay     int `json:"lastDay"`
	LastWeek    int `json:"lastWeek"`
	NeverOnline int `json:"neverOnline"`
	OnlineNow   int `json:"onlineNow"`
}

// NodesInfo represents nodes information
type NodesInfo struct {
	TotalOnline        int    `json:"totalOnline"`
	TotalBytesLifetime string `json:"totalBytesLifetime"`
}
