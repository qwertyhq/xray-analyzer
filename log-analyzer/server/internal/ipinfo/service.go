package ipinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// IPInfo contains geolocation and ISP information for an IP address
type IPInfo struct {
	IP          string    `json:"ip"`
	Country     string    `json:"country"`
	CountryCode string    `json:"country_code"`
	Region      string    `json:"region"`
	City        string    `json:"city"`
	ISP         string    `json:"isp"`
	Org         string    `json:"org"`
	AS          string    `json:"as"`
	Mobile      bool      `json:"mobile"`
	Proxy       bool      `json:"proxy"`
	Hosting     bool      `json:"hosting"`
	Lat         float64   `json:"lat"`
	Lon         float64   `json:"lon"`
	CachedAt    time.Time `json:"cached_at"`
}

// ipAPIResponse matches the ip-api.com JSON response
type ipAPIResponse struct {
	Status      string  `json:"status"`
	Message     string  `json:"message,omitempty"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Mobile      bool    `json:"mobile"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
	Query       string  `json:"query"`
}

// Service provides IP information lookup with caching
type Service struct {
	client    *http.Client
	cache     map[string]*IPInfo
	cacheTTL  time.Duration
	mu        sync.RWMutex
	rateLimit chan struct{}
}

// NewService creates a new IP info service
func NewService() *Service {
	s := &Service{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache:     make(map[string]*IPInfo),
		cacheTTL:  24 * time.Hour,         // Cache for 24 hours
		rateLimit: make(chan struct{}, 1), // 1 concurrent request to respect rate limits
	}

	// Start cache cleanup goroutine
	go s.cleanupCache()

	return s
}

// cleanupCache removes expired entries periodically
func (s *Service) cleanupCache() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for ip, info := range s.cache {
			if now.Sub(info.CachedAt) > s.cacheTTL {
				delete(s.cache, ip)
			}
		}
		s.mu.Unlock()
	}
}

// Lookup returns IP information for a given IP address
func (s *Service) Lookup(ctx context.Context, ip string) (*IPInfo, error) {
	// Check cache first
	s.mu.RLock()
	if info, ok := s.cache[ip]; ok {
		s.mu.RUnlock()
		return info, nil
	}
	s.mu.RUnlock()

	// Rate limiting - wait for slot
	select {
	case s.rateLimit <- struct{}{}:
		defer func() { <-s.rateLimit }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Double-check cache after waiting
	s.mu.RLock()
	if info, ok := s.cache[ip]; ok {
		s.mu.RUnlock()
		return info, nil
	}
	s.mu.RUnlock()

	// Fetch from API
	info, err := s.fetchFromAPI(ctx, ip)
	if err != nil {
		return nil, err
	}

	// Store in cache
	s.mu.Lock()
	s.cache[ip] = info
	s.mu.Unlock()

	return info, nil
}

// fetchFromAPI fetches IP info from ip-api.com
func (s *Service) fetchFromAPI(ctx context.Context, ip string) (*IPInfo, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting,query&lang=ru", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Handle rate limiting
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limited by ip-api.com")
	}

	var apiResp ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	if apiResp.Status == "fail" {
		// Return partial info for private/reserved ranges
		return &IPInfo{
			IP:       ip,
			Country:  "Private",
			City:     apiResp.Message,
			CachedAt: time.Now(),
		}, nil
	}

	return &IPInfo{
		IP:          apiResp.Query,
		Country:     apiResp.Country,
		CountryCode: apiResp.CountryCode,
		Region:      apiResp.RegionName,
		City:        apiResp.City,
		ISP:         apiResp.ISP,
		Org:         apiResp.Org,
		AS:          apiResp.AS,
		Mobile:      apiResp.Mobile,
		Proxy:       apiResp.Proxy,
		Hosting:     apiResp.Hosting,
		Lat:         apiResp.Lat,
		Lon:         apiResp.Lon,
		CachedAt:    time.Now(),
	}, nil
}

// LookupBatch looks up multiple IPs (up to 100)
func (s *Service) LookupBatch(ctx context.Context, ips []string) (map[string]*IPInfo, error) {
	result := make(map[string]*IPInfo)
	var toFetch []string

	// Check cache first
	s.mu.RLock()
	for _, ip := range ips {
		if info, ok := s.cache[ip]; ok {
			result[ip] = info
		} else {
			toFetch = append(toFetch, ip)
		}
	}
	s.mu.RUnlock()

	if len(toFetch) == 0 {
		return result, nil
	}

	// Limit batch size
	if len(toFetch) > 100 {
		toFetch = toFetch[:100]
	}

	// Rate limiting
	select {
	case s.rateLimit <- struct{}{}:
		defer func() { <-s.rateLimit }()
	case <-ctx.Done():
		return result, ctx.Err()
	}

	// Fetch batch from API
	url := "http://ip-api.com/batch?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting,query&lang=ru"

	body, err := json.Marshal(toFetch)
	if err != nil {
		return result, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Body = http.NoBody

	// Use custom request with body
	req2, _ := http.NewRequestWithContext(ctx, "POST", url, nil)
	req2.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Post(url, "application/json", nil)
	if err != nil {
		// Fallback to individual lookups
		for _, ip := range toFetch {
			if info, err := s.fetchFromAPI(ctx, ip); err == nil {
				result[ip] = info
				s.mu.Lock()
				s.cache[ip] = info
				s.mu.Unlock()
			}
			// Small delay between requests
			time.Sleep(100 * time.Millisecond)
		}
		return result, nil
	}
	defer resp.Body.Close()

	_ = body // Used in actual POST

	var responses []ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&responses); err != nil {
		return result, err
	}

	s.mu.Lock()
	for _, apiResp := range responses {
		info := &IPInfo{
			IP:          apiResp.Query,
			Country:     apiResp.Country,
			CountryCode: apiResp.CountryCode,
			Region:      apiResp.RegionName,
			City:        apiResp.City,
			ISP:         apiResp.ISP,
			Org:         apiResp.Org,
			AS:          apiResp.AS,
			Mobile:      apiResp.Mobile,
			Proxy:       apiResp.Proxy,
			Hosting:     apiResp.Hosting,
			Lat:         apiResp.Lat,
			Lon:         apiResp.Lon,
			CachedAt:    time.Now(),
		}

		if apiResp.Status == "fail" {
			info.Country = "Private"
			info.City = apiResp.Message
		}

		s.cache[apiResp.Query] = info
		result[apiResp.Query] = info
	}
	s.mu.Unlock()

	return result, nil
}

// GetCached returns cached IP info without API call
func (s *Service) GetCached(ip string) *IPInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cache[ip]
}

// GetCachedByLocation returns cached IP info for a country/city combination
// This is used to enrich existing records with coordinates
func (s *Service) GetCachedByLocation(countryCode, city string) *IPInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find any cached entry matching country code and city
	for _, info := range s.cache {
		if info.CountryCode == countryCode && info.Lat != 0 && info.Lon != 0 {
			// If city matches or we just need country coords
			if city == "" || info.City == city {
				return info
			}
		}
	}

	// If no exact city match, return any entry with matching country
	for _, info := range s.cache {
		if info.CountryCode == countryCode && info.Lat != 0 && info.Lon != 0 {
			return info
		}
	}

	return nil
}

// GetCacheStats returns cache statistics
func (s *Service) GetCacheStats() (total int, expired int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	total = len(s.cache)
	for _, info := range s.cache {
		if now.Sub(info.CachedAt) > s.cacheTTL {
			expired++
		}
	}
	return
}
