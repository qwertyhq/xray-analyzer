package threatintel

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/xray-log-analyzer/server/internal/ipinfo"
)

// Service manages threat intelligence operations
type Service struct {
	loader         *FeedLoader
	storage        Storage
	ipInfo         *ipinfo.Service
	mu             sync.RWMutex
	updateInterval time.Duration
	stopChan       chan struct{}
	running        bool
}

// Storage interface for threat intel persistence
type Storage interface {
	SaveThreatMatch(ctx context.Context, match *ThreatMatch) error
	GetThreatMatches(ctx context.Context, limit int) ([]*ThreatMatch, error)
	GetThreatMatchesByUser(ctx context.Context, userEmail string, limit int) ([]*ThreatMatch, error)
	GetThreatMatchesByType(ctx context.Context, threatType string, limit int) ([]*ThreatMatch, error)
	GetThreatStats(ctx context.Context) (*ThreatStats, error)
	GetTopUsersByCategory(ctx context.Context, category string, limit int) ([]*CategoryUserStats, error)
	GetTopUsersByAllCategories(ctx context.Context, limit int) (map[string][]*CategoryUserStats, error)
	GetRecentUsersByCategory(ctx context.Context, category string, limit int) ([]*CategoryUserStats, error)
	GetRecentUsersByAllCategories(ctx context.Context, limit int) (map[string][]*CategoryUserStats, error)
	GetUsersByCategory(ctx context.Context, category string, page, pageSize int) ([]*CategoryUserStats, int, error)
	// Geo stats
	SaveGeoStats(ctx context.Context, countryCode, countryName, threatType, userEmail string) error
	SaveUserLocation(ctx context.Context, userEmail, countryCode, countryName, city string, lat, lon float64) error
	// Geo enrichment
	GetLocationsWithoutCoords(ctx context.Context, limit int) ([]*LocationWithoutCoords, error)
	UpdateLocationCoords(ctx context.Context, userEmail, countryCode, city string, lat, lon float64) error
}

// LocationWithoutCoords represents a user location missing coordinates
type LocationWithoutCoords struct {
	UserEmail   string
	CountryCode string
	City        string
}

// CategoryUserStats represents user stats for a content category
type CategoryUserStats struct {
	UserEmail   string   `json:"user_email"` // raw identifier from Xray logs (numeric id or username)
	DisplayName string   `json:"username"`   // resolved username from Remnawave when available
	Category    string   `json:"category"`
	MatchCount  int64    `json:"match_count"`
	Domains     []string `json:"domains"` // Top visited domains in this category
}

// NewService creates a new threat intelligence service
func NewService(storage Storage, ipInfoSvc *ipinfo.Service) *Service {
	return &Service{
		loader:         NewFeedLoader(),
		storage:        storage,
		ipInfo:         ipInfoSvc,
		updateInterval: 3 * time.Hour,
		stopChan:       make(chan struct{}),
	}
}

// Start starts the threat intelligence service
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	log.Println("threatintel: starting service")

	// Load feeds in background to not block server startup
	go func() {
		if err := s.loader.LoadAllFeeds(ctx); err != nil {
			log.Printf("threatintel: initial load error: %v", err)
		}
		log.Printf("threatintel: loaded %d indicators", s.loader.GetIndicatorCount())
	}()

	// Start background update loop
	go s.updateLoop(ctx)

	// Start geo enrichment loop (backfill coordinates for existing records)
	go s.geoEnrichmentLoop(ctx)

	return nil
}

// Stop stops the threat intelligence service
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	close(s.stopChan)
	s.running = false
	log.Println("threatintel: stopped service")
}

// updateLoop periodically updates threat feeds
func (s *Service) updateLoop(ctx context.Context) {
	ticker := time.NewTicker(s.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case <-ticker.C:
			log.Println("threatintel: updating feeds")
			if err := s.loader.LoadAllFeeds(ctx); err != nil {
				log.Printf("threatintel: update error: %v", err)
			}
			log.Printf("threatintel: updated, now have %d indicators", s.loader.GetIndicatorCount())
		}
	}
}

// geoEnrichmentLoop periodically enriches user locations with coordinates
func (s *Service) geoEnrichmentLoop(ctx context.Context) {
	// Start after a delay to let the system stabilize
	time.Sleep(30 * time.Second)

	// Run every 5 minutes
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Run immediately on start
	s.enrichGeoCoordinates(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.enrichGeoCoordinates(ctx)
		}
	}
}

// enrichGeoCoordinates enriches user locations without coordinates
func (s *Service) enrichGeoCoordinates(ctx context.Context) {
	if s.storage == nil || s.ipInfo == nil {
		return
	}

	locations, err := s.storage.GetLocationsWithoutCoords(ctx, 50)
	if err != nil {
		log.Printf("threatintel: geo enrichment error: %v", err)
		return
	}

	if len(locations) == 0 {
		return
	}

	log.Printf("threatintel: enriching %d locations without coordinates", len(locations))
	enriched := 0

	for _, loc := range locations {
		// Try to get coordinates from IP lookup cache or by city/country
		// We need an IP to lookup - try to find one from user_ip_history
		ipData := s.ipInfo.GetCachedByLocation(loc.CountryCode, loc.City)
		if ipData != nil && ipData.Lat != 0 && ipData.Lon != 0 {
			if err := s.storage.UpdateLocationCoords(ctx, loc.UserEmail, loc.CountryCode, ipData.City, ipData.Lat, ipData.Lon); err != nil {
				log.Printf("threatintel: failed to update coords for %s/%s: %v", loc.UserEmail, loc.CountryCode, err)
				continue
			}
			enriched++
		}

		// Rate limit to avoid overwhelming IP-API
		time.Sleep(100 * time.Millisecond)
	}

	if enriched > 0 {
		log.Printf("threatintel: enriched %d/%d locations with coordinates", enriched, len(locations))
	}
}

// CheckDestination checks if a destination is a known threat
func (s *Service) CheckDestination(destination string) *ThreatIndicator {
	return s.loader.CheckDestination(destination)
}

// CheckAndRecord checks a destination and records a match if found
func (s *Service) CheckAndRecord(ctx context.Context, userEmail, nodeID, sourceIP, destination string) *ThreatMatch {
	indicator := s.loader.CheckDestination(destination)
	if indicator == nil {
		return nil
	}

	// Don't record low confidence matches (adware/tracking from StevenBlack)
	// unless confidence is >= 70
	if indicator.Confidence < 70 {
		return nil
	}

	match := &ThreatMatch{
		UserEmail:   userEmail,
		NodeID:      nodeID,
		SourceIP:    sourceIP,
		Destination: destination,
		ThreatType:  indicator.ThreatType,
		Source:      indicator.Source,
		Confidence:  indicator.Confidence,
		Description: indicator.Description,
		MatchedAt:   time.Now(),
	}

	// Save to storage if available
	if s.storage != nil {
		if err := s.storage.SaveThreatMatch(ctx, match); err != nil {
			log.Printf("threatintel: failed to save match: %v", err)
		}

		// Save geo stats if IP info service is available
		if s.ipInfo != nil && sourceIP != "" {
			go func() {
				geoCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				if ipData, err := s.ipInfo.Lookup(geoCtx, sourceIP); err == nil && ipData != nil {
					// Save geo stats for threat
					s.storage.SaveGeoStats(geoCtx, ipData.CountryCode, ipData.Country, string(indicator.ThreatType), userEmail)
					// Save user location with coordinates
					s.storage.SaveUserLocation(geoCtx, userEmail, ipData.CountryCode, ipData.Country, ipData.City, ipData.Lat, ipData.Lon)
				}
			}()
		}
	}

	return match
}

// GetStats returns threat intelligence statistics
func (s *Service) GetStats() *ThreatStats {
	stats := s.loader.GetStats()

	// Add match stats from storage if available
	if s.storage != nil {
		ctx := context.Background()
		if dbStats, err := s.storage.GetThreatStats(ctx); err == nil {
			stats.TotalMatches = dbStats.TotalMatches
			stats.MatchesLast24h = dbStats.MatchesLast24h
		}
	}

	return stats
}

// GetFeedStatus returns the status of all feeds
func (s *Service) GetFeedStatus() []*FeedStatus {
	return s.loader.GetFeedStatus()
}

// GetIndicatorCount returns the total number of loaded indicators
func (s *Service) GetIndicatorCount() int {
	return s.loader.GetIndicatorCount()
}

// GetRecentMatches returns recent threat matches
func (s *Service) GetRecentMatches(ctx context.Context, limit int) ([]*ThreatMatch, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetThreatMatches(ctx, limit)
}

// GetUserMatches returns threat matches for a specific user
func (s *Service) GetUserMatches(ctx context.Context, userEmail string, limit int) ([]*ThreatMatch, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetThreatMatchesByUser(ctx, userEmail, limit)
}

// GetMatchesByType returns threat matches for a specific threat type
func (s *Service) GetMatchesByType(ctx context.Context, threatType string, limit int) ([]*ThreatMatch, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetThreatMatchesByType(ctx, threatType, limit)
}

// ForceUpdate forces an immediate update of all feeds
func (s *Service) ForceUpdate(ctx context.Context) error {
	log.Println("threatintel: forcing feed update")
	return s.loader.LoadAllFeeds(ctx)
}

// GetTopUsersByCategory returns top users for a specific content category
func (s *Service) GetTopUsersByCategory(ctx context.Context, category string, limit int) ([]*CategoryUserStats, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetTopUsersByCategory(ctx, category, limit)
}

// GetTopUsersByAllCategories returns top users for all content categories
func (s *Service) GetTopUsersByAllCategories(ctx context.Context, limit int) (map[string][]*CategoryUserStats, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetTopUsersByAllCategories(ctx, limit)
}

// GetRecentUsersByCategory returns recent users for a specific content category
func (s *Service) GetRecentUsersByCategory(ctx context.Context, category string, limit int) ([]*CategoryUserStats, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetRecentUsersByCategory(ctx, category, limit)
}

// GetRecentUsersByAllCategories returns recent users for all content categories
func (s *Service) GetRecentUsersByAllCategories(ctx context.Context, limit int) (map[string][]*CategoryUserStats, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetRecentUsersByAllCategories(ctx, limit)
}

// GetUsersByCategory returns users for a category with pagination
func (s *Service) GetUsersByCategory(ctx context.Context, category string, page, pageSize int) ([]*CategoryUserStats, int, error) {
	if s.storage == nil {
		return nil, 0, nil
	}
	return s.storage.GetUsersByCategory(ctx, category, page, pageSize)
}
