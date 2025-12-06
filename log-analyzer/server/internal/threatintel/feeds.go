package threatintel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxRetries    = 3
	retryBaseWait = 5 * time.Second
)

// FeedLoader handles loading threat intelligence feeds
type FeedLoader struct {
	client     *http.Client
	mu         sync.RWMutex
	indicators map[string]*ThreatIndicator // key: indicator value (domain/ip)
	feedStatus map[ThreatSource]*FeedStatus
}

// NewFeedLoader creates a new feed loader
func NewFeedLoader() *FeedLoader {
	return &FeedLoader{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		indicators: make(map[string]*ThreatIndicator),
		feedStatus: make(map[ThreatSource]*FeedStatus),
	}
}

// loadWithRetry wraps a loader function with retry logic
func (f *FeedLoader) loadWithRetry(ctx context.Context, source ThreatSource, loader func(context.Context) (int, error)) (int, error) {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		count, err := loader(ctx)

		// Success with data
		if err == nil && count > 0 {
			return count, nil
		}

		// Error occurred
		if err != nil {
			lastErr = err
			log.Printf("threatintel: %s attempt %d/%d failed: %v", source, attempt, maxRetries, err)
		} else if count == 0 {
			// No error but zero results - treat as temporary failure
			lastErr = fmt.Errorf("received 0 indicators")
			log.Printf("threatintel: %s attempt %d/%d returned 0 indicators, retrying...", source, attempt, maxRetries)
		}

		// Don't sleep after last attempt
		if attempt < maxRetries {
			wait := retryBaseWait * time.Duration(attempt)
			log.Printf("threatintel: %s waiting %v before retry...", source, wait)

			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(wait):
			}
		}
	}

	return 0, fmt.Errorf("failed after %d attempts: %w", maxRetries, lastErr)
}

// LoadAllFeeds loads all threat intelligence feeds
func (f *FeedLoader) LoadAllFeeds(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 30) // Enough buffer for all feeds

	// Load feeds concurrently
	feeds := []struct {
		source ThreatSource
		loader func(context.Context) (int, error)
	}{
		{SourceURLhaus, f.loadURLhaus},
		{SourceFeodoTracker, f.loadFeodoTracker},
		{SourceThreatFox, f.loadThreatFox},
		{SourceStevenBlack, f.loadStevenBlack},
		// Content category blocklists
		{SourcePorn, f.loadPornBlocklist},
		{SourceGambling, f.loadGamblingBlocklist},
		{SourceSocial, f.loadSocialBlocklist},
		{SourceFakeNews, f.loadFakeNewsBlocklist},
		// P2P
		{SourceTorrent, f.loadTorrentTrackers},
		// Anonymization
		{SourceTor, f.loadTorExitNodes},
		// BlockList Project - comprehensive category blocklists
		{SourceBlockListAbuse, f.loadBlockListAbuse},
		{SourceBlockListAds, f.loadBlockListAds},
		{SourceBlockListCrypto, f.loadBlockListCrypto},
		{SourceBlockListDrugs, f.loadBlockListDrugs},
		{SourceBlockListFraud, f.loadBlockListFraud},
		{SourceBlockListMalware, f.loadBlockListMalware},
		{SourceBlockListPhishing, f.loadBlockListPhishing},
		{SourceBlockListPiracy, f.loadBlockListPiracy},
		{SourceBlockListPorn, f.loadBlockListPorn},
		{SourceBlockListScam, f.loadBlockListScam},
		{SourceBlockListRedirect, f.loadBlockListRedirect},
		{SourceBlockListTikTok, f.loadBlockListTikTok},
		{SourceBlockListTorrent, f.loadBlockListTorrent},
		{SourceBlockListTracking, f.loadBlockListTracking},
		{SourceBlockListRansomware, f.loadBlockListRansomware},
	}

	for _, feed := range feeds {
		wg.Add(1)
		go func(source ThreatSource, loader func(context.Context) (int, error)) {
			defer wg.Done()

			f.updateFeedStatus(source, "updating", "", 0)
			start := time.Now()

			// Use retry wrapper
			count, err := f.loadWithRetry(ctx, source, loader)
			if err != nil {
				f.updateFeedStatus(source, "error", err.Error(), 0)
				errChan <- fmt.Errorf("%s: %w", source, err)
				return
			}

			f.updateFeedStatus(source, "ok", "", int64(count))
			log.Printf("threatintel: loaded %d indicators from %s in %v", count, source, time.Since(start))
		}(feed.source, feed.loader)
	}

	wg.Wait()
	close(errChan)

	// Collect errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		log.Printf("threatintel: %d feeds failed to load", len(errors))
	}

	return nil
}

// updateFeedStatus updates the status of a feed
func (f *FeedLoader) updateFeedStatus(source ThreatSource, status, errMsg string, count int64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.feedStatus[source] = &FeedStatus{
		Source:     source,
		LastUpdate: time.Now(),
		NextUpdate: time.Now().Add(6 * time.Hour),
		Indicators: count,
		Status:     status,
		Error:      errMsg,
	}
}

// loadURLhaus loads malware URLs from URLhaus plain text feed (no API key required)
func (f *FeedLoader) loadURLhaus(ctx context.Context) (int, error) {
	// Use plain text feed instead of JSON API (no auth required)
	resp, err := f.client.Get("https://urlhaus.abuse.ch/downloads/text_online/")
	if err != nil {
		return 0, fmt.Errorf("fetch urlhaus: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("urlhaus returned status %d", resp.StatusCode)
	}

	count := 0
	f.mu.Lock()
	defer f.mu.Unlock()

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse URL and extract host
		u, err := url.Parse(line)
		if err != nil {
			continue
		}

		host := u.Hostname()
		if host == "" {
			continue
		}

		indicator := &ThreatIndicator{
			Indicator:   strings.ToLower(host),
			Type:        "domain",
			ThreatType:  ThreatTypeMalware,
			Source:      SourceURLhaus,
			Confidence:  80,
			Description: "Malware distribution host",
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
		count++
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("scan urlhaus: %w", err)
	}

	return count, nil
}

// loadFeodoTracker loads C2 server IPs from Feodo Tracker
func (f *FeedLoader) loadFeodoTracker(ctx context.Context) (int, error) {
	resp, err := f.client.Get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
	if err != nil {
		return 0, fmt.Errorf("fetch feodo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("feodo returned status %d", resp.StatusCode)
	}

	var entries []FeodoEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return 0, fmt.Errorf("decode feodo: %w", err)
	}

	count := 0
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, entry := range entries {
		if entry.IPAddress == "" {
			continue
		}

		// Determine threat type from malware name
		threatType := ThreatTypeC2
		malwareLower := strings.ToLower(entry.Malware)
		if strings.Contains(malwareLower, "botnet") {
			threatType = ThreatTypeBotnet
		}

		indicator := &ThreatIndicator{
			Indicator:   entry.IPAddress,
			Type:        "ip",
			ThreatType:  threatType,
			Source:      SourceFeodoTracker,
			Confidence:  90,
			Description: fmt.Sprintf("%s C2 server (%s)", entry.Malware, entry.Country),
			Tags:        []string{entry.Malware, entry.Country},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
		count++
	}

	return count, nil
}

// loadThreatFox loads IOCs from ThreatFox plain text feed (no API key required)
func (f *FeedLoader) loadThreatFox(ctx context.Context) (int, error) {
	// Use plain text CSV feed instead of JSON API (no auth required)
	resp, err := f.client.Get("https://threatfox.abuse.ch/export/csv/recent/")
	if err != nil {
		return 0, fmt.Errorf("fetch threatfox: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("threatfox returned status %d", resp.StatusCode)
	}

	count := 0
	f.mu.Lock()
	defer f.mu.Unlock()

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// CSV format: "first_seen_utc", "ioc_id", "ioc_value", "ioc_type", ...
		// Note: ThreatFox uses ", " (comma-space) as delimiter, so we split and trim
		parts := strings.Split(line, ",")
		if len(parts) < 8 {
			continue
		}

		// Remove quotes and whitespace from fields
		iocValue := strings.Trim(strings.TrimSpace(parts[2]), `" `)
		iocType := strings.Trim(strings.TrimSpace(parts[3]), `" `)
		threatType := strings.Trim(strings.TrimSpace(parts[4]), `" `)
		malware := strings.Trim(strings.TrimSpace(parts[7]), `" `)

		// Only process domain and IP IOCs
		var indicatorType string
		switch iocType {
		case "domain":
			indicatorType = "domain"
		case "ip:port":
			indicatorType = "ip"
			// Extract IP from ip:port format
			if idx := strings.Index(iocValue, ":"); idx > 0 {
				iocValue = iocValue[:idx]
			}
		default:
			continue
		}

		// Map threat type
		threat := ThreatTypeMalware
		switch strings.ToLower(threatType) {
		case "botnet_cc":
			threat = ThreatTypeBotnet
		case "cc":
			threat = ThreatTypeC2
		case "payload_delivery":
			threat = ThreatTypeMalware
		}

		indicator := &ThreatIndicator{
			Indicator:   strings.ToLower(iocValue),
			Type:        indicatorType,
			ThreatType:  threat,
			Source:      SourceThreatFox,
			Confidence:  75,
			Description: malware,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
		count++
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("scan threatfox: %w", err)
	}

	return count, nil
}

// loadStevenBlack loads domains from StevenBlack hosts file
func (f *FeedLoader) loadStevenBlack(ctx context.Context) (int, error) {
	resp, err := f.client.Get("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
	if err != nil {
		return 0, fmt.Errorf("fetch stevenblack: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("stevenblack returned status %d", resp.StatusCode)
	}

	count := 0
	f.mu.Lock()
	defer f.mu.Unlock()

	scanner := bufio.NewScanner(resp.Body)
	// Increase buffer size for long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse hosts file format: 0.0.0.0 domain.com
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		// Skip localhost entries
		domain := strings.ToLower(parts[1])
		if domain == "localhost" || domain == "localhost.localdomain" ||
			domain == "local" || strings.HasPrefix(domain, "broadcasthost") {
			continue
		}

		// Determine threat type based on domain patterns
		threatType := ThreatTypeAdware
		domainLower := strings.ToLower(domain)
		if strings.Contains(domainLower, "track") || strings.Contains(domainLower, "analytics") ||
			strings.Contains(domainLower, "telemetry") || strings.Contains(domainLower, "metric") {
			threatType = ThreatTypeTracker
		}

		indicator := &ThreatIndicator{
			Indicator:   domain,
			Type:        "domain",
			ThreatType:  threatType,
			Source:      SourceStevenBlack,
			Confidence:  60, // Lower confidence for adware/tracking
			Description: "Adware/Tracking domain",
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
		count++
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return count, fmt.Errorf("scan stevenblack: %w", err)
	}

	return count, nil
}

// CheckIndicator checks if a domain/IP is a known threat
func (f *FeedLoader) CheckIndicator(indicator string) *ThreatIndicator {
	f.mu.RLock()
	defer f.mu.RUnlock()

	indicator = strings.ToLower(indicator)

	// Direct match
	if ind, ok := f.indicators[indicator]; ok {
		return ind
	}

	// For domains, also check parent domains
	if strings.Contains(indicator, ".") && !isIP(indicator) {
		parts := strings.Split(indicator, ".")
		// Check all possible parent domains (from most specific to least)
		// e.g., for "www.torproject.org" check: "torproject.org", then "org" (but skip TLDs)
		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[i:], ".")
			// Skip single-part TLDs
			if !strings.Contains(parent, ".") {
				continue
			}
			if ind, ok := f.indicators[parent]; ok {
				return ind
			}
		}
	}

	return nil
}

// CheckDestination checks a destination (domain:port or IP:port) against threat intel
func (f *FeedLoader) CheckDestination(destination string) *ThreatIndicator {
	// Extract host and port from destination
	host := destination
	port := 0
	if idx := strings.LastIndex(destination, ":"); idx > 0 {
		// Handle IPv6 addresses
		if strings.Count(destination, ":") > 1 && !strings.HasPrefix(destination, "[") {
			// This is IPv6 without brackets, keep as is
		} else {
			host = destination[:idx]
			// Parse port
			if p, err := strconv.Atoi(destination[idx+1:]); err == nil {
				port = p
			}
		}
	}

	// Remove brackets from IPv6
	host = strings.Trim(host, "[]")

	// First check by indicator (domain/IP)
	if ind := f.CheckIndicator(host); ind != nil {
		return ind
	}

	// Then check by port for protocol detection
	if port > 0 {
		if ind := f.checkPortIndicator(host, port); ind != nil {
			return ind
		}
	}

	return nil
}

// checkPortIndicator detects threats based on destination port
func (f *FeedLoader) checkPortIndicator(host string, port int) *ThreatIndicator {
	// Tor network ports
	// 9001 - ORPort (relay connections)
	// 9030 - DirPort (directory services)
	// 9050 - Default SOCKS proxy
	// 9150 - Tor Browser SOCKS
	// 9051 - Control port
	torPorts := map[int]string{
		9001: "Tor ORPort (relay connection)",
		9030: "Tor DirPort (directory)",
		9050: "Tor SOCKS proxy",
		9051: "Tor control port",
		9150: "Tor Browser SOCKS",
		9151: "Tor Browser control",
	}

	if desc, ok := torPorts[port]; ok {
		return &ThreatIndicator{
			Indicator:   fmt.Sprintf("%s:%d", host, port),
			Type:        "port",
			ThreatType:  ThreatTypeTor,
			Source:      SourceTor,
			Confidence:  70, // Lower confidence - port-based detection
			Description: desc,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}
	}

	// BitTorrent ports
	// 6881-6889 - Classic BitTorrent range
	// 6969 - Popular tracker port
	// 51413 - Transmission default
	// 6880-6999 - Extended P2P range
	isTorrentPort := false
	torrentDesc := ""

	switch {
	case port >= 6881 && port <= 6889:
		isTorrentPort = true
		torrentDesc = "BitTorrent classic port range (6881-6889)"
	case port == 6969:
		isTorrentPort = true
		torrentDesc = "BitTorrent tracker port (6969)"
	case port == 51413:
		isTorrentPort = true
		torrentDesc = "Transmission BitTorrent port"
	case port >= 6890 && port <= 6999:
		isTorrentPort = true
		torrentDesc = "BitTorrent extended port range"
	case port == 16881 || port == 26881:
		isTorrentPort = true
		torrentDesc = "Alternative BitTorrent port"
	case port == 8999:
		isTorrentPort = true
		torrentDesc = "qBittorrent default port"
	}

	if isTorrentPort {
		return &ThreatIndicator{
			Indicator:   fmt.Sprintf("%s:%d", host, port),
			Type:        "port",
			ThreatType:  ThreatTypeTorrent,
			Source:      SourceTorrent,
			Confidence:  65, // Lower confidence - port-based detection
			Description: torrentDesc,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}
	}

	return nil
}

// GetIndicatorCount returns the total number of loaded indicators
func (f *FeedLoader) GetIndicatorCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.indicators)
}

// GetFeedStatus returns the status of all feeds
func (f *FeedLoader) GetFeedStatus() []*FeedStatus {
	f.mu.RLock()
	defer f.mu.RUnlock()

	statuses := make([]*FeedStatus, 0, len(f.feedStatus))
	for _, status := range f.feedStatus {
		statuses = append(statuses, status)
	}
	return statuses
}

// GetStats returns threat intelligence statistics
func (f *FeedLoader) GetStats() *ThreatStats {
	f.mu.RLock()
	defer f.mu.RUnlock()

	stats := &ThreatStats{
		TotalIndicators:    int64(len(f.indicators)),
		IndicatorsByType:   make(map[string]int64),
		IndicatorsBySource: make(map[string]int64),
		LastUpdated:        time.Now(),
	}

	for _, ind := range f.indicators {
		stats.IndicatorsByType[string(ind.ThreatType)]++
		stats.IndicatorsBySource[string(ind.Source)]++
	}

	return stats
}

// isIP checks if a string is an IP address
func isIP(s string) bool {
	// Simple check for IPv4
	parts := strings.Split(s, ".")
	if len(parts) == 4 {
		for _, part := range parts {
			if len(part) == 0 || len(part) > 3 {
				return false
			}
			for _, c := range part {
				if c < '0' || c > '9' {
					return false
				}
			}
		}
		return true
	}
	// IPv6 check
	return strings.Contains(s, ":")
}

// loadCategoryHosts loads a StevenBlack category-specific hosts file
func (f *FeedLoader) loadCategoryHosts(ctx context.Context, url string, source ThreatSource, threatType ThreatType, description string, confidence int) (int, error) {
	resp, err := f.client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("fetch %s: %w", source, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s returned status %d", source, resp.StatusCode)
	}

	count := 0
	f.mu.Lock()
	defer f.mu.Unlock()

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse hosts file format: 0.0.0.0 domain.com
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		// Skip localhost entries
		domain := strings.ToLower(parts[1])
		if domain == "localhost" || domain == "localhost.localdomain" ||
			domain == "local" || strings.HasPrefix(domain, "broadcasthost") ||
			domain == "0.0.0.0" {
			continue
		}

		// Skip if already in indicators with higher confidence
		if existing, ok := f.indicators[domain]; ok && existing.Confidence >= confidence {
			continue
		}

		indicator := &ThreatIndicator{
			Indicator:   domain,
			Type:        "domain",
			ThreatType:  threatType,
			Source:      source,
			Confidence:  confidence,
			Description: description,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
		count++
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return count, fmt.Errorf("scan %s: %w", source, err)
	}

	return count, nil
}

// loadPornBlocklist loads porn/adult content domains
func (f *FeedLoader) loadPornBlocklist(ctx context.Context) (int, error) {
	return f.loadCategoryHosts(
		ctx,
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/porn/sinfonietta/hosts",
		SourcePorn,
		ThreatTypePorn,
		"Adult/Porn content",
		75,
	)
}

// loadGamblingBlocklist loads gambling/casino domains
func (f *FeedLoader) loadGamblingBlocklist(ctx context.Context) (int, error) {
	return f.loadCategoryHosts(
		ctx,
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/gambling/sinfonietta/hosts",
		SourceGambling,
		ThreatTypeGambling,
		"Gambling/Casino site",
		75,
	)
}

// loadSocialBlocklist loads social media domains
func (f *FeedLoader) loadSocialBlocklist(ctx context.Context) (int, error) {
	return f.loadCategoryHosts(
		ctx,
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/social/sinfonietta/hosts",
		SourceSocial,
		ThreatTypeSocial,
		"Social media site",
		75,
	)
}

// loadFakeNewsBlocklist loads fake news domains
func (f *FeedLoader) loadFakeNewsBlocklist(ctx context.Context) (int, error) {
	return f.loadCategoryHosts(
		ctx,
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/fakenews/hosts",
		SourceFakeNews,
		ThreatTypeFakeNews,
		"Fake news site",
		75,
	)
}

// loadTorrentTrackers loads BitTorrent tracker domains from ngosang/trackerslist
func (f *FeedLoader) loadTorrentTrackers(ctx context.Context) (int, error) {
	// Load from multiple ngosang/trackerslist sources for comprehensive coverage
	// All lists are automatically updated daily
	trackerURLs := []string{
		// Main comprehensive list (121 trackers)
		"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt",
		// Best/most popular trackers (20 trackers)
		"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt",
		// UDP trackers (50 trackers)
		"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_udp.txt",
		// HTTP trackers (53 trackers)
		"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_http.txt",
		// HTTPS trackers (18 trackers)
		"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_https.txt",
		// WebSocket/WebTorrent trackers (4 trackers)
		"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_ws.txt",
		// I2P trackers (10 trackers) - anonymous network
		"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_i2p.txt",
		// Yggdrasil network trackers
		"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_yggdrasil.txt",
		// IP-based lists (for when DNS resolution is needed)
		"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_ip.txt",
		"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best_ip.txt",
	}

	count := 0
	for _, trackerURL := range trackerURLs {
		c, err := f.loadTorrentTrackersFromURL(ctx, trackerURL)
		if err != nil {
			log.Printf("threatintel: failed to load torrent trackers from %s: %v", trackerURL, err)
			continue
		}
		count += c
	}

	// Also add known BitTorrent-related domains with pattern matching
	f.addTorrentPatterns()

	return count, nil
}

// loadTorrentTrackersFromURL loads torrent trackers from a URL
func (f *FeedLoader) loadTorrentTrackersFromURL(ctx context.Context, trackerURL string) (int, error) {
	resp, err := f.client.Get(trackerURL)
	if err != nil {
		return 0, fmt.Errorf("fetch torrent trackers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("torrent trackers returned status %d", resp.StatusCode)
	}

	count := 0
	f.mu.Lock()
	defer f.mu.Unlock()

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Parse tracker URL to extract host
		// Format: udp://tracker.example.com:6969/announce or http://tracker.example.com/announce
		u, err := url.Parse(line)
		if err != nil {
			// Maybe it's just an IP address
			if isIP(line) {
				if _, exists := f.indicators[line]; !exists {
					f.indicators[line] = &ThreatIndicator{
						Indicator:   line,
						Type:        "ip",
						ThreatType:  ThreatTypeTorrent,
						Source:      SourceTorrent,
						Confidence:  85,
						Description: "BitTorrent tracker IP",
						FirstSeen:   time.Now(),
						LastSeen:    time.Now(),
						CreatedAt:   time.Now(),
					}
					count++
				}
			}
			continue
		}

		host := u.Hostname()
		if host == "" {
			continue
		}

		// Skip if already exists
		if _, exists := f.indicators[host]; exists {
			continue
		}

		// Determine type based on whether it's an IP or domain
		indicatorType := "domain"
		description := "BitTorrent tracker"
		if isIP(host) {
			indicatorType = "ip"
			description = "BitTorrent tracker IP"
		}

		indicator := &ThreatIndicator{
			Indicator:   strings.ToLower(host),
			Type:        indicatorType,
			ThreatType:  ThreatTypeTorrent,
			Source:      SourceTorrent,
			Confidence:  85, // High confidence - these are known tracker domains
			Description: description,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
		count++
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return count, fmt.Errorf("scan torrent trackers: %w", err)
	}

	return count, nil
}

// addTorrentPatterns adds common torrent-related domain patterns
func (f *FeedLoader) addTorrentPatterns() {
	// These are known BitTorrent DHT bootstrap nodes and common tracker patterns
	torrentDomains := []string{
		// DHT Bootstrap nodes
		"router.bittorrent.com",
		"router.utorrent.com",
		"dht.transmissionbt.com",
		"dht.aelitis.com",
		// Popular torrent sites (for detection)
		"thepiratebay.org",
		"www.thepiratebay.org",
		"thepiratebay.se",
		"pirateproxy.live",
		"1337x.to",
		"www.1337x.to",
		"1337x.st",
		"1337x.is",
		"rarbg.to",
		"rarbgmirror.org",
		"nyaa.si",
		"sukebei.nyaa.si",
		"rutracker.org",
		"rutracker.net",
		"rutracker.cc",
		"rutor.info",
		"rutor.is",
		"rutor.org",
		"nnmclub.to",
		"nnm-club.me",
		"kinozal.tv",
		"kinozal.guru",
		"rustorka.com",
		"pornolab.net",
		"torrentgalaxy.to",
		"torrentgalaxy.mx",
		"limetorrents.info",
		"limetorrents.cc",
		"torrentdownloads.me",
		"torrentz2.eu",
		"torrentz2.is",
		"bt4g.org",
		"bitsearch.to",
		"yts.mx",
		"yts.am",
		"yts.lt",
		"eztv.re",
		"eztv.io",
		"eztv.ag",
		"zooqle.com",
		"magnetdl.com",
		"idope.se",
		"torlock.com",
		"torlock2.com",
		"yourbittorrent.com",
		"glodls.to",
		// Russian torrent sites
		"nnmclub.to",
		"rutor.info",
		"tfile.me",
		"torrent-games.net",
		"fast-torrent.ru",
		"bitru.org",
		"seedoff.cc",
		"underverse.me",
		// Torrent client domains
		"check.utorrent.com",
		"update.utorrent.com",
		"update.bittorrent.com",
		"www.utorrent.com",
		"www.bittorrent.com",
		"www.qbittorrent.org",
		"www.transmissionbt.com",
		"deluge-torrent.org",
		"www.tixati.com",
		// Torrent search engines
		"btdig.com",
		"snowfl.com",
		"solidtorrents.to",
		"torrends.to",
		"torrentfunk.com",
		"monova.org",
		"torrentproject.se",
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	for _, domain := range torrentDomains {
		if _, exists := f.indicators[domain]; exists {
			continue
		}

		indicator := &ThreatIndicator{
			Indicator:   domain,
			Type:        "domain",
			ThreatType:  ThreatTypeTorrent,
			Source:      SourceTorrent,
			Confidence:  90, // Very high confidence for known torrent domains
			Description: "BitTorrent/P2P related domain",
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
	}

	// Add known DHT bootstrap node IPs
	dhtBootstrapIPs := []string{
		// BitTorrent DHT bootstrap nodes
		"67.215.246.10",  // router.bittorrent.com
		"82.221.103.244", // router.utorrent.com
		"87.98.162.88",   // dht.transmissionbt.com
		"174.129.43.152", // dht.aelitis.com (Vuze/Azureus)
		"212.129.33.59",  // dht.libtorrent.org
		// Additional public DHT nodes
		"91.121.59.153",   // Public DHT node
		"23.21.224.150",   // Public DHT node
		"188.165.227.128", // Public DHT node
	}

	for _, ip := range dhtBootstrapIPs {
		if _, exists := f.indicators[ip]; exists {
			continue
		}

		indicator := &ThreatIndicator{
			Indicator:   ip,
			Type:        "ip",
			ThreatType:  ThreatTypeTorrent,
			Source:      SourceTorrent,
			Confidence:  95, // Very high - these are known DHT bootstrap IPs
			Description: "BitTorrent DHT bootstrap node",
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
	}
}

// loadTorExitNodes loads Tor exit node IPs and related domains
func (f *FeedLoader) loadTorExitNodes(ctx context.Context) (int, error) {
	count := 0

	// Multiple sources for Tor exit nodes (in case one fails)
	torSources := []struct {
		url  string
		name string
	}{
		// TorProject official exit list (most reliable)
		{"https://check.torproject.org/torbulkexitlist", "TorProject"},
		// dan.me.uk (popular but sometimes unavailable)
		{"https://www.dan.me.uk/torlist/?exit", "dan.me.uk"},
		// SecOps Tor exit nodes
		{"https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst", "SecOps-GitHub"},
	}

	successCount := 0
	for _, src := range torSources {
		c, err := f.loadTorExitNodesFromURL(ctx, src.url)
		if err != nil {
			log.Printf("threatintel: failed to load tor exit nodes from %s: %v", src.name, err)
			continue
		}
		count += c
		successCount++
		log.Printf("threatintel: loaded %d Tor exit nodes from %s", c, src.name)
	}

	// Add known Tor-related domains (always works)
	f.addTorDomains()

	// If at least one source succeeded, return success
	if successCount > 0 || count > 0 {
		return count, nil
	}

	return 0, fmt.Errorf("all Tor exit node sources failed")
}

// loadTorExitNodesFromURL loads Tor exit node IPs from a URL
func (f *FeedLoader) loadTorExitNodesFromURL(ctx context.Context, torURL string) (int, error) {
	resp, err := f.client.Get(torURL)
	if err != nil {
		return 0, fmt.Errorf("fetch tor exit nodes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("tor exit nodes returned status %d", resp.StatusCode)
	}

	count := 0
	f.mu.Lock()
	defer f.mu.Unlock()

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Each line should be an IP address
		if !isIP(line) {
			continue
		}

		// Skip if already exists
		if _, exists := f.indicators[line]; exists {
			continue
		}

		indicator := &ThreatIndicator{
			Indicator:   line,
			Type:        "ip",
			ThreatType:  ThreatTypeTor,
			Source:      SourceTor,
			Confidence:  90, // High confidence - these are known Tor exit nodes
			Description: "Tor exit node",
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
		count++
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return count, fmt.Errorf("scan tor exit nodes: %w", err)
	}

	return count, nil
}

// addTorDomains adds known Tor-related domains
func (f *FeedLoader) addTorDomains() {
	// Known Tor-related domains for detection
	torDomains := []string{
		// Tor Project official
		"torproject.org",
		"www.torproject.org",
		"check.torproject.org",
		"dist.torproject.org",
		"bridges.torproject.org",
		"metrics.torproject.org",
		"blog.torproject.org",
		"support.torproject.org",
		"community.torproject.org",
		"tb-manual.torproject.org",
		"forum.torproject.org",
		"gitlab.torproject.org",
		"trac.torproject.org",
		// Tor directory authorities
		"authority.torproject.org",
		// Tor Browser update servers
		"aus1.torproject.org",
		"aus2.torproject.org",
		// Onion routing / Tor2Web gateways
		"onion.ws",
		"onion.pet",
		"onion.ly",
		"onion.cab",
		"onion.to",
		"onion.sh",
		"onion.link",
		"onion.plus",
		"tor2web.org",
		"tor2web.io",
		"tor2web.fi",
		"onion.city",
		"onion.direct",
		"darknet.to",
		// Tor relay search and monitoring
		"relay.love",
		"torstatus.blutmagie.de",
		"atlas.torproject.org",
		"exonerator.torproject.org",
		"collector.torproject.org",
		// Tor mirrors and alternative domains
		"tor.eff.org",
		"torservers.net",
		"torrelay.de",
		// VPN services often used with Tor
		"mullvad.net",
		"www.mullvad.net",
		// I2P (similar anonymous network)
		"geti2p.net",
		"www.i2p2.de",
		"i2pd.website",
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	for _, domain := range torDomains {
		if _, exists := f.indicators[domain]; exists {
			continue
		}

		indicator := &ThreatIndicator{
			Indicator:   domain,
			Type:        "domain",
			ThreatType:  ThreatTypeTor,
			Source:      SourceTor,
			Confidence:  95, // Very high confidence for known Tor domains
			Description: "Tor network related domain",
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
	}

	// Add known Tor Directory Authority IPs (hardcoded in Tor source code)
	// These are the 9 trusted authorities that sign the Tor consensus
	// Source: https://gitweb.torproject.org/tor.git/tree/src/app/config/auth_dirs.inc
	torDirectoryAuthorities := []struct {
		ip   string
		name string
	}{
		// moria1 (Mike Perry)
		{"128.31.0.39", "Tor Directory Authority (moria1)"},
		{"128.31.0.34", "Tor Directory Authority (moria1 alt)"},
		// tor26 (Peter Palfrader)
		{"86.59.21.38", "Tor Directory Authority (tor26)"},
		// dizum (Alex de Joode)
		{"45.66.33.45", "Tor Directory Authority (dizum)"},
		// Serge (Serge)
		{"66.111.2.131", "Tor Directory Authority (Serge)"},
		// gabelmoo (Sebastian Hahn)
		{"131.188.40.189", "Tor Directory Authority (gabelmoo)"},
		// dannenberg (Andreas Lehner)
		{"193.23.244.244", "Tor Directory Authority (dannenberg)"},
		// maatuska (Linus Nordberg)
		{"171.25.193.9", "Tor Directory Authority (maatuska)"},
		{"171.25.193.20", "Tor Directory Authority (maatuska alt)"},
		// Faravahar (Sina Rabbani)
		{"154.35.175.225", "Tor Directory Authority (Faravahar)"},
		// longclaw (Riseup)
		{"199.58.81.140", "Tor Directory Authority (longclaw)"},
		// bastet (Tor Project)
		{"204.13.164.118", "Tor Directory Authority (bastet)"},
	}

	for _, auth := range torDirectoryAuthorities {
		if _, exists := f.indicators[auth.ip]; exists {
			continue
		}

		indicator := &ThreatIndicator{
			Indicator:   auth.ip,
			Type:        "ip",
			ThreatType:  ThreatTypeTor,
			Source:      SourceTor,
			Confidence:  99, // Extremely high - these are hardcoded in Tor
			Description: auth.name,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
	}

	// Add known Tor bridge authority and other infrastructure IPs
	torInfrastructureIPs := []struct {
		ip   string
		name string
	}{
		// Bridge authority
		{"38.229.33.83", "Tor Bridge Authority (Bifroest)"},
		// Snowflake broker
		{"193.187.88.42", "Tor Snowflake broker"},
		// meek-azure fronting
		{"13.107.21.200", "Tor meek-azure (Microsoft CDN)"},
	}

	for _, infra := range torInfrastructureIPs {
		if _, exists := f.indicators[infra.ip]; exists {
			continue
		}

		indicator := &ThreatIndicator{
			Indicator:   infra.ip,
			Type:        "ip",
			ThreatType:  ThreatTypeTor,
			Source:      SourceTor,
			Confidence:  95,
			Description: infra.name,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
	}
}

// ============================================================================
// BlockList Project Loaders
// https://github.com/blocklistproject/Lists
// Comprehensive domain blocklists for various threat categories
// ============================================================================

// blockListProjectBaseURL is the base URL for BlockList Project raw files
const blockListProjectBaseURL = "https://blocklistproject.github.io/Lists/"

// loadBlockListProjectHosts loads domains from BlockList Project hosts format
// Format: 0.0.0.0 domain.com
func (f *FeedLoader) loadBlockListProjectHosts(ctx context.Context, listName string, source ThreatSource, threatType ThreatType, confidence int) (int, error) {
	url := blockListProjectBaseURL + listName + ".txt"

	resp, err := f.client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("fetch blocklist %s: %w", listName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("blocklist %s returned status %d", listName, resp.StatusCode)
	}

	count := 0
	f.mu.Lock()
	defer f.mu.Unlock()

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 2*1024*1024) // 2MB buffer for large lists

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse hosts format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		// First part should be IP (0.0.0.0 or 127.0.0.1)
		if parts[0] != "0.0.0.0" && parts[0] != "127.0.0.1" {
			continue
		}

		domain := strings.ToLower(parts[1])

		// Skip localhost entries
		if domain == "localhost" || domain == "localhost.localdomain" ||
			domain == "local" || strings.HasPrefix(domain, "0.0.0.0") ||
			strings.HasPrefix(domain, "127.") || domain == "broadcasthost" {
			continue
		}

		// Skip if already exists
		if _, exists := f.indicators[domain]; exists {
			continue
		}

		indicator := &ThreatIndicator{
			Indicator:   domain,
			Type:        "domain",
			ThreatType:  threatType,
			Source:      source,
			Confidence:  confidence,
			Description: fmt.Sprintf("BlockList Project: %s", listName),
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
		count++
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return count, fmt.Errorf("scan blocklist %s: %w", listName, err)
	}

	return count, nil
}

// loadBlockListAbuse loads abuse blocklist (spam, harassment, etc.)
func (f *FeedLoader) loadBlockListAbuse(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "abuse", SourceBlockListAbuse, ThreatTypeAbuse, 80)
}

// loadBlockListAds loads advertising/adware blocklist
func (f *FeedLoader) loadBlockListAds(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "ads", SourceBlockListAds, ThreatTypeAds, 85)
}

// loadBlockListCrypto loads cryptocurrency/cryptojacking blocklist
func (f *FeedLoader) loadBlockListCrypto(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "crypto", SourceBlockListCrypto, ThreatTypeCrypto, 85)
}

// loadBlockListDrugs loads illegal drugs blocklist
func (f *FeedLoader) loadBlockListDrugs(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "drugs", SourceBlockListDrugs, ThreatTypeDrugs, 80)
}

// loadBlockListFraud loads fraud/scam blocklist
func (f *FeedLoader) loadBlockListFraud(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "fraud", SourceBlockListFraud, ThreatTypeFraud, 85)
}

// loadBlockListMalware loads malware blocklist
func (f *FeedLoader) loadBlockListMalware(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "malware", SourceBlockListMalware, ThreatTypeMalware, 90)
}

// loadBlockListPhishing loads phishing blocklist
func (f *FeedLoader) loadBlockListPhishing(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "phishing", SourceBlockListPhishing, ThreatTypePhishing, 90)
}

// loadBlockListPiracy loads piracy/illegal downloads blocklist
func (f *FeedLoader) loadBlockListPiracy(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "piracy", SourceBlockListPiracy, ThreatTypePiracy, 85)
}

// loadBlockListPorn loads adult content blocklist
func (f *FeedLoader) loadBlockListPorn(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "porn", SourceBlockListPorn, ThreatTypePorn, 85)
}

// loadBlockListScam loads scam blocklist
func (f *FeedLoader) loadBlockListScam(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "scam", SourceBlockListScam, ThreatTypeScam, 85)
}

// loadBlockListRedirect loads redirect/URL shortener abuse blocklist
func (f *FeedLoader) loadBlockListRedirect(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "redirect", SourceBlockListRedirect, ThreatTypeRedirect, 75)
}

// loadBlockListTikTok loads TikTok/ByteDance blocklist
func (f *FeedLoader) loadBlockListTikTok(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "tiktok", SourceBlockListTikTok, ThreatTypeTikTok, 90)
}

// loadBlockListTorrent loads torrent/P2P blocklist
func (f *FeedLoader) loadBlockListTorrent(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "torrent", SourceBlockListTorrent, ThreatTypeTorrent, 85)
}

// loadBlockListTracking loads tracking/analytics blocklist
func (f *FeedLoader) loadBlockListTracking(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "tracking", SourceBlockListTracking, ThreatTypeTracking, 80)
}

// loadBlockListRansomware loads ransomware blocklist
func (f *FeedLoader) loadBlockListRansomware(ctx context.Context) (int, error) {
	return f.loadBlockListProjectHosts(ctx, "ransomware", SourceBlockListRansomware, ThreatTypeRansomware, 95)
}
