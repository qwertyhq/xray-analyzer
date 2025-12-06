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
	"strings"
	"sync"
	"time"
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

// LoadAllFeeds loads all threat intelligence feeds
func (f *FeedLoader) LoadAllFeeds(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 10)

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
	}

	for _, feed := range feeds {
		wg.Add(1)
		go func(source ThreatSource, loader func(context.Context) (int, error)) {
			defer wg.Done()

			f.updateFeedStatus(source, "updating", "", 0)
			start := time.Now()

			count, err := loader(ctx)
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

		// CSV format: first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,malware_alias,malware_printable,last_seen_utc,confidence_level,reference,tags,anonymous,reporter
		parts := strings.Split(line, ",")
		if len(parts) < 8 {
			continue
		}

		// Remove quotes from fields
		iocValue := strings.Trim(parts[2], `"`)
		iocType := strings.Trim(parts[3], `"`)
		threatType := strings.Trim(parts[4], `"`)
		malware := strings.Trim(parts[7], `"`)

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
		for i := 1; i < len(parts)-1; i++ {
			parent := strings.Join(parts[i:], ".")
			if ind, ok := f.indicators[parent]; ok {
				return ind
			}
		}
	}

	return nil
}

// CheckDestination checks a destination (domain:port or IP:port) against threat intel
func (f *FeedLoader) CheckDestination(destination string) *ThreatIndicator {
	// Extract host from destination (remove port)
	host := destination
	if idx := strings.LastIndex(destination, ":"); idx > 0 {
		// Handle IPv6 addresses
		if strings.Count(destination, ":") > 1 && !strings.HasPrefix(destination, "[") {
			// This is IPv6 without brackets, keep as is
		} else {
			host = destination[:idx]
		}
	}

	// Remove brackets from IPv6
	host = strings.Trim(host, "[]")

	return f.CheckIndicator(host)
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
	// Load from multiple sources for comprehensive coverage
	trackerURLs := []string{
		"https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt",
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
			continue
		}

		host := u.Hostname()
		if host == "" {
			continue
		}

		// Skip IP addresses - only use domain names
		if isIP(host) {
			continue
		}

		// Skip if already exists
		if _, exists := f.indicators[host]; exists {
			continue
		}

		indicator := &ThreatIndicator{
			Indicator:   strings.ToLower(host),
			Type:        "domain",
			ThreatType:  ThreatTypeTorrent,
			Source:      SourceTorrent,
			Confidence:  85, // High confidence - these are known tracker domains
			Description: "BitTorrent tracker",
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
		// Popular torrent sites (for detection, not blocking)
		"thepiratebay.org",
		"1337x.to",
		"rarbg.to",
		"nyaa.si",
		"rutracker.org",
		"rutor.info",
		"rutor.is",
		"nnmclub.to",
		"kinozal.tv",
		"rustorka.com",
		"pornolab.net",
		"torrentgalaxy.to",
		"limetorrents.info",
		"torrentdownloads.me",
		"torrentz2.eu",
		"bt4g.org",
		"bitsearch.to",
		// Torrent client APIs
		"check.utorrent.com",
		"update.utorrent.com",
		"update.bittorrent.com",
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
}

// loadTorExitNodes loads Tor exit node IPs and related domains
func (f *FeedLoader) loadTorExitNodes(ctx context.Context) (int, error) {
	count := 0

	// Load Tor exit nodes from dan.me.uk (popular Tor exit list)
	c, err := f.loadTorExitNodesFromURL(ctx, "https://www.dan.me.uk/torlist/?exit")
	if err != nil {
		log.Printf("threatintel: failed to load tor exit nodes from dan.me.uk: %v", err)
	} else {
		count += c
	}

	// Add known Tor-related domains
	f.addTorDomains()

	return count, nil
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
		// Tor directory authorities
		"authority.torproject.org",
		// Tor Browser update servers
		"aus1.torproject.org",
		"aus2.torproject.org",
		// Onion routing related
		"onion.ws",
		"onion.pet",
		"onion.ly",
		"onion.cab",
		"onion.to",
		"tor2web.org",
		"tor2web.io",
		// Tor relay search
		"relay.love",
		"torstatus.blutmagie.de",
		"atlas.torproject.org",
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
}
