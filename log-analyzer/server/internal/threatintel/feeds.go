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
	userAgent     = "Mozilla/5.0 (compatible; ThreatIntelFeedLoader/1.0)"
)

// FeedLoader handles loading threat intelligence feeds
type FeedLoader struct {
	client     *http.Client
	mu         sync.RWMutex
	indicators map[string]*ThreatIndicator // key: indicator value (domain/ip)
	whitelist  map[string]bool             // domains/IPs to exclude (false positives)
	feedStatus map[ThreatSource]*FeedStatus
}

// defaultWhitelist contains domains that popular blocklists often flag as "ads/tracking"
// but are legitimate infrastructure (CDNs, analytics required for sites to function, etc.)
// These would create false-positive noise in threat matches.
var defaultWhitelist = []string{
	// Major CDNs
	"cloudfront.net",
	"akamaihd.net",
	"akamai.net",
	"akamaiedge.net",
	"akamaitechnologies.com",
	"fastly.net",
	"fastlylb.net",
	"cloudflare.com",
	"cdn.cloudflare.net",
	// Big tech infrastructure (shared with apps)
	"googleapis.com",
	"gstatic.com",
	"google.com",
	"googleusercontent.com",
	"ggpht.com",
	"gvt1.com",
	"gvt2.com",
	"youtube.com",
	"ytimg.com",
	"apple.com",
	"icloud.com",
	"mzstatic.com",
	"microsoft.com",
	"msftconnecttest.com",
	"windows.com",
	"windowsupdate.com",
	"office.com",
	"office365.com",
	"live.com",
	"outlook.com",
	"skype.com",
	"amazon.com",
	"amazonaws.com",
	"aws.amazon.com",
	"facebook.com",
	"fbcdn.net",
	"instagram.com",
	"whatsapp.com",
	"whatsapp.net",
	"telegram.org",
	"telegram.me",
	"t.me",
	"cdn-telegram.org",
	// Developer tools often in ad-blocklists
	"github.com",
	"githubusercontent.com",
	"githubassets.com",
	"gitlab.com",
	"stackoverflow.com",
	"npmjs.com",
	"jsdelivr.net",
	"unpkg.com",
}

// NewFeedLoader creates a new feed loader
func NewFeedLoader() *FeedLoader {
	wl := make(map[string]bool, len(defaultWhitelist))
	for _, d := range defaultWhitelist {
		wl[strings.ToLower(d)] = true
	}
	return &FeedLoader{
		client: &http.Client{
			Timeout: 120 * time.Second, // Increased timeout for large feeds
			Transport: &http.Transport{
				MaxIdleConns:       10,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: false,
				DisableKeepAlives:  false,
			},
		},
		indicators: make(map[string]*ThreatIndicator),
		whitelist:  wl,
		feedStatus: make(map[ThreatSource]*FeedStatus),
	}
}

// upsertIndicator adds or merges a threat indicator into the map.
// When the same indicator comes from multiple sources, we keep the highest
// ThreatType priority source as primary but record all contributing sources
// and boost confidence (+5 per additional source, capped at 99).
// Caller must hold f.mu.
func (f *FeedLoader) upsertIndicator(ind *ThreatIndicator) bool {
	if f.isWhitelisted(ind.Indicator) {
		return false
	}
	existing, ok := f.indicators[ind.Indicator]
	if !ok {
		if ind.Sources == nil {
			ind.Sources = []ThreatSource{ind.Source}
		}
		f.indicators[ind.Indicator] = ind
		return true
	}
	// Same source reporting again — just refresh LastSeen
	for _, s := range existing.Sources {
		if s == ind.Source {
			existing.LastSeen = ind.LastSeen
			return false
		}
	}
	// Different source — record it and boost confidence
	existing.Sources = append(existing.Sources, ind.Source)
	existing.LastSeen = ind.LastSeen
	// Upgrade primary source to higher-confidence entry
	if ind.Confidence > existing.Confidence {
		existing.Source = ind.Source
		existing.ThreatType = ind.ThreatType
		existing.Description = ind.Description
		existing.Confidence = ind.Confidence
	}
	// Multi-source boost: +5 per additional source, up to 99
	boost := existing.Confidence + 5
	if boost > 99 {
		boost = 99
	}
	existing.Confidence = boost
	return false
}

// isWhitelisted checks if a domain (or its parent) is whitelisted.
// Caller must hold f.mu.
func (f *FeedLoader) isWhitelisted(indicator string) bool {
	if f.whitelist[indicator] {
		return true
	}
	// Check parent domains
	if strings.Contains(indicator, ".") && !isIP(indicator) {
		parts := strings.Split(indicator, ".")
		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[i:], ".")
			if !strings.Contains(parent, ".") {
				continue
			}
			if f.whitelist[parent] {
				return true
			}
		}
	}
	return false
}

// doRequest performs an HTTP GET request with proper headers
func (f *FeedLoader) doRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	return f.client.Do(req)
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

// LoadAllFeeds loads all threat intelligence feeds with controlled concurrency
func (f *FeedLoader) LoadAllFeeds(ctx context.Context) error {
	// Define all feeds
	feeds := []struct {
		source ThreatSource
		loader func(context.Context) (int, error)
	}{
		// Specialized malware/C2/botnet
		{SourceURLhaus, f.loadURLhaus},
		{SourceFeodoTracker, f.loadFeodoTracker},
		{SourceThreatFox, f.loadThreatFox},
		// Reputation-based (high signal)
		{SourceAlienVaultOTX, f.loadAlienVaultOTX},
		{SourcePhishTank, f.loadPhishTank},
		{SourceSpamhaus, f.loadSpamhausDROP},
		// Content category blocklists (StevenBlack extensions — categories without BlockList Project equivalents)
		{SourceGambling, f.loadGamblingBlocklist},
		{SourceSocial, f.loadSocialBlocklist},
		{SourceFakeNews, f.loadFakeNewsBlocklist},
		// P2P / Anonymization
		{SourceTorrent, f.loadTorrentTrackers},
		{SourceTor, f.loadTorExitNodes},
		{SourceTorRelays, f.loadTorRelays},
		// Cryptomining pools (hardcoded list)
		{SourceMiningPools, f.loadMiningPools},
		// BlockList Project — comprehensive category blocklists
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

	var errorCount int
	const batchSize = 5
	const batchDelay = 2 * time.Second

	// Process feeds in batches to avoid rate limiting
	for i := 0; i < len(feeds); i += batchSize {
		end := i + batchSize
		if end > len(feeds) {
			end = len(feeds)
		}
		batch := feeds[i:end]

		var wg sync.WaitGroup
		errChan := make(chan error, len(batch))

		for _, feed := range batch {
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

		// Count errors in this batch
		for range errChan {
			errorCount++
		}

		// Delay between batches (except after last batch)
		if end < len(feeds) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(batchDelay):
			}
		}
	}

	if errorCount > 0 {
		log.Printf("threatintel: %d feeds failed to load", errorCount)
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
	resp, err := f.doRequest("https://urlhaus.abuse.ch/downloads/text_online/")
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

		host := strings.ToLower(u.Hostname())
		if host == "" {
			continue
		}

		if f.upsertIndicator(&ThreatIndicator{
			Indicator:   host,
			Type:        "domain",
			ThreatType:  ThreatTypeMalware,
			Source:      SourceURLhaus,
			Confidence:  80,
			Description: "Malware distribution host",
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}) {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("scan urlhaus: %w", err)
	}

	return count, nil
}

// loadFeodoTracker loads C2 server IPs from Feodo Tracker
func (f *FeedLoader) loadFeodoTracker(ctx context.Context) (int, error) {
	resp, err := f.doRequest("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
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

		if f.upsertIndicator(&ThreatIndicator{
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
		}) {
			count++
		}
	}

	return count, nil
}

// loadThreatFox loads IOCs from ThreatFox plain text feed (no API key required)
func (f *FeedLoader) loadThreatFox(ctx context.Context) (int, error) {
	// Use plain text CSV feed instead of JSON API (no auth required)
	resp, err := f.doRequest("https://threatfox.abuse.ch/export/csv/recent/")
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

		iocValueLower := strings.ToLower(iocValue)
		if f.upsertIndicator(&ThreatIndicator{
			Indicator:   iocValueLower,
			Type:        indicatorType,
			ThreatType:  threat,
			Source:      SourceThreatFox,
			Confidence:  75,
			Description: malware,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}) {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("scan threatfox: %w", err)
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
	resp, err := f.doRequest(url)
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

		if f.upsertIndicator(&ThreatIndicator{
			Indicator:   domain,
			Type:        "domain",
			ThreatType:  threatType,
			Source:      source,
			Confidence:  confidence,
			Description: description,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}) {
			count++
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return count, fmt.Errorf("scan %s: %w", source, err)
	}

	return count, nil
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
