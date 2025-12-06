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
	errChan := make(chan error, 5)

	// Load feeds concurrently
	feeds := []struct {
		source ThreatSource
		loader func(context.Context) (int, error)
	}{
		{SourceURLhaus, f.loadURLhaus},
		{SourceFeodoTracker, f.loadFeodoTracker},
		{SourceThreatFox, f.loadThreatFox},
		{SourceStevenBlack, f.loadStevenBlack},
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

// loadURLhaus loads malware URLs from URLhaus
func (f *FeedLoader) loadURLhaus(ctx context.Context) (int, error) {
	// Get recent malware hosts
	resp, err := f.client.Get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/10000/")
	if err != nil {
		return 0, fmt.Errorf("fetch urlhaus: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("urlhaus returned status %d", resp.StatusCode)
	}

	var result URLhausResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode urlhaus: %w", err)
	}

	count := 0
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, entry := range result.URLs {
		if entry.URLStatus != "online" {
			continue
		}

		// Extract host from URL
		host := entry.Host
		if host == "" {
			if u, err := url.Parse(entry.URL); err == nil {
				host = u.Hostname()
			}
		}

		if host == "" {
			continue
		}

		// Determine threat type from tags
		threatType := ThreatTypeMalware
		for _, tag := range entry.Tags {
			switch strings.ToLower(tag) {
			case "phishing":
				threatType = ThreatTypePhishing
			case "ransomware":
				threatType = ThreatTypeRansomware
			case "c2", "c&c":
				threatType = ThreatTypeC2
			}
		}

		indicator := &ThreatIndicator{
			Indicator:   strings.ToLower(host),
			Type:        "domain",
			ThreatType:  threatType,
			Source:      SourceURLhaus,
			Confidence:  80,
			Description: entry.Threat,
			Tags:        entry.Tags,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
		count++
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

// loadThreatFox loads IOCs from ThreatFox
func (f *FeedLoader) loadThreatFox(ctx context.Context) (int, error) {
	// Query for recent IOCs (domains and IPs)
	payload := strings.NewReader(`{"query": "get_iocs", "days": 7}`)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://threatfox-api.abuse.ch/api/v1/", payload)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch threatfox: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("threatfox returned status %d", resp.StatusCode)
	}

	var result ThreatFoxResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode threatfox: %w", err)
	}

	if result.QueryStatus != "ok" {
		return 0, fmt.Errorf("threatfox query failed: %s", result.QueryStatus)
	}

	count := 0
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, ioc := range result.Data {
		// Only process domain and IP IOCs
		iocType := ""
		switch ioc.IOCType {
		case "domain":
			iocType = "domain"
		case "ip:port":
			iocType = "ip"
			// Extract IP from ip:port format
			if idx := strings.Index(ioc.IOC, ":"); idx > 0 {
				ioc.IOC = ioc.IOC[:idx]
			}
		default:
			continue
		}

		// Map threat type
		threatType := ThreatTypeMalware
		switch strings.ToLower(ioc.ThreatType) {
		case "botnet_cc":
			threatType = ThreatTypeBotnet
		case "cc":
			threatType = ThreatTypeC2
		case "payload_delivery":
			threatType = ThreatTypeMalware
		}

		confidence := ioc.Confidence
		if confidence == 0 {
			confidence = 70
		}

		indicator := &ThreatIndicator{
			Indicator:   strings.ToLower(ioc.IOC),
			Type:        iocType,
			ThreatType:  threatType,
			Source:      SourceThreatFox,
			Confidence:  confidence,
			Description: ioc.MalwarePrintable,
			Tags:        ioc.Tags,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}

		f.indicators[indicator.Indicator] = indicator
		count++
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
