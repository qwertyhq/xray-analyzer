package threatintel

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// loadAlienVaultOTX loads the public AlienVault OTX IP reputation feed.
// No API key required for this generic list.
// Format: "IP #category,reliability,risk" lines.
func (f *FeedLoader) loadAlienVaultOTX(ctx context.Context) (int, error) {
	resp, err := f.doRequest("https://reputation.alienvault.com/reputation.generic")
	if err != nil {
		return 0, fmt.Errorf("fetch alienvault: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("alienvault returned status %d", resp.StatusCode)
	}

	count := 0
	now := time.Now()

	f.mu.Lock()
	defer f.mu.Unlock()

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: "IP #category,reliability,risk"
		// Split once on whitespace to separate IP
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		ip := parts[0]
		if !isIP(ip) {
			continue
		}

		// Parse the trailing "#category,reliability,risk" if present
		category := "Malicious Host"
		if idx := strings.Index(line, "#"); idx >= 0 {
			metadata := strings.TrimSpace(line[idx+1:])
			if metaParts := strings.Split(metadata, ","); len(metaParts) >= 1 {
				category = strings.TrimSpace(metaParts[0])
			}
		}

		// Map category to our threat type
		threat := ThreatTypeMalware
		switch strings.ToLower(category) {
		case "scanning host", "spamming":
			threat = ThreatTypeAbuse
		case "malicious host", "malware domain", "malware ip":
			threat = ThreatTypeMalware
		case "c&c", "c2":
			threat = ThreatTypeC2
		case "phishing":
			threat = ThreatTypePhishing
		}

		if f.upsertIndicator(&ThreatIndicator{
			Indicator:   ip,
			Type:        "ip",
			ThreatType:  threat,
			Source:      SourceAlienVaultOTX,
			Confidence:  80,
			Description: "AlienVault OTX: " + category,
			FirstSeen:   now,
			LastSeen:    now,
			CreatedAt:   now,
		}) {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("scan alienvault: %w", err)
	}
	return count, nil
}

// loadPhishTank loads the PhishTank community phishing URL database.
// The free feed is paginated CSV; no API key required for basic access.
func (f *FeedLoader) loadPhishTank(ctx context.Context) (int, error) {
	// Plain CSV, no key required
	resp, err := f.doRequest("http://data.phishtank.com/data/online-valid.csv")
	if err != nil {
		return 0, fmt.Errorf("fetch phishtank: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("phishtank returned status %d", resp.StatusCode)
	}

	count := 0
	now := time.Now()

	f.mu.Lock()
	defer f.mu.Unlock()

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 256*1024)
	scanner.Buffer(buf, 2*1024*1024)

	headerSkipped := false
	for scanner.Scan() {
		line := scanner.Text()
		if !headerSkipped {
			headerSkipped = true
			continue
		}
		// CSV columns: phish_id, url, phish_detail_url, submission_time, verified, verification_time, online, target
		fields := splitCSV(line)
		if len(fields) < 2 {
			continue
		}
		rawURL := strings.Trim(fields[1], `" `)
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			continue
		}

		target := ""
		if len(fields) >= 8 {
			target = strings.Trim(fields[7], `" `)
		}
		desc := "PhishTank verified phishing"
		if target != "" && target != "Other" {
			desc = "PhishTank phishing targeting " + target
		}

		if f.upsertIndicator(&ThreatIndicator{
			Indicator:   host,
			Type:        "domain",
			ThreatType:  ThreatTypePhishing,
			Source:      SourcePhishTank,
			Confidence:  85, // community-verified
			Description: desc,
			FirstSeen:   now,
			LastSeen:    now,
			CreatedAt:   now,
		}) {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("scan phishtank: %w", err)
	}
	return count, nil
}

// splitCSV does a minimal CSV split that respects double-quoted fields.
// Good enough for PhishTank's CSV format which doesn't have embedded quotes/commas
// in most fields.
func splitCSV(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false
	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case r == ',' && !inQuotes:
			fields = append(fields, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	fields = append(fields, current.String())
	return fields
}

// loadSpamhausDROP loads the Spamhaus DROP (Don't Route Or Peer) list —
// networks hijacked by spammers/criminals. Very high-signal, low volume.
func (f *FeedLoader) loadSpamhausDROP(ctx context.Context) (int, error) {
	resp, err := f.doRequest("https://www.spamhaus.org/drop/drop.txt")
	if err != nil {
		return 0, fmt.Errorf("fetch spamhaus: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("spamhaus returned status %d", resp.StatusCode)
	}

	count := 0
	now := time.Now()

	f.mu.Lock()
	defer f.mu.Unlock()

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		// Format: "CIDR ; SBL123456"
		parts := strings.Split(line, ";")
		cidr := strings.TrimSpace(parts[0])
		if cidr == "" || !strings.Contains(cidr, "/") {
			continue
		}

		// We index CIDRs as strings for now; CheckIndicator resolves IPs directly.
		// To resolve matching properly, we'd need a separate CIDR-aware lookup.
		// For MVP, expand only small ranges (/24 or smaller) to individual IPs.
		// Otherwise record the CIDR itself so at least stats/analysis can count it.
		if f.upsertIndicator(&ThreatIndicator{
			Indicator:   cidr,
			Type:        "cidr",
			ThreatType:  ThreatTypeAbuse,
			Source:      SourceSpamhaus,
			Confidence:  95, // Spamhaus DROP is extremely high signal
			Description: "Spamhaus DROP (hijacked/criminal network)",
			FirstSeen:   now,
			LastSeen:    now,
			CreatedAt:   now,
		}) {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("scan spamhaus: %w", err)
	}
	return count, nil
}
