package threatintel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// ============================================================================
// BlockList Project Loaders
// https://github.com/blocklistproject/Lists
// Comprehensive domain blocklists for various threat categories
// ============================================================================

// blockListProjectBaseURL is the base URL for BlockList Project raw files
// Using raw.githubusercontent.com instead of github.io for better reliability
const blockListProjectBaseURL = "https://raw.githubusercontent.com/blocklistproject/Lists/master/"

// loadBlockListProjectHosts loads domains from BlockList Project hosts format
// Format: 0.0.0.0 domain.com
func (f *FeedLoader) loadBlockListProjectHosts(ctx context.Context, listName string, source ThreatSource, threatType ThreatType, confidence int) (int, error) {
	url := blockListProjectBaseURL + listName + ".txt"

	resp, err := f.doRequest(url)
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

	lineCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineCount++

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse hosts file format: 0.0.0.0 domain.com
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		// Get the domain - it's the second field after the IP
		domain := strings.ToLower(parts[1])

		// Skip localhost entries
		if domain == "localhost" || domain == "localhost.localdomain" ||
			domain == "local" || strings.HasPrefix(domain, "0.0.0.0") ||
			strings.HasPrefix(domain, "127.") || domain == "broadcasthost" {
			continue
		}

		if f.upsertIndicator(&ThreatIndicator{
			Indicator:   domain,
			Type:        "domain",
			ThreatType:  threatType,
			Source:      source,
			Confidence:  confidence,
			Description: fmt.Sprintf("BlockList Project: %s", listName),
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}) {
			count++
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return count, fmt.Errorf("scan blocklist %s: %w", listName, err)
	}

	if count == 0 {
		log.Printf("threatintel: blocklist %s parsed %d lines but found 0 valid domains", listName, lineCount)
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
