package threatintel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"
	"time"
)

// loadTorrentTrackers loads torrent trackers from multiple sources
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
	resp, err := f.doRequest(trackerURL)
	if err != nil {
		return 0, fmt.Errorf("fetch torrent trackers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
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
