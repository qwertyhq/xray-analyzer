package threatintel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"
)

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
	resp, err := f.doRequest(torURL)
	if err != nil {
		return 0, fmt.Errorf("fetch tor exit nodes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
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
		"onion.moe",
		"onion.ink",
		"onion.lu",
		"onion.casa",
		"onion.re",
		"onion.nu",
		"tor2web.org",
		"tor2web.io",
		"tor2web.fi",
		"tor2web.dev",
		"onion.city",
		"onion.direct",
		"darknet.to",
		"onion.run",
		"onion.glass",
		"onion.dog",
		"onion.foundation",
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
