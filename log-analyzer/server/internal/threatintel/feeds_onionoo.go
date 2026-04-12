package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Onionoo response — we only need or_addresses + flags for each relay.
type onionooResponse struct {
	Relays []struct {
		Nickname    string   `json:"nickname"`
		Fingerprint string   `json:"fingerprint"`
		ORAddresses []string `json:"or_addresses"` // "IP:port" (may include IPv6 in brackets)
		Flags       []string `json:"flags"`        // "Guard", "Exit", "Running", ...
		CountryName string   `json:"country_name"`
	} `json:"relays"`
}

// loadTorRelays fetches the full list of currently-running Tor relays from Onionoo.
// This catches users connecting to GUARD/MIDDLE relays too, not just exits — which is
// what most Tor clients actually hit (users rarely dial the exit directly).
func (f *FeedLoader) loadTorRelays(ctx context.Context) (int, error) {
	// Only running relays, only fields we need. Strip extraneous data for bandwidth.
	url := "https://onionoo.torproject.org/details?type=relay&running=true&fields=or_addresses,flags,nickname,fingerprint"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := f.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch onionoo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("onionoo returned status %d", resp.StatusCode)
	}

	var data onionooResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, fmt.Errorf("decode onionoo: %w", err)
	}

	count := 0
	now := time.Now()

	f.mu.Lock()
	defer f.mu.Unlock()

	for _, r := range data.Relays {
		isExit := false
		isGuard := false
		for _, flag := range r.Flags {
			switch flag {
			case "Exit":
				isExit = true
			case "Guard":
				isGuard = true
			}
		}

		// Role drives confidence. Guards are what typical users dial first,
		// so they're the most valuable detection signal.
		var confidence int
		var role string
		switch {
		case isExit && isGuard:
			confidence = 92
			role = "Tor Guard+Exit relay"
		case isExit:
			confidence = 90
			role = "Tor Exit relay"
		case isGuard:
			confidence = 88
			role = "Tor Guard relay"
		default:
			confidence = 80
			role = "Tor Middle relay"
		}

		for _, addr := range r.ORAddresses {
			// or_addresses are "IP:port" or "[IPv6]:port"
			ip := addr
			if strings.HasPrefix(addr, "[") {
				if end := strings.Index(addr, "]"); end > 0 {
					ip = addr[1:end]
				}
			} else if idx := strings.LastIndex(addr, ":"); idx > 0 {
				ip = addr[:idx]
			}
			if ip == "" {
				continue
			}

			desc := role
			if r.CountryName != "" {
				desc = fmt.Sprintf("%s (%s, %s)", role, r.Nickname, r.CountryName)
			}

			f.upsertIndicator(&ThreatIndicator{
				Indicator:   ip,
				Type:        "ip",
				ThreatType:  ThreatTypeTor,
				Source:      SourceTorRelays,
				Confidence:  confidence,
				Description: desc,
				FirstSeen:   now,
				LastSeen:    now,
				CreatedAt:   now,
			})
			count++
		}
	}

	return count, nil
}
