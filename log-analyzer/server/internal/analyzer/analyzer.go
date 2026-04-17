package analyzer

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"sync"
	"time"

	"github.com/xray-log-analyzer/server/internal/blacklist"
	"github.com/xray-log-analyzer/server/internal/correlation"
	"github.com/xray-log-analyzer/server/internal/ipinfo"
	"github.com/xray-log-analyzer/server/internal/models"
	"github.com/xray-log-analyzer/server/internal/storage"
	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// Analyzer processes log batches and generates alerts
type Analyzer struct {
	blacklist         *blacklist.Blacklist
	storage           *storage.Storage
	threatIntel       *threatintel.Service
	ipInfo            *ipinfo.Service
	correlation       *correlation.Service
	alertCh           chan *models.Alert
	suspiciousCount   int
	suspiciousWindow  time.Duration
	recentAlerts      map[string]time.Time // Prevent duplicate alerts
	recentAlertsMu    sync.RWMutex
	alertDedupeWindow time.Duration

	// bridgeInboundRegex matches inbound tags whose source IP is an
	// infrastructure hop (another Xray bridge node), not a real client.
	// nil disables the filter — see SetBridgeInboundPattern.
	bridgeInboundRegex *regexp.Regexp

	// bridgeNodeIDs lists node_ids that ingest real-client traffic into the
	// bridge tunnel. Used to look up the real client IP when correlating an
	// exit-node bridged flow. Empty disables correlation.
	bridgeNodeIDs []string

	// bridgeCorrelationWindow is the ± window we accept between the exit-node
	// entry timestamp and the bridge user_ip_history record.
	bridgeCorrelationWindow time.Duration
}

// New creates a new Analyzer
func New(bl *blacklist.Blacklist, st *storage.Storage, alertCh chan *models.Alert, suspiciousCount int, suspiciousWindow time.Duration) *Analyzer {
	return &Analyzer{
		blacklist:         bl,
		storage:           st,
		alertCh:           alertCh,
		suspiciousCount:   suspiciousCount,
		suspiciousWindow:  suspiciousWindow,
		recentAlerts:      make(map[string]time.Time),
		alertDedupeWindow: 15 * time.Minute,
	}
}

// SetThreatIntel sets the threat intelligence service
func (a *Analyzer) SetThreatIntel(ti *threatintel.Service) {
	a.threatIntel = ti
}

// SetIPInfo sets the IP info service for geo lookups
func (a *Analyzer) SetIPInfo(ip *ipinfo.Service) {
	a.ipInfo = ip
}

// SetCorrelation sets the correlation service for user analysis
func (a *Analyzer) SetCorrelation(c *correlation.Service) {
	a.correlation = c
}

// SetBridgeInboundPattern compiles a regex matching inbound tags that
// belong to bridged tunnels (e.g. "BRIDGE_DE_IN", "BRIDGE_DE_IN_2"). For
// matched entries the source IP is suppressed everywhere it would be
// recorded as a "client IP" — because it's actually the other Xray node.
// Empty pattern disables the filter; an invalid regex is returned as-is.
func (a *Analyzer) SetBridgeInboundPattern(pattern string) error {
	if pattern == "" {
		a.bridgeInboundRegex = nil
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	a.bridgeInboundRegex = re
	return nil
}

// isInfrastructureSource reports whether the entry's inbound tag matches
// the configured bridge pattern (i.e. source IP belongs to our own infra).
func (a *Analyzer) isInfrastructureSource(inbound string) bool {
	return a.bridgeInboundRegex != nil && a.bridgeInboundRegex.MatchString(inbound)
}

// SetBridgeCorrelation enables Layer-3 correlation. For each entry whose
// inbound matches the bridge pattern, the analyzer looks up the real client
// IP in user_ip_history on any of `nodeIDs`, as long as it was seen within
// `maxAge` of the entry timestamp, and records a row in bridged_flows.
// Empty nodeIDs disables correlation entirely.
func (a *Analyzer) SetBridgeCorrelation(nodeIDs []string, maxAge time.Duration) {
	a.bridgeNodeIDs = append(a.bridgeNodeIDs[:0], nodeIDs...)
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	a.bridgeCorrelationWindow = maxAge
}

// ProcessBatch processes a batch of log entries
func (a *Analyzer) ProcessBatch(ctx context.Context, batch *models.LogBatch) (processed int, blacklistHits int, err error) {
	if batch.NodeID == "" {
		return 0, 0, fmt.Errorf("empty node_id in batch")
	}
	// Track per-user stats in this batch
	userRequests := make(map[string]int)
	userBlacklist := make(map[string]int)
	userLastDomain := make(map[string]string)
	userLastIP := make(map[string]string)                // user -> last source IP
	userDestinations := make(map[string]map[string]bool) // user -> set of destinations
	threatHits := 0

	for _, entry := range batch.Entries {
		processed++

		// Count user requests
		userRequests[entry.UserEmail]++

		// Track last IP for user. For bridged inbounds the source is the
		// upstream bridge node (e.g. RU-White), not the real client — skip
		// so user_ip_history / ip_user_map / user_locations stay clean.
		// The destination is still correct and is recorded below.
		if entry.SourceIP != "" && !a.isInfrastructureSource(entry.Inbound) {
			userLastIP[entry.UserEmail] = entry.SourceIP
		}

		// Track unique destinations per user
		if userDestinations[entry.UserEmail] == nil {
			userDestinations[entry.UserEmail] = make(map[string]bool)
		}
		userDestinations[entry.UserEmail][entry.Destination] = true

		// Check blacklist
		matchedRule := a.blacklist.Check(entry.Destination)
		if matchedRule != "" {
			blacklistHits++
			userBlacklist[entry.UserEmail]++
			userLastDomain[entry.UserEmail] = entry.Destination

			// Record the match
			match := &models.BlacklistMatch{
				NodeID:      batch.NodeID,
				UserEmail:   entry.UserEmail,
				SourceIP:    entry.SourceIP,
				Destination: entry.Destination,
				MatchedRule: matchedRule,
				Timestamp:   entry.Timestamp,
			}
			if err := a.storage.RecordBlacklistMatch(ctx, match); err != nil {
				// log.Printf("analyzer: failed to record blacklist match: %v", err)
				_ = err // suppress verbose logging
			}

			// Check if we need to generate an alert
			a.checkAndAlert(ctx, batch.NodeID, entry, matchedRule)
		}

		// Check threat intelligence (only if not already blocked by blacklist)
		if matchedRule == "" && a.threatIntel != nil {
			if threatMatch := a.threatIntel.CheckAndRecord(ctx, entry.UserEmail, batch.NodeID, entry.SourceIP, entry.Destination); threatMatch != nil {
				threatHits++
				// Generate alert for high confidence threats
				if threatMatch.Confidence >= 80 {
					a.generateThreatAlert(ctx, batch.NodeID, entry, threatMatch)
				}
			}
		}
	}

	// Update aggregated stats
	if err := a.storage.UpdateNodeStats(ctx, batch.NodeID, processed, blacklistHits, batch.Count); err != nil {
		// log.Printf("analyzer: failed to update node stats: %v", err)
		_ = err
	}

	for user, requests := range userRequests {
		hits := userBlacklist[user]
		domain := userLastDomain[user]
		lastIP := userLastIP[user]
		uniqueDests := len(userDestinations[user])
		if err := a.storage.UpdateUserStats(ctx, batch.NodeID, user, requests, hits, domain, uniqueDests, lastIP); err != nil {
			// log.Printf("analyzer: failed to update user stats: %v", err)
			_ = err
		}

		// Record user IP history with geo enrichment.
		// GeoIP lookup is async to avoid blocking batch processing on network I/O.
		if lastIP != "" {
			// Record immediately without geo — RecordUserIP upserts, so geo can be added later.
			if err := a.storage.RecordUserIP(ctx, user, lastIP, batch.NodeID, "", "", ""); err != nil {
				_ = err
			}
			if a.ipInfo != nil {
				u, ip, nodeID := user, lastIP, batch.NodeID
				go func() {
					geoCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					ipData, err := a.ipInfo.Lookup(geoCtx, ip)
					if err != nil || ipData == nil {
						return
					}
					_ = a.storage.RecordUserIP(geoCtx, u, ip, nodeID, ipData.CountryCode, ipData.Country, ipData.City)
				}()
			}
		}

		// Process correlation data (IP + HWID mapping)
		if a.correlation != nil && lastIP != "" {
			// HWID will come from Remnawave sync, here we just record IP correlation
			// UserAgent is not in LogEntry, so we pass empty string
			a.correlation.ProcessConnection(ctx, user, lastIP, "", "", batch.NodeID)
		}

		// Record user destinations for detailed tracking
		for dest := range userDestinations[user] {
			if err := a.storage.RecordUserDestination(ctx, user, batch.NodeID, dest); err != nil {
				// log.Printf("analyzer: failed to record user destination: %v", err)
				_ = err
			}
		}
	}

	// Update unique users count for this node
	if err := a.storage.UpdateNodeUniqueUsers(ctx, batch.NodeID); err != nil {
		// log.Printf("analyzer: failed to update unique users: %v", err)
		_ = err
	}

	// Update hourly stats for charts
	uniqueUsersInBatch := len(userRequests)
	if err := a.storage.UpdateHourlyStats(ctx, batch.NodeID, processed, blacklistHits, uniqueUsersInBatch); err != nil {
		// log.Printf("analyzer: failed to update hourly stats: %v", err)
		_ = err
	}

	// Layer-3 correlation: for each bridged entry, resolve real client IP
	// via user_ip_history on any of bridgeNodeIDs and persist the link in
	// bridged_flows. One lookup per user, then a row per destination.
	a.correlateBridgedFlows(ctx, batch)

	return processed, blacklistHits, nil
}

// correlateBridgedFlows resolves and persists bridged_flows for entries
// whose inbound matches the bridge pattern. No-op when correlation is
// disabled (empty bridgeNodeIDs) or no bridged entries exist.
func (a *Analyzer) correlateBridgedFlows(ctx context.Context, batch *models.LogBatch) {
	if len(a.bridgeNodeIDs) == 0 || a.bridgeInboundRegex == nil {
		return
	}

	// Group bridged entries by user, keeping only entries that look bridged.
	bridgedByUser := make(map[string][]models.LogEntry)
	for _, entry := range batch.Entries {
		if !a.isInfrastructureSource(entry.Inbound) {
			continue
		}
		if entry.UserEmail == "" || entry.Destination == "" {
			continue
		}
		bridgedByUser[entry.UserEmail] = append(bridgedByUser[entry.UserEmail], entry)
	}
	if len(bridgedByUser) == 0 {
		return
	}

	for user, entries := range bridgedByUser {
		// Use the latest entry's timestamp as the lookup anchor — the
		// freshest user_ip_history record near it is the safest match.
		latest := entries[0].Timestamp
		for _, e := range entries[1:] {
			if e.Timestamp.After(latest) {
				latest = e.Timestamp
			}
		}
		ip, bridgeNode, ok := a.storage.LookupRealClientIP(ctx, user, latest, a.bridgeCorrelationWindow, a.bridgeNodeIDs)
		if !ok {
			// No matching bridge ingress yet — skip silently. Future
			// batches with the same user will likely succeed once the
			// bridge agent flushes its batch.
			continue
		}
		for _, e := range entries {
			flow := &storage.BridgedFlow{
				UserEmail:    user,
				RealClientIP: ip,
				BridgeNodeID: bridgeNode,
				ExitNodeID:   batch.NodeID,
				Destination:  e.Destination,
				Timestamp:    e.Timestamp,
			}
			if err := a.storage.RecordBridgedFlow(ctx, flow); err != nil {
				_ = err // suppress verbose logging
			}
		}
	}
}

// checkAndAlert checks if an alert should be generated
func (a *Analyzer) checkAndAlert(ctx context.Context, nodeID string, entry models.LogEntry, matchedRule string) {
	// Check recent alerts to avoid spam
	alertKey := fmt.Sprintf("%s:%s:%s", nodeID, entry.UserEmail, matchedRule)

	a.recentAlertsMu.RLock()
	lastAlert, exists := a.recentAlerts[alertKey]
	a.recentAlertsMu.RUnlock()

	if exists && time.Since(lastAlert) < a.alertDedupeWindow {
		return // Skip duplicate alert
	}

	// Check how many blacklist hits this user has in the time window
	since := time.Now().Add(-a.suspiciousWindow)
	count, err := a.storage.GetUserBlacklistCount(ctx, nodeID, entry.UserEmail, since)
	if err != nil {
		log.Printf("analyzer: failed to get user blacklist count: %v", err)
		return
	}

	if count >= a.suspiciousCount {
		alert := &models.Alert{
			Type:        "blacklist_threshold",
			NodeID:      nodeID,
			UserEmail:   entry.UserEmail,
			SourceIP:    entry.SourceIP,
			Destination: entry.Destination,
			Count:       count,
			Message: fmt.Sprintf("🚨 Пользователь %s на ноде %s превысил лимит запросов к запрещённым сайтам!\n"+
				"Количество: %d за %v\n"+
				"Последний сайт: %s\n"+
				"Правило: %s\n"+
				"IP: %s",
				entry.UserEmail, nodeID, count, a.suspiciousWindow, entry.Destination, matchedRule, entry.SourceIP),
		}

		// Save alert
		if err := a.storage.CreateAlert(ctx, alert); err != nil {
			log.Printf("analyzer: failed to create alert: %v", err)
			return
		}

		// Send to alert channel
		select {
		case a.alertCh <- alert:
		default:
			log.Println("analyzer: alert channel full")
		}

		// Record this alert
		a.recentAlertsMu.Lock()
		a.recentAlerts[alertKey] = time.Now()
		a.recentAlertsMu.Unlock()
	}
}

// CleanupAlertCache removes old entries from the alert cache
func (a *Analyzer) CleanupAlertCache() {
	a.recentAlertsMu.Lock()
	defer a.recentAlertsMu.Unlock()

	now := time.Now()
	for key, t := range a.recentAlerts {
		if now.Sub(t) > a.alertDedupeWindow {
			delete(a.recentAlerts, key)
		}
	}
}

// generateThreatAlert generates an alert for a threat intelligence match
func (a *Analyzer) generateThreatAlert(ctx context.Context, nodeID string, entry models.LogEntry, match *threatintel.ThreatMatch) {
	// Check recent alerts to avoid spam
	alertKey := fmt.Sprintf("threat:%s:%s:%s", nodeID, entry.UserEmail, entry.Destination)

	a.recentAlertsMu.RLock()
	lastAlert, exists := a.recentAlerts[alertKey]
	a.recentAlertsMu.RUnlock()

	if exists && time.Since(lastAlert) < a.alertDedupeWindow {
		return // Skip duplicate alert
	}

	threatTypeLabels := map[threatintel.ThreatType]string{
		threatintel.ThreatTypeMalware:    "🦠 Malware",
		threatintel.ThreatTypeC2:         "🎯 C2 Server",
		threatintel.ThreatTypePhishing:   "🎣 Phishing",
		threatintel.ThreatTypeBotnet:     "🤖 Botnet",
		threatintel.ThreatTypeRansomware: "💀 Ransomware",
	}

	threatLabel := threatTypeLabels[match.ThreatType]
	if threatLabel == "" {
		threatLabel = string(match.ThreatType)
	}

	alert := &models.Alert{
		Type:        "threat_intel",
		NodeID:      nodeID,
		UserEmail:   entry.UserEmail,
		SourceIP:    entry.SourceIP,
		Destination: entry.Destination,
		Count:       match.Confidence,
		Message: fmt.Sprintf("🔴 THREAT INTEL: %s\n"+
			"Пользователь: %s\n"+
			"Нода: %s\n"+
			"Назначение: %s\n"+
			"Источник данных: %s\n"+
			"Уверенность: %d%%\n"+
			"Описание: %s\n"+
			"IP: %s",
			threatLabel, entry.UserEmail, nodeID, entry.Destination,
			match.Source, match.Confidence, match.Description, entry.SourceIP),
	}

	// Save alert
	if err := a.storage.CreateAlert(ctx, alert); err != nil {
		log.Printf("analyzer: failed to create threat alert: %v", err)
		return
	}

	// Send to alert channel
	select {
	case a.alertCh <- alert:
	default:
		log.Println("analyzer: alert channel full")
	}

	// Record this alert
	a.recentAlertsMu.Lock()
	a.recentAlerts[alertKey] = time.Now()
	a.recentAlertsMu.Unlock()

	log.Printf("analyzer: generated threat alert for user %s (type: %s, confidence: %d%%)",
		entry.UserEmail, match.ThreatType, match.Confidence)
}
