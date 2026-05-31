package analyzer

import (
	"context"
	"fmt"
	"log"
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
	var threatMatches []*threatintel.ThreatMatch

	for _, entry := range batch.Entries {
		processed++

		// Count user requests
		userRequests[entry.UserEmail]++

		// Track last IP for user.
		if entry.SourceIP != "" {
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

		// Check threat intelligence (only if not already blocked by blacklist).
		// Matches are accumulated and persisted once per batch (see below) so the
		// per-match stat upserts collapse into aggregated writes.
		if matchedRule == "" && a.threatIntel != nil {
			if threatMatch := a.threatIntel.Check(entry.UserEmail, batch.NodeID, entry.SourceIP, entry.Destination); threatMatch != nil {
				threatHits++
				threatMatches = append(threatMatches, threatMatch)
				// Generate alert for high confidence threats
				if threatMatch.Confidence >= 80 {
					a.generateThreatAlert(ctx, batch.NodeID, entry, threatMatch)
				}
			}
		}
	}

	// Flush accumulated threat matches as one aggregated batch.
	if a.threatIntel != nil && len(threatMatches) > 0 {
		a.threatIntel.RecordMatches(ctx, threatMatches)
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

	return processed, blacklistHits, nil
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
			Category:    models.AlertCategoryBlacklist,
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
		Category:    models.AlertCategoryThreat,
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
