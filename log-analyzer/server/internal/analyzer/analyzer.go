package analyzer

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/xray-log-analyzer/server/internal/blacklist"
	"github.com/xray-log-analyzer/server/internal/models"
	"github.com/xray-log-analyzer/server/internal/storage"
)

// Analyzer processes log batches and generates alerts
type Analyzer struct {
	blacklist         *blacklist.Blacklist
	storage           *storage.Storage
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

// ProcessBatch processes a batch of log entries
func (a *Analyzer) ProcessBatch(ctx context.Context, batch *models.LogBatch) (processed int, blacklistHits int, err error) {
	// Track per-user stats in this batch
	userRequests := make(map[string]int)
	userBlacklist := make(map[string]int)
	userLastDomain := make(map[string]string)
	userLastIP := make(map[string]string)                // user -> last source IP
	userDestinations := make(map[string]map[string]bool) // user -> set of destinations

	for _, entry := range batch.Entries {
		processed++

		// Count user requests
		userRequests[entry.UserEmail]++

		// Track last IP for user
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
				log.Printf("analyzer: failed to record blacklist match: %v", err)
			}

			// Check if we need to generate an alert
			a.checkAndAlert(ctx, batch.NodeID, entry, matchedRule)
		}
	}

	// Update aggregated stats
	if err := a.storage.UpdateNodeStats(ctx, batch.NodeID, processed, blacklistHits, batch.Count); err != nil {
		log.Printf("analyzer: failed to update node stats: %v", err)
	}

	for user, requests := range userRequests {
		hits := userBlacklist[user]
		domain := userLastDomain[user]
		lastIP := userLastIP[user]
		uniqueDests := len(userDestinations[user])
		if err := a.storage.UpdateUserStats(ctx, batch.NodeID, user, requests, hits, domain, uniqueDests, lastIP); err != nil {
			log.Printf("analyzer: failed to update user stats: %v", err)
		}
	}

	// Update unique users count for this node
	if err := a.storage.UpdateNodeUniqueUsers(ctx, batch.NodeID); err != nil {
		log.Printf("analyzer: failed to update unique users: %v", err)
	}

	// Update hourly stats for charts
	uniqueUsersInBatch := len(userRequests)
	if err := a.storage.UpdateHourlyStats(ctx, batch.NodeID, processed, blacklistHits, uniqueUsersInBatch); err != nil {
		log.Printf("analyzer: failed to update hourly stats: %v", err)
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

		log.Printf("analyzer: generated alert for user %s (count: %d)", entry.UserEmail, count)
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
