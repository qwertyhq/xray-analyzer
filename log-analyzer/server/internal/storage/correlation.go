package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// RecordIPUserMapping records that a user connected from an IP
func (s *Storage) RecordIPUserMapping(ctx context.Context, ip, userEmail, nodeID string) error {
	userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("resolve user_email: %w", err)
	}

	// node_id is nullable smallint FK — resolve if non-empty.
	var nodeIntID interface{}
	if nodeID != "" {
		if nid, err := s.LookupNodeID(ctx, nodeID, "exit"); err == nil {
			nodeIntID = int16(nid)
		}
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO ip_user_map (ip_address, user_email, node_id, first_seen, last_seen, request_count)
		VALUES ($1::inet, $2, $3, NOW(), NOW(), 1)
		ON CONFLICT (ip_address, user_email) DO UPDATE SET
			last_seen = NOW(),
			request_count = ip_user_map.request_count + 1,
			node_id = COALESCE(EXCLUDED.node_id, ip_user_map.node_id)
	`, ip, userUUID, nodeIntID)
	return err
}

// RecordHWIDUserMapping records that a user connected with an HWID
func (s *Storage) RecordHWIDUserMapping(ctx context.Context, hwid, userEmail, platform string) error {
	userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("resolve user_email: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO hwid_user_map (hwid, user_email, platform, first_seen, last_seen, request_count)
		VALUES ($1, $2, $3, NOW(), NOW(), 1)
		ON CONFLICT (hwid, user_email) DO UPDATE SET
			last_seen = NOW(),
			request_count = hwid_user_map.request_count + 1,
			platform = COALESCE(EXCLUDED.platform, hwid_user_map.platform)
	`, hwid, userUUID, platform)
	return err
}

// RecordUserFingerprint records a unique combination of user+IP+HWID
func (s *Storage) RecordUserFingerprint(ctx context.Context, userEmail, ip, hwid, userAgent, nodeID string) error {
	userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("resolve user_email: %w", err)
	}

	var nodeIntID interface{}
	if nodeID != "" {
		if nid, err := s.LookupNodeID(ctx, nodeID, "exit"); err == nil {
			nodeIntID = int16(nid)
		}
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_fingerprints (user_email, ip_address, hwid, user_agent, node_id, first_seen, last_seen, session_count)
		VALUES ($1, $2::inet, $3, $4, $5, NOW(), NOW(), 1)
		ON CONFLICT (user_email, ip_address, hwid) DO UPDATE SET
			last_seen = NOW(),
			session_count = user_fingerprints.session_count + 1,
			user_agent = COALESCE(EXCLUDED.user_agent, user_fingerprints.user_agent)
	`, userUUID, ip, hwid, userAgent, nodeIntID)
	return err
}

// GetUsersForIP returns all users that have used a specific IP (cached)
func (s *Storage) GetUsersForIP(ctx context.Context, ip string) ([]IPUserMapping, error) {
	cacheKey := fmt.Sprintf("users_for_ip_%s", ip)
	if cached, found := s.cache.Get(cacheKey); found {
		return cached.([]IPUserMapping), nil
	}

	rows, err := s.pool.Query(ctx, `
		SELECT host(m.ip_address), m.user_email::text,
		       COALESCE(n.node_id, ''), m.first_seen, m.last_seen, m.request_count
		FROM ip_user_map m
		LEFT JOIN nodes n ON n.id = m.node_id
		WHERE m.ip_address = $1::inet
		ORDER BY m.last_seen DESC
	`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []IPUserMapping
	for rows.Next() {
		var m IPUserMapping
		if err := rows.Scan(&m.IPAddress, &m.UserEmail, &m.NodeID, &m.FirstSeen, &m.LastSeen, &m.RequestCount); err != nil {
			continue
		}
		result = append(result, m)
	}

	s.cache.Set(cacheKey, result, CacheTTLMedium)
	return result, nil
}

// GetUsersForHWID returns all users that have used a specific HWID (cached)
func (s *Storage) GetUsersForHWID(ctx context.Context, hwid string) ([]HWIDUserMapping, error) {
	cacheKey := fmt.Sprintf("users_for_hwid_%s", hwid)
	if cached, found := s.cache.Get(cacheKey); found {
		return cached.([]HWIDUserMapping), nil
	}

	rows, err := s.pool.Query(ctx, `
		SELECT hwid, user_email::text, COALESCE(platform, ''), first_seen, last_seen, request_count
		FROM hwid_user_map WHERE hwid = $1
		ORDER BY last_seen DESC
	`, hwid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []HWIDUserMapping
	for rows.Next() {
		var m HWIDUserMapping
		if err := rows.Scan(&m.HWID, &m.UserEmail, &m.Platform, &m.FirstSeen, &m.LastSeen, &m.RequestCount); err != nil {
			continue
		}
		result = append(result, m)
	}

	s.cache.Set(cacheKey, result, CacheTTLMedium)
	return result, nil
}

// GetSharedIPUsers returns users that share IPs with the given user
func (s *Storage) GetSharedIPUsers(ctx context.Context, userEmail string) ([]SharedUserInfo, error) {
	userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return nil, fmt.Errorf("resolve user_email: %w", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT m2.user_email::text, host(m1.ip_address), m2.last_seen, m2.request_count
		FROM ip_user_map m1
		JOIN ip_user_map m2 ON m1.ip_address = m2.ip_address
		WHERE m1.user_email = $1 AND m2.user_email != $2
		ORDER BY m2.last_seen DESC
	`, userUUID, userUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []SharedUserInfo
	for rows.Next() {
		var u SharedUserInfo
		if err := rows.Scan(&u.UserEmail, &u.SharedValue, &u.LastSeen, &u.RequestCount); err != nil {
			continue
		}
		u.Reason = "shared_ip"
		result = append(result, u)
	}
	return result, nil
}

// GetSharedHWIDUsers returns users that share HWIDs with the given user
func (s *Storage) GetSharedHWIDUsers(ctx context.Context, userEmail string) ([]SharedUserInfo, error) {
	userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return nil, fmt.Errorf("resolve user_email: %w", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT m2.user_email::text, m1.hwid, m2.last_seen, m2.request_count
		FROM hwid_user_map m1
		JOIN hwid_user_map m2 ON m1.hwid = m2.hwid
		WHERE m1.user_email = $1 AND m2.user_email != $2
		ORDER BY m2.last_seen DESC
	`, userUUID, userUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []SharedUserInfo
	for rows.Next() {
		var u SharedUserInfo
		if err := rows.Scan(&u.UserEmail, &u.SharedValue, &u.LastSeen, &u.RequestCount); err != nil {
			continue
		}
		u.Reason = "shared_hwid"
		result = append(result, u)
	}
	return result, nil
}

// GetUserFingerprints returns all fingerprints for a user
func (s *Storage) GetUserFingerprints(ctx context.Context, userEmail string) ([]UserFingerprint, error) {
	userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return nil, fmt.Errorf("resolve user_email: %w", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT f.id, f.user_email::text, host(f.ip_address),
		       COALESCE(f.hwid, ''), COALESCE(f.user_agent, ''),
		       COALESCE(n.node_id, ''), f.first_seen, f.last_seen, f.session_count
		FROM user_fingerprints f
		LEFT JOIN nodes n ON n.id = f.node_id
		WHERE f.user_email = $1
		ORDER BY f.last_seen DESC
	`, userUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []UserFingerprint
	for rows.Next() {
		var f UserFingerprint
		if err := rows.Scan(&f.ID, &f.UserEmail, &f.IPAddress, &f.HWID, &f.UserAgent, &f.NodeID, &f.FirstSeen, &f.LastSeen, &f.SessionCount); err != nil {
			continue
		}
		result = append(result, f)
	}
	return result, nil
}

// UpsertUserAIProfile updates or creates an AI profile for a user
func (s *Storage) UpsertUserAIProfile(ctx context.Context, profile *UserAIProfile) error {
	threatCategories, _ := json.Marshal(profile.ThreatCategories)
	clusterIDs, _ := json.Marshal(profile.ClusterIDs)
	typicalHours, _ := json.Marshal(profile.TypicalHours)
	riskFactors, _ := json.Marshal(profile.RiskFactors)

	userUUID, err := s.ResolveUserEmailToUUID(ctx, profile.UserEmail)
	if err != nil {
		return fmt.Errorf("resolve user_email: %w", err)
	}
	// remna_uuid is type uuid — pass NULL for empty string to avoid parse error.
	var remnaUUIDVal interface{}
	if profile.RemnaUUID != "" {
		remnaUUIDVal = profile.RemnaUUID
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_ai_profile (
			user_email, unique_ips, unique_hwids, unique_fingerprints, unique_countries, unique_nodes,
			total_requests, total_sessions, avg_session_duration_sec,
			total_threat_matches, threat_categories,
			shared_ip_users, shared_hwid_users, cluster_ids,
			first_seen, last_seen, active_days, typical_hours,
			risk_score, risk_factors,
			remna_uuid, remna_status, remna_traffic_used, remna_traffic_limit, remna_expire_at, remna_hwid_devices, remna_hwid_limit,
			updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, NOW())
		ON CONFLICT (user_email) DO UPDATE SET
			unique_ips = EXCLUDED.unique_ips,
			unique_hwids = EXCLUDED.unique_hwids,
			unique_fingerprints = EXCLUDED.unique_fingerprints,
			unique_countries = EXCLUDED.unique_countries,
			unique_nodes = EXCLUDED.unique_nodes,
			total_requests = EXCLUDED.total_requests,
			total_sessions = EXCLUDED.total_sessions,
			avg_session_duration_sec = EXCLUDED.avg_session_duration_sec,
			total_threat_matches = EXCLUDED.total_threat_matches,
			threat_categories = EXCLUDED.threat_categories,
			shared_ip_users = EXCLUDED.shared_ip_users,
			shared_hwid_users = EXCLUDED.shared_hwid_users,
			cluster_ids = EXCLUDED.cluster_ids,
			first_seen = COALESCE(user_ai_profile.first_seen, EXCLUDED.first_seen),
			last_seen = EXCLUDED.last_seen,
			active_days = EXCLUDED.active_days,
			typical_hours = EXCLUDED.typical_hours,
			risk_score = EXCLUDED.risk_score,
			risk_factors = EXCLUDED.risk_factors,
			remna_uuid = EXCLUDED.remna_uuid,
			remna_status = EXCLUDED.remna_status,
			remna_traffic_used = EXCLUDED.remna_traffic_used,
			remna_traffic_limit = EXCLUDED.remna_traffic_limit,
			remna_expire_at = EXCLUDED.remna_expire_at,
			remna_hwid_devices = EXCLUDED.remna_hwid_devices,
			remna_hwid_limit = EXCLUDED.remna_hwid_limit,
			updated_at = NOW()
	`, userUUID, profile.UniqueIPs, profile.UniqueHWIDs, profile.UniqueFingerprints, profile.UniqueCountries, profile.UniqueNodes,
		profile.TotalRequests, profile.TotalSessions, profile.AvgSessionDurationSec,
		profile.TotalThreatMatches, string(threatCategories),
		profile.SharedIPUsers, profile.SharedHWIDUsers, string(clusterIDs),
		profile.FirstSeen, profile.LastSeen, profile.ActiveDays, string(typicalHours),
		profile.RiskScore, string(riskFactors),
		remnaUUIDVal, profile.RemnaStatus, profile.RemnaTrafficUsed, profile.RemnaTrafficLimit, profile.RemnaExpireAt, profile.RemnaHWIDDevices, profile.RemnaHWIDLimit)
	return err
}

// GetUserAIProfile retrieves the AI profile for a user
func (s *Storage) GetUserAIProfile(ctx context.Context, userEmail string) (*UserAIProfile, error) {
	userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return nil, fmt.Errorf("resolve user_email: %w", err)
	}
	row := s.pool.QueryRow(ctx, `
		SELECT user_email::text, unique_ips, unique_hwids, unique_fingerprints, unique_countries, unique_nodes,
			total_requests, total_sessions, avg_session_duration_sec,
			total_threat_matches, COALESCE(threat_categories, ''),
			shared_ip_users, shared_hwid_users, COALESCE(cluster_ids, ''),
			first_seen, last_seen, active_days, COALESCE(typical_hours, ''),
			risk_score, COALESCE(risk_factors, ''),
			COALESCE(remna_uuid::text, ''), COALESCE(remna_status, ''),
			remna_traffic_used, remna_traffic_limit, remna_expire_at,
			remna_hwid_devices, remna_hwid_limit, updated_at
		FROM user_ai_profile WHERE user_email = $1
	`, userUUID)

	var p UserAIProfile
	var threatCatStr, clusterIDsStr, typicalHoursStr, riskFactorsStr string
	var firstSeen, lastSeen, updatedAt *time.Time
	var remnaExpireAt *time.Time

	err = row.Scan(&p.UserEmail, &p.UniqueIPs, &p.UniqueHWIDs, &p.UniqueFingerprints, &p.UniqueCountries, &p.UniqueNodes,
		&p.TotalRequests, &p.TotalSessions, &p.AvgSessionDurationSec,
		&p.TotalThreatMatches, &threatCatStr,
		&p.SharedIPUsers, &p.SharedHWIDUsers, &clusterIDsStr,
		&firstSeen, &lastSeen, &p.ActiveDays, &typicalHoursStr,
		&p.RiskScore, &riskFactorsStr,
		&p.RemnaUUID, &p.RemnaStatus,
		&p.RemnaTrafficUsed, &p.RemnaTrafficLimit, &remnaExpireAt,
		&p.RemnaHWIDDevices, &p.RemnaHWIDLimit, &updatedAt)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}

	if threatCatStr != "" {
		json.Unmarshal([]byte(threatCatStr), &p.ThreatCategories)
	}
	if clusterIDsStr != "" {
		json.Unmarshal([]byte(clusterIDsStr), &p.ClusterIDs)
	}
	if typicalHoursStr != "" {
		json.Unmarshal([]byte(typicalHoursStr), &p.TypicalHours)
	}
	if riskFactorsStr != "" {
		json.Unmarshal([]byte(riskFactorsStr), &p.RiskFactors)
	}
	if firstSeen != nil {
		p.FirstSeen = *firstSeen
	}
	if lastSeen != nil {
		p.LastSeen = *lastSeen
	}
	if updatedAt != nil {
		p.UpdatedAt = *updatedAt
	}
	if remnaExpireAt != nil {
		p.RemnaExpireAt = remnaExpireAt
	}

	return &p, nil
}

// GetAllUserAIProfiles returns all AI profiles with optional filtering (cached)
func (s *Storage) GetAllUserAIProfiles(ctx context.Context, limit int, minRiskScore int) ([]UserAIProfile, error) {
	cacheKey := fmt.Sprintf("ai_profiles_%d_%d", limit, minRiskScore)

	if cached, found := s.cache.Get(cacheKey); found {
		return cached.([]UserAIProfile), nil
	}

	rows, err := s.pool.Query(ctx, `
		SELECT p.user_email::text, COALESCE(r.username, ''), p.unique_ips, p.unique_hwids, p.unique_fingerprints, p.unique_countries, p.unique_nodes,
			p.total_requests, p.total_sessions, p.avg_session_duration_sec,
			p.total_threat_matches, COALESCE(p.threat_categories, ''),
			p.shared_ip_users, p.shared_hwid_users, COALESCE(p.cluster_ids, ''),
			p.first_seen, p.last_seen, p.active_days, COALESCE(p.typical_hours, ''),
			p.risk_score, COALESCE(p.risk_factors, ''),
			COALESCE(p.remna_uuid::text, ''), COALESCE(p.remna_status, ''),
			p.remna_traffic_used, p.remna_traffic_limit, p.remna_expire_at,
			p.remna_hwid_devices, p.remna_hwid_limit, p.updated_at
		FROM user_ai_profile p
		LEFT JOIN remna_users r ON p.remna_uuid::text = r.uuid::text
		WHERE p.risk_score >= $1
		ORDER BY p.risk_score DESC, p.total_threat_matches DESC
		LIMIT $2
	`, minRiskScore, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []UserAIProfile
	for rows.Next() {
		var p UserAIProfile
		var remnaUsername string
		var threatCatStr, clusterIDsStr, typicalHoursStr, riskFactorsStr string
		var firstSeen, lastSeen, updatedAt *time.Time
		var remnaExpireAt *time.Time

		err := rows.Scan(&p.UserEmail, &remnaUsername, &p.UniqueIPs, &p.UniqueHWIDs, &p.UniqueFingerprints, &p.UniqueCountries, &p.UniqueNodes,
			&p.TotalRequests, &p.TotalSessions, &p.AvgSessionDurationSec,
			&p.TotalThreatMatches, &threatCatStr,
			&p.SharedIPUsers, &p.SharedHWIDUsers, &clusterIDsStr,
			&firstSeen, &lastSeen, &p.ActiveDays, &typicalHoursStr,
			&p.RiskScore, &riskFactorsStr,
			&p.RemnaUUID, &p.RemnaStatus,
			&p.RemnaTrafficUsed, &p.RemnaTrafficLimit, &remnaExpireAt,
			&p.RemnaHWIDDevices, &p.RemnaHWIDLimit, &updatedAt)
		if err != nil {
			continue
		}

		p.RemnaUsername = remnaUsername
		if threatCatStr != "" {
			json.Unmarshal([]byte(threatCatStr), &p.ThreatCategories)
		}
		if clusterIDsStr != "" {
			json.Unmarshal([]byte(clusterIDsStr), &p.ClusterIDs)
		}
		if typicalHoursStr != "" {
			json.Unmarshal([]byte(typicalHoursStr), &p.TypicalHours)
		}
		if riskFactorsStr != "" {
			json.Unmarshal([]byte(riskFactorsStr), &p.RiskFactors)
		}
		if firstSeen != nil {
			p.FirstSeen = *firstSeen
		}
		if lastSeen != nil {
			p.LastSeen = *lastSeen
		}
		if updatedAt != nil {
			p.UpdatedAt = *updatedAt
		}
		if remnaExpireAt != nil {
			p.RemnaExpireAt = remnaExpireAt
		}

		result = append(result, p)
	}

	s.cache.Set(cacheKey, result, CacheTTLMedium)
	return result, nil
}

// GetCorrelationStats returns overview statistics about correlations (cached)
func (s *Storage) GetCorrelationStats(ctx context.Context) (*CorrelationStats, error) {
	cacheKey := "correlation_stats"

	if cached, found := s.cache.Get(cacheKey); found {
		return cached.(*CorrelationStats), nil
	}

	var stats CorrelationStats

	// Optimized query using CTE for shared IPs (avoids repeated subqueries)
	s.db.QueryRowContext(ctx, `
		WITH shared_ips AS (
			SELECT ip_address, COUNT(DISTINCT user_email) as user_count
			FROM ip_user_map
			GROUP BY ip_address
			HAVING COUNT(DISTINCT user_email) > 1
		)
		SELECT
			(SELECT COUNT(*) FROM shared_ips) as shared_ip_count,
			(SELECT COUNT(DISTINCT m.user_email) FROM ip_user_map m INNER JOIN shared_ips s ON m.ip_address = s.ip_address)
	`).Scan(&stats.SharedIPs, &stats.UsersWithSharedIP)

	// Optimized query for shared HWIDs
	s.db.QueryRowContext(ctx, `
		WITH shared_hwids AS (
			SELECT hwid, COUNT(DISTINCT user_email) as user_count
			FROM hwid_user_map
			GROUP BY hwid
			HAVING COUNT(DISTINCT user_email) > 1
		)
		SELECT
			(SELECT COUNT(*) FROM shared_hwids) as shared_hwid_count,
			(SELECT COUNT(DISTINCT m.user_email) FROM hwid_user_map m INNER JOIN shared_hwids s ON m.hwid = s.hwid)
	`).Scan(&stats.SharedHWIDs, &stats.UsersWithSharedHWID)

	// Get total fingerprints
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_fingerprints`).Scan(&stats.TotalFingerprints)

	// Get cluster stats
	s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT cluster_id) FROM user_clusters`).Scan(&stats.TotalClusters)
	s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT user_email) FROM user_clusters`).Scan(&stats.UsersInClusters)

	s.cache.Set(cacheKey, &stats, CacheTTLMedium)
	return &stats, nil
}

// GetTopSharedIPs returns IPs shared by most users (cached)
func (s *Storage) GetTopSharedIPs(ctx context.Context, limit int) ([]SharedIPInfo, error) {
	cacheKey := fmt.Sprintf("shared_ips_%d", limit)
	if cached, found := s.cache.Get(cacheKey); found {
		return cached.([]SharedIPInfo), nil
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT ip_address, COUNT(DISTINCT user_email) as user_count, MAX(last_seen) as last_seen, SUM(request_count) as total_requests
		FROM ip_user_map
		GROUP BY ip_address
		HAVING COUNT(DISTINCT user_email) > 1
		ORDER BY user_count DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []SharedIPInfo
	for rows.Next() {
		var info SharedIPInfo
		var lastSeen time.Time
		if err := rows.Scan(&info.IPAddress, &info.UserCount, &lastSeen, &info.TotalRequests); err != nil {
			continue
		}
		info.LastSeen = lastSeen
		result = append(result, info)
	}

	s.cache.Set(cacheKey, result, CacheTTLMedium)
	return result, nil
}

// GetTopSharedHWIDs returns HWIDs shared by most users (cached)
func (s *Storage) GetTopSharedHWIDs(ctx context.Context, limit int) ([]SharedHWIDInfo, error) {
	cacheKey := fmt.Sprintf("shared_hwids_%d", limit)
	if cached, found := s.cache.Get(cacheKey); found {
		return cached.([]SharedHWIDInfo), nil
	}

	// platform is picked up via MIN to satisfy Postgres GROUP BY strictness;
	// semantically a single HWID belongs to one platform in practice.
	rows, err := s.db.QueryContext(ctx, `
		SELECT hwid, MIN(platform), COUNT(DISTINCT user_email) as user_count, MAX(last_seen) as last_seen, SUM(request_count) as total_requests
		FROM hwid_user_map
		GROUP BY hwid
		HAVING COUNT(DISTINCT user_email) > 1
		ORDER BY user_count DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []SharedHWIDInfo
	for rows.Next() {
		var info SharedHWIDInfo
		var platform sql.NullString
		var lastSeen time.Time
		if err := rows.Scan(&info.HWID, &platform, &info.UserCount, &lastSeen, &info.TotalRequests); err != nil {
			continue
		}
		info.LastSeen = lastSeen
		if platform.Valid {
			info.Platform = platform.String
		}
		result = append(result, info)
	}

	s.cache.Set(cacheKey, result, CacheTTLMedium)
	return result, nil
}

// Types for correlation data

type IPUserMapping struct {
	IPAddress    string    `json:"ip_address"`
	UserEmail    string    `json:"user_email"`
	NodeID       string    `json:"node_id,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	RequestCount int       `json:"request_count"`
}

type HWIDUserMapping struct {
	HWID         string    `json:"hwid"`
	UserEmail    string    `json:"user_email"`
	Platform     string    `json:"platform,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	RequestCount int       `json:"request_count"`
}

type SharedUserInfo struct {
	UserEmail    string    `json:"user_email"`
	SharedValue  string    `json:"shared_value"`
	Reason       string    `json:"reason"` // "shared_ip" or "shared_hwid"
	LastSeen     time.Time `json:"last_seen"`
	RequestCount int       `json:"request_count"`
}

type UserFingerprint struct {
	ID           int       `json:"id"`
	UserEmail    string    `json:"user_email"`
	IPAddress    string    `json:"ip_address"`
	HWID         string    `json:"hwid,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	NodeID       string    `json:"node_id,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	SessionCount int       `json:"session_count"`
}

type UserAIProfile struct {
	UserEmail             string         `json:"user_email"`
	RemnaUsername         string         `json:"remna_username,omitempty"`
	UniqueIPs             int            `json:"unique_ips"`
	UniqueHWIDs           int            `json:"unique_hwids"`
	UniqueFingerprints    int            `json:"unique_fingerprints"`
	UniqueCountries       int            `json:"unique_countries"`
	UniqueNodes           int            `json:"unique_nodes"`
	TotalRequests         int            `json:"total_requests"`
	TotalSessions         int            `json:"total_sessions"`
	AvgSessionDurationSec float64        `json:"avg_session_duration_sec"`
	TotalThreatMatches    int            `json:"total_threat_matches"`
	ThreatCategories      map[string]int `json:"threat_categories"`
	SharedIPUsers         int            `json:"shared_ip_users"`
	SharedHWIDUsers       int            `json:"shared_hwid_users"`
	ClusterIDs            []string       `json:"cluster_ids"`
	FirstSeen             time.Time      `json:"first_seen"`
	LastSeen              time.Time      `json:"last_seen"`
	ActiveDays            int            `json:"active_days"`
	TypicalHours          []int          `json:"typical_hours"`
	RiskScore             int            `json:"risk_score"`
	RiskFactors           []string       `json:"risk_factors"`
	RemnaUUID             string         `json:"remna_uuid,omitempty"`
	RemnaStatus           string         `json:"remna_status,omitempty"`
	RemnaTrafficUsed      int64          `json:"remna_traffic_used"`
	RemnaTrafficLimit     int64          `json:"remna_traffic_limit"`
	RemnaExpireAt         *time.Time     `json:"remna_expire_at,omitempty"`
	RemnaHWIDDevices      int            `json:"remna_hwid_devices"`
	RemnaHWIDLimit        int            `json:"remna_hwid_limit"`
	UpdatedAt             time.Time      `json:"updated_at"`
}

type CorrelationStats struct {
	SharedIPs           int `json:"shared_ips"`
	SharedHWIDs         int `json:"shared_hwids"`
	TotalFingerprints   int `json:"total_fingerprints"`
	UsersWithSharedIP   int `json:"users_with_shared_ip"`
	UsersWithSharedHWID int `json:"users_with_shared_hwid"`
	TotalClusters       int `json:"total_clusters"`
	UsersInClusters     int `json:"users_in_clusters"`
}

type SharedIPInfo struct {
	IPAddress     string    `json:"ip_address"`
	UserCount     int       `json:"user_count"`
	LastSeen      time.Time `json:"last_seen"`
	TotalRequests int       `json:"total_requests"`
}

type SharedHWIDInfo struct {
	HWID          string    `json:"hwid"`
	Platform      string    `json:"platform,omitempty"`
	UserCount     int       `json:"user_count"`
	LastSeen      time.Time `json:"last_seen"`
	TotalRequests int       `json:"total_requests"`
}
