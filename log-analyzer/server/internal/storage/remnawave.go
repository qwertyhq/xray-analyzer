package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/xray-log-analyzer/server/internal/remnawave"
)

// Adapter methods to implement remnawave.StorageWriter interface

// UpsertRemnaUserFromSync adapts remnawave.RemnaUserData to storage
func (s *Storage) UpsertRemnaUser(ctx context.Context, user *remnawave.RemnaUserData) error {
	query := `
		INSERT INTO remna_users (
			uuid, id, short_uuid, username, email, status,
			traffic_limit_bytes, used_traffic_bytes, lifetime_traffic_bytes,
			traffic_limit_strategy, expire_at, online_at, first_connected_at,
			hwid_device_limit, hwid_device_count, telegram_id, description, tag,
			created_at, updated_at, synced_at,
			real_name, phone, telegram_user, payment_info, plan, us_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(uuid) DO UPDATE SET
			id = excluded.id,
			short_uuid = excluded.short_uuid,
			username = excluded.username,
			email = excluded.email,
			status = excluded.status,
			traffic_limit_bytes = excluded.traffic_limit_bytes,
			used_traffic_bytes = excluded.used_traffic_bytes,
			lifetime_traffic_bytes = excluded.lifetime_traffic_bytes,
			traffic_limit_strategy = excluded.traffic_limit_strategy,
			expire_at = excluded.expire_at,
			online_at = excluded.online_at,
			first_connected_at = excluded.first_connected_at,
			hwid_device_limit = excluded.hwid_device_limit,
			hwid_device_count = excluded.hwid_device_count,
			telegram_id = excluded.telegram_id,
			description = excluded.description,
			tag = excluded.tag,
			updated_at = excluded.updated_at,
			synced_at = excluded.synced_at,
			real_name = excluded.real_name,
			phone = excluded.phone,
			telegram_user = excluded.telegram_user,
			payment_info = excluded.payment_info,
			plan = excluded.plan,
			us_id = excluded.us_id
	`
	_, err := s.db.ExecContext(ctx, query,
		user.UUID, user.ID, user.ShortUUID, user.Username, user.Email, user.Status,
		user.TrafficLimitBytes, user.UsedTrafficBytes, user.LifetimeTrafficBytes,
		user.TrafficLimitStrategy, user.ExpireAt, user.OnlineAt, user.FirstConnectedAt,
		user.HwidDeviceLimit, user.HwidDeviceCount, user.TelegramID, user.Description, user.Tag,
		user.CreatedAt, user.UpdatedAt, user.SyncedAt,
		user.RealName, user.Phone, user.TelegramUser, user.PaymentInfo, user.Plan, user.USID,
	)
	return err
}

// UpsertRemnaHwidDevice adapts remnawave.RemnaHwidData to storage
func (s *Storage) UpsertRemnaHwidDevice(ctx context.Context, device *remnawave.RemnaHwidData) error {
	query := `
		INSERT INTO remna_hwid_devices (
			hwid, user_uuid, username, platform, os_version, device_model, app_version,
			first_seen_at, last_active_at, synced_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(hwid, user_uuid) DO UPDATE SET
			username = excluded.username,
			platform = excluded.platform,
			os_version = excluded.os_version,
			device_model = excluded.device_model,
			app_version = excluded.app_version,
			last_active_at = excluded.last_active_at,
			synced_at = excluded.synced_at
	`
	_, err := s.db.ExecContext(ctx, query,
		device.Hwid, device.UserUUID, device.Username, device.Platform, device.OSVersion,
		device.DeviceModel, device.AppVersion, device.FirstSeenAt, device.LastActiveAt, device.SyncedAt,
	)
	return err
}

// UpdateRemnaUserHwidCounts updates hwid_device_count for all users based on actual HWID data
func (s *Storage) UpdateRemnaUserHwidCounts(ctx context.Context) error {
	query := `
		UPDATE remna_users SET hwid_device_count = (
			SELECT COUNT(*) FROM remna_hwid_devices WHERE remna_hwid_devices.user_uuid = remna_users.uuid
		)
	`
	_, err := s.db.ExecContext(ctx, query)
	return err
}

// UpsertRemnaNode adapts remnawave.RemnaNodeData to storage
func (s *Storage) UpsertRemnaNode(ctx context.Context, node *remnawave.RemnaNodeData) error {
	query := `
		INSERT INTO remna_nodes (
			uuid, name, address, port, is_connected, is_disabled, is_traffic_track,
			traffic_total, traffic_used, users_online, country_code, synced_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(uuid) DO UPDATE SET
			name = excluded.name,
			address = excluded.address,
			port = excluded.port,
			is_connected = excluded.is_connected,
			is_disabled = excluded.is_disabled,
			is_traffic_track = excluded.is_traffic_track,
			traffic_total = excluded.traffic_total,
			traffic_used = excluded.traffic_used,
			users_online = excluded.users_online,
			country_code = excluded.country_code,
			synced_at = excluded.synced_at
	`
	_, err := s.db.ExecContext(ctx, query,
		node.UUID, node.Name, node.Address, node.Port, node.IsConnected, node.IsDisabled,
		node.IsTrafficTrack, node.TrafficTotal, node.TrafficUsed, node.UsersOnline,
		node.CountryCode, node.SyncedAt,
	)
	return err
}

// Local types for query results

// RemnaUser represents a Remnawave user stored in database
type RemnaUser struct {
	UUID                 string     `json:"uuid"`
	ShortUUID            string     `json:"short_uuid"`
	Username             string     `json:"username"`
	Email                *string    `json:"email"`
	Status               string     `json:"status"`
	TrafficLimitBytes    int64      `json:"traffic_limit_bytes"`
	UsedTrafficBytes     int64      `json:"used_traffic_bytes"`
	LifetimeTrafficBytes int64      `json:"lifetime_traffic_bytes"`
	TrafficLimitStrategy string     `json:"traffic_limit_strategy"`
	ExpireAt             *time.Time `json:"expire_at"`
	OnlineAt             *time.Time `json:"online_at"`
	FirstConnectedAt     *time.Time `json:"first_connected_at"`
	HwidDeviceLimit      *int       `json:"hwid_device_limit"`
	HwidDeviceCount      int        `json:"hwid_device_count"`
	TelegramID           *int64     `json:"telegram_id"`
	Description          *string    `json:"description"`
	Tag                  *string    `json:"tag"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	SyncedAt             time.Time  `json:"synced_at"`
	RealName             *string    `json:"real_name"`
	Phone                *string    `json:"phone"`
	TelegramUser         *string    `json:"telegram_user"`
	PaymentInfo          *string    `json:"payment_info"`
	Plan                 *string    `json:"plan"`
}

// RemnaHwidDevice represents a HWID device from Remnawave
type RemnaHwidDevice struct {
	ID           int64      `json:"id"`
	Hwid         string     `json:"hwid"`
	UserUUID     string     `json:"user_uuid"`
	Username     string     `json:"username"`
	Platform     *string    `json:"platform"`
	OSVersion    *string    `json:"os_version"`
	DeviceModel  *string    `json:"device_model"`
	AppVersion   *string    `json:"app_version"`
	FirstSeenAt  time.Time  `json:"first_seen_at"`
	LastActiveAt *time.Time `json:"last_active_at"`
	SyncedAt     time.Time  `json:"synced_at"`
}

// RemnaNode represents a Remnawave node
type RemnaNode struct {
	UUID           string    `json:"uuid"`
	Name           string    `json:"name"`
	Address        string    `json:"address"`
	Port           int       `json:"port"`
	IsConnected    bool      `json:"is_connected"`
	IsDisabled     bool      `json:"is_disabled"`
	IsTrafficTrack bool      `json:"is_traffic_track"`
	TrafficTotal   int64     `json:"traffic_total"`
	TrafficUsed    int64     `json:"traffic_used"`
	UsersOnline    int       `json:"users_online"`
	CountryCode    string    `json:"country_code"`
	SyncedAt       time.Time `json:"synced_at"`
}

// RemnaStats represents aggregated Remnawave statistics
type RemnaStats struct {
	TotalUsers       int       `json:"total_users"`
	ActiveUsers      int       `json:"active_users"`
	DisabledUsers    int       `json:"disabled_users"`
	ExpiredUsers     int       `json:"expired_users"`
	LimitedUsers     int       `json:"limited_users"`
	OnlineNow        int       `json:"online_now"`
	TotalTrafficUsed int64     `json:"total_traffic_used"`
	TotalNodes       int       `json:"total_nodes"`
	OnlineNodes      int       `json:"online_nodes"`
	TotalHwids       int       `json:"total_hwids"`
	UsersWithHwid    int       `json:"users_with_hwid"`
	LastSyncAt       time.Time `json:"last_sync_at"`
}

// GetRemnaStats returns aggregated Remnawave statistics
func (s *Storage) GetRemnaStats(ctx context.Context) (*RemnaStats, error) {
	stats := &RemnaStats{}

	// User stats
	err := s.db.QueryRowContext(ctx, `
		SELECT 
			COUNT(*) as total,
			SUM(CASE WHEN status = 'ACTIVE' THEN 1 ELSE 0 END) as active,
			SUM(CASE WHEN status = 'DISABLED' THEN 1 ELSE 0 END) as disabled,
			SUM(CASE WHEN status = 'EXPIRED' THEN 1 ELSE 0 END) as expired,
			SUM(CASE WHEN status = 'LIMITED' THEN 1 ELSE 0 END) as limited,
			SUM(CASE WHEN online_at > datetime('now', '-5 minutes') THEN 1 ELSE 0 END) as online_now,
			COALESCE(SUM(used_traffic_bytes), 0) as total_traffic,
			COALESCE(MAX(synced_at), datetime('now')) as last_sync
		FROM remna_users
	`).Scan(&stats.TotalUsers, &stats.ActiveUsers, &stats.DisabledUsers,
		&stats.ExpiredUsers, &stats.LimitedUsers, &stats.OnlineNow,
		&stats.TotalTrafficUsed, &stats.LastSyncAt)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Node stats
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), SUM(CASE WHEN is_connected = 1 THEN 1 ELSE 0 END)
		FROM remna_nodes
	`).Scan(&stats.TotalNodes, &stats.OnlineNodes)

	// HWID stats
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT hwid), COUNT(DISTINCT user_uuid)
		FROM remna_hwid_devices
	`).Scan(&stats.TotalHwids, &stats.UsersWithHwid)

	return stats, nil
}

// GetRemnaUsers returns Remnawave users with optional filters
func (s *Storage) GetRemnaUsers(ctx context.Context, limit int, status string, search string) ([]*RemnaUser, error) {
	query := `
		SELECT uuid, short_uuid, username, email, status,
			traffic_limit_bytes, used_traffic_bytes, lifetime_traffic_bytes,
			traffic_limit_strategy, expire_at, online_at, first_connected_at,
			hwid_device_limit, hwid_device_count, telegram_id, description, tag,
			created_at, updated_at, synced_at,
			real_name, phone, telegram_user, payment_info, plan
		FROM remna_users
		WHERE 1=1
	`
	args := []interface{}{}

	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	if search != "" {
		query += " AND (username LIKE ? OR email LIKE ? OR real_name LIKE ?)"
		searchTerm := "%" + search + "%"
		args = append(args, searchTerm, searchTerm, searchTerm)
	}

	query += " ORDER BY online_at DESC NULLS LAST, updated_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*RemnaUser
	for rows.Next() {
		u := &RemnaUser{}
		err := rows.Scan(
			&u.UUID, &u.ShortUUID, &u.Username, &u.Email, &u.Status,
			&u.TrafficLimitBytes, &u.UsedTrafficBytes, &u.LifetimeTrafficBytes,
			&u.TrafficLimitStrategy, &u.ExpireAt, &u.OnlineAt, &u.FirstConnectedAt,
			&u.HwidDeviceLimit, &u.HwidDeviceCount, &u.TelegramID, &u.Description, &u.Tag,
			&u.CreatedAt, &u.UpdatedAt, &u.SyncedAt,
			&u.RealName, &u.Phone, &u.TelegramUser, &u.PaymentInfo, &u.Plan,
		)
		if err != nil {
			continue
		}
		users = append(users, u)
	}
	return users, nil
}

// GetRemnaUserByEmail returns a user by email
func (s *Storage) GetRemnaUserByEmail(ctx context.Context, email string) (*RemnaUser, error) {
	u := &RemnaUser{}
	err := s.db.QueryRowContext(ctx, `
		SELECT uuid, short_uuid, username, email, status,
			traffic_limit_bytes, used_traffic_bytes, lifetime_traffic_bytes,
			traffic_limit_strategy, expire_at, online_at, first_connected_at,
			hwid_device_limit, hwid_device_count, telegram_id, description, tag,
			created_at, updated_at, synced_at,
			real_name, phone, telegram_user, payment_info, plan
		FROM remna_users WHERE email = ? OR username = ?
	`, email, email).Scan(
		&u.UUID, &u.ShortUUID, &u.Username, &u.Email, &u.Status,
		&u.TrafficLimitBytes, &u.UsedTrafficBytes, &u.LifetimeTrafficBytes,
		&u.TrafficLimitStrategy, &u.ExpireAt, &u.OnlineAt, &u.FirstConnectedAt,
		&u.HwidDeviceLimit, &u.HwidDeviceCount, &u.TelegramID, &u.Description, &u.Tag,
		&u.CreatedAt, &u.UpdatedAt, &u.SyncedAt,
		&u.RealName, &u.Phone, &u.TelegramUser, &u.PaymentInfo, &u.Plan,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// GetRemnaUserHwids returns HWID devices for a user
func (s *Storage) GetRemnaUserHwids(ctx context.Context, userUUID string) ([]*RemnaHwidDevice, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, hwid, user_uuid, username, platform, os_version, device_model, app_version,
			first_seen_at, last_active_at, synced_at
		FROM remna_hwid_devices WHERE user_uuid = ?
		ORDER BY last_active_at DESC NULLS LAST
	`, userUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*RemnaHwidDevice
	for rows.Next() {
		d := &RemnaHwidDevice{}
		err := rows.Scan(&d.ID, &d.Hwid, &d.UserUUID, &d.Username, &d.Platform, &d.OSVersion,
			&d.DeviceModel, &d.AppVersion, &d.FirstSeenAt, &d.LastActiveAt, &d.SyncedAt)
		if err != nil {
			continue
		}
		devices = append(devices, d)
	}
	return devices, nil
}

// GetRemnaTopHwidAbusers returns users with most HWID devices
func (s *Storage) GetRemnaTopHwidAbusers(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.uuid, u.username, u.email, u.status, u.hwid_device_count, u.hwid_device_limit,
			u.used_traffic_bytes, u.traffic_limit_bytes, u.online_at
		FROM remna_users u
		WHERE u.hwid_device_count > 1
		ORDER BY u.hwid_device_count DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var uuid, username, status string
		var email *string
		var hwidCount int
		var hwidLimit *int
		var usedTraffic, trafficLimit int64
		var onlineAt *time.Time

		if err := rows.Scan(&uuid, &username, &email, &status, &hwidCount, &hwidLimit,
			&usedTraffic, &trafficLimit, &onlineAt); err != nil {
			continue
		}

		results = append(results, map[string]interface{}{
			"uuid":              uuid,
			"username":          username,
			"email":             email,
			"status":            status,
			"hwid_device_count": hwidCount,
			"hwid_device_limit": hwidLimit,
			"used_traffic":      usedTraffic,
			"traffic_limit":     trafficLimit,
			"online_at":         onlineAt,
		})
	}
	return results, nil
}

// GetRemnaSharedHwids returns HWIDs used by multiple users
func (s *Storage) GetRemnaSharedHwids(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT hwid, platform, COUNT(DISTINCT user_uuid) as user_count,
			GROUP_CONCAT(DISTINCT username) as usernames,
			MAX(last_active_at) as last_active
		FROM remna_hwid_devices
		GROUP BY hwid
		HAVING user_count > 1
		ORDER BY user_count DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var hwid string
		var platform *string
		var userCount int
		var usernames string
		var lastActive *time.Time

		if err := rows.Scan(&hwid, &platform, &userCount, &usernames, &lastActive); err != nil {
			continue
		}

		results = append(results, map[string]interface{}{
			"hwid":        hwid,
			"platform":    platform,
			"user_count":  userCount,
			"usernames":   usernames,
			"last_active": lastActive,
		})
	}
	return results, nil
}

// GetRemnaNodes returns all nodes
func (s *Storage) GetRemnaNodes(ctx context.Context) ([]*RemnaNode, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT uuid, name, address, port, is_connected, is_disabled, is_traffic_track,
			traffic_total, traffic_used, users_online, country_code, synced_at
		FROM remna_nodes ORDER BY users_online DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*RemnaNode
	for rows.Next() {
		n := &RemnaNode{}
		if err := rows.Scan(&n.UUID, &n.Name, &n.Address, &n.Port, &n.IsConnected, &n.IsDisabled,
			&n.IsTrafficTrack, &n.TrafficTotal, &n.TrafficUsed, &n.UsersOnline,
			&n.CountryCode, &n.SyncedAt); err != nil {
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// GetRemnaUserFullProfile returns comprehensive user profile combining local and Remnawave data
func (s *Storage) GetRemnaUserFullProfile(ctx context.Context, emailOrUsername string) (map[string]interface{}, error) {
	profile := make(map[string]interface{})

	// Get Remnawave user data
	remnaUser, err := s.GetRemnaUserByEmail(ctx, emailOrUsername)
	if err != nil {
		return nil, err
	}
	if remnaUser != nil {
		profile["remnawave"] = remnaUser

		// Get HWID devices
		hwids, _ := s.GetRemnaUserHwids(ctx, remnaUser.UUID)
		profile["hwid_devices"] = hwids
	}

	// Get local user details
	details, _ := s.GetUserDetails(ctx, emailOrUsername)
	if details != nil {
		profile["local_stats"] = details
	}

	// Get risk profile
	risk, _ := s.GetUserRiskProfile(ctx, emailOrUsername)
	if risk != nil {
		profile["risk_profile"] = risk
	}

	// Get threat matches
	threats, _ := s.GetThreatMatchesByUser(ctx, emailOrUsername, 20)
	if threats != nil {
		profile["recent_threats"] = threats
	}

	// Get IP history
	ipHistory, _ := s.GetUserIPHistory(ctx, emailOrUsername)
	if ipHistory != nil {
		profile["ip_history"] = ipHistory
	}

	// Get shared HWID users
	sharedHwid, _ := s.GetSharedHWIDUsers(ctx, emailOrUsername)
	if sharedHwid != nil {
		profile["shared_hwid_users"] = sharedHwid
	}

	if len(profile) == 0 {
		return map[string]interface{}{
			"error": "user not found",
			"query": emailOrUsername,
		}, nil
	}

	return profile, nil
}

// GetRemnaOnlineUsers returns currently online users
func (s *Storage) GetRemnaOnlineUsers(ctx context.Context, minutes int) ([]*RemnaUser, error) {
	if minutes <= 0 {
		minutes = 5
	}
	return s.GetRemnaUsers(ctx, 1000, "", "")
}

// GetRemnaExpiringSoon returns users expiring within days
func (s *Storage) GetRemnaExpiringSoon(ctx context.Context, days int) ([]*RemnaUser, error) {
	query := `
		SELECT uuid, short_uuid, username, email, status,
			traffic_limit_bytes, used_traffic_bytes, lifetime_traffic_bytes,
			traffic_limit_strategy, expire_at, online_at, first_connected_at,
			hwid_device_limit, hwid_device_count, telegram_id, description, tag,
			created_at, updated_at, synced_at,
			real_name, phone, telegram_user, payment_info, plan
		FROM remna_users
		WHERE expire_at BETWEEN datetime('now') AND datetime('now', '+' || ? || ' days')
			AND status = 'ACTIVE'
		ORDER BY expire_at ASC
	`
	rows, err := s.db.QueryContext(ctx, query, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*RemnaUser
	for rows.Next() {
		u := &RemnaUser{}
		err := rows.Scan(
			&u.UUID, &u.ShortUUID, &u.Username, &u.Email, &u.Status,
			&u.TrafficLimitBytes, &u.UsedTrafficBytes, &u.LifetimeTrafficBytes,
			&u.TrafficLimitStrategy, &u.ExpireAt, &u.OnlineAt, &u.FirstConnectedAt,
			&u.HwidDeviceLimit, &u.HwidDeviceCount, &u.TelegramID, &u.Description, &u.Tag,
			&u.CreatedAt, &u.UpdatedAt, &u.SyncedAt,
			&u.RealName, &u.Phone, &u.TelegramUser, &u.PaymentInfo, &u.Plan,
		)
		if err != nil {
			continue
		}
		users = append(users, u)
	}
	return users, nil
}

// GetRemnaTrafficAbusers returns users close to traffic limit
func (s *Storage) GetRemnaTrafficAbusers(ctx context.Context, thresholdPercent int) ([]map[string]interface{}, error) {
	query := `
		SELECT uuid, username, email, status, used_traffic_bytes, traffic_limit_bytes,
			CASE WHEN traffic_limit_bytes > 0 
				THEN CAST(used_traffic_bytes AS REAL) / traffic_limit_bytes * 100 
				ELSE 0 
			END as usage_percent
		FROM remna_users
		WHERE traffic_limit_bytes > 0 
			AND CAST(used_traffic_bytes AS REAL) / traffic_limit_bytes * 100 >= ?
		ORDER BY usage_percent DESC
		LIMIT 50
	`
	rows, err := s.db.QueryContext(ctx, query, thresholdPercent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var uuid, username, status string
		var email *string
		var usedTraffic, trafficLimit int64
		var usagePercent float64

		if err := rows.Scan(&uuid, &username, &email, &status, &usedTraffic, &trafficLimit, &usagePercent); err != nil {
			continue
		}

		results = append(results, map[string]interface{}{
			"uuid":          uuid,
			"username":      username,
			"email":         email,
			"status":        status,
			"used_traffic":  usedTraffic,
			"traffic_limit": trafficLimit,
			"usage_percent": usagePercent,
		})
	}
	return results, nil
}

// GetRemnaUsersByTag returns users by tag
func (s *Storage) GetRemnaUsersByTag(ctx context.Context, tag string) ([]*RemnaUser, error) {
	query := `
		SELECT uuid, short_uuid, username, email, status,
			traffic_limit_bytes, used_traffic_bytes, lifetime_traffic_bytes,
			traffic_limit_strategy, expire_at, online_at, first_connected_at,
			hwid_device_limit, hwid_device_count, telegram_id, description, tag,
			created_at, updated_at, synced_at,
			real_name, phone, telegram_user, payment_info, plan
		FROM remna_users WHERE tag = ?
		ORDER BY username
	`
	rows, err := s.db.QueryContext(ctx, query, tag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*RemnaUser
	for rows.Next() {
		u := &RemnaUser{}
		err := rows.Scan(
			&u.UUID, &u.ShortUUID, &u.Username, &u.Email, &u.Status,
			&u.TrafficLimitBytes, &u.UsedTrafficBytes, &u.LifetimeTrafficBytes,
			&u.TrafficLimitStrategy, &u.ExpireAt, &u.OnlineAt, &u.FirstConnectedAt,
			&u.HwidDeviceLimit, &u.HwidDeviceCount, &u.TelegramID, &u.Description, &u.Tag,
			&u.CreatedAt, &u.UpdatedAt, &u.SyncedAt,
			&u.RealName, &u.Phone, &u.TelegramUser, &u.PaymentInfo, &u.Plan,
		)
		if err != nil {
			continue
		}
		users = append(users, u)
	}
	return users, nil
}

// SearchRemnaUsers performs full-text search on Remnawave users
func (s *Storage) SearchRemnaUsers(ctx context.Context, query string, limit int) ([]*RemnaUser, error) {
	searchQuery := `
		SELECT uuid, short_uuid, username, email, status,
			traffic_limit_bytes, used_traffic_bytes, lifetime_traffic_bytes,
			traffic_limit_strategy, expire_at, online_at, first_connected_at,
			hwid_device_limit, hwid_device_count, telegram_id, description, tag,
			created_at, updated_at, synced_at,
			real_name, phone, telegram_user, payment_info, plan
		FROM remna_users 
		WHERE username LIKE ? 
			OR email LIKE ? 
			OR real_name LIKE ?
			OR phone LIKE ?
			OR telegram_user LIKE ?
			OR description LIKE ?
		ORDER BY 
			CASE WHEN username = ? THEN 0
				WHEN username LIKE ? THEN 1
				ELSE 2
			END,
			online_at DESC NULLS LAST
		LIMIT ?
	`
	searchTerm := "%" + query + "%"
	rows, err := s.db.QueryContext(ctx, searchQuery,
		searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm,
		query, query+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*RemnaUser
	for rows.Next() {
		u := &RemnaUser{}
		err := rows.Scan(
			&u.UUID, &u.ShortUUID, &u.Username, &u.Email, &u.Status,
			&u.TrafficLimitBytes, &u.UsedTrafficBytes, &u.LifetimeTrafficBytes,
			&u.TrafficLimitStrategy, &u.ExpireAt, &u.OnlineAt, &u.FirstConnectedAt,
			&u.HwidDeviceLimit, &u.HwidDeviceCount, &u.TelegramID, &u.Description, &u.Tag,
			&u.CreatedAt, &u.UpdatedAt, &u.SyncedAt,
			&u.RealName, &u.Phone, &u.TelegramUser, &u.PaymentInfo, &u.Plan,
		)
		if err != nil {
			continue
		}
		users = append(users, u)
	}
	return users, nil
}

// GetRemnaSummaryForAI returns a summary optimized for AI context
func (s *Storage) GetRemnaSummaryForAI(ctx context.Context) (map[string]interface{}, error) {
	summary := make(map[string]interface{})

	// Get basic stats
	stats, err := s.GetRemnaStats(ctx)
	if err != nil {
		return nil, err
	}
	summary["stats"] = stats

	// Get status distribution
	var statusDist []map[string]interface{}
	rows, _ := s.db.QueryContext(ctx, `
		SELECT status, COUNT(*) as count FROM remna_users GROUP BY status
	`)
	if rows != nil {
		for rows.Next() {
			var status string
			var count int
			if rows.Scan(&status, &count) == nil {
				statusDist = append(statusDist, map[string]interface{}{
					"status": status, "count": count,
				})
			}
		}
		rows.Close()
	}
	summary["status_distribution"] = statusDist

	// Get traffic strategy distribution
	var stratDist []map[string]interface{}
	rows, _ = s.db.QueryContext(ctx, `
		SELECT traffic_limit_strategy, COUNT(*) as count FROM remna_users GROUP BY traffic_limit_strategy
	`)
	if rows != nil {
		for rows.Next() {
			var strategy string
			var count int
			if rows.Scan(&strategy, &count) == nil {
				stratDist = append(stratDist, map[string]interface{}{
					"strategy": strategy, "count": count,
				})
			}
		}
		rows.Close()
	}
	summary["traffic_strategy_distribution"] = stratDist

	// Get users expiring soon
	expiring, _ := s.GetRemnaExpiringSoon(ctx, 7)
	summary["expiring_7_days"] = len(expiring)

	// Get HWID abuse potential
	hwidAbusers, _ := s.GetRemnaTopHwidAbusers(ctx, 10)
	summary["top_hwid_users"] = hwidAbusers

	// Get shared HWIDs
	sharedHwids, _ := s.GetRemnaSharedHwids(ctx, 10)
	summary["shared_hwids"] = sharedHwids

	// Get traffic abusers (>80% usage)
	trafficAbusers, _ := s.GetRemnaTrafficAbusers(ctx, 80)
	summary["traffic_abusers"] = trafficAbusers

	// Marshal to JSON to get size estimate
	jsonBytes, _ := json.Marshal(summary)
	summary["_context_size_bytes"] = len(jsonBytes)

	return summary, nil
}

// ResolveUserEmail resolves a user identifier (username, email, or numeric US_ID) to display name
// Returns the original identifier if no match found
func (s *Storage) ResolveUserEmail(ctx context.Context, userEmail string) string {
	if userEmail == "" {
		return userEmail
	}

	// First try direct lookup by username or email
	var username string
	err := s.db.QueryRowContext(ctx, `
		SELECT username FROM remna_users WHERE username = ? OR email = ?
	`, userEmail, userEmail).Scan(&username)
	if err == nil && username != "" {
		return username
	}

	// If userEmail is numeric, try to find by US_ID in description
	// Format: "SHM_info- @123456, Name, ..., US_ID: 29"
	if isNumericString(userEmail) {
		searchPattern := "%US_ID: " + userEmail + "%"
		err = s.db.QueryRowContext(ctx, `
			SELECT username FROM remna_users WHERE description LIKE ?
		`, searchPattern).Scan(&username)
		if err == nil && username != "" {
			return username
		}
	}

	return userEmail
}

// isNumericString checks if a string contains only digits
func isNumericString(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// BuildUserEmailCache builds a cache mapping all user identifiers to usernames
// This includes username, email, and US_ID from description
func (s *Storage) BuildUserEmailCache(ctx context.Context) (map[string]string, error) {
	cache := make(map[string]string)

	rows, err := s.db.QueryContext(ctx, `
		SELECT username, COALESCE(email, ''), COALESCE(description, '') FROM remna_users
	`)
	if err != nil {
		return cache, err
	}
	defer rows.Close()

	for rows.Next() {
		var username, email, description string
		if err := rows.Scan(&username, &email, &description); err != nil {
			continue
		}

		// Map username -> username
		cache[username] = username

		// Map email -> username (if different)
		if email != "" && email != username {
			cache[email] = username
		}

		// Extract US_ID from description and map it
		if usID := extractUSID(description); usID != "" {
			cache[usID] = username
		}
	}

	return cache, nil
}

// extractUSID extracts US_ID value from description
// Format: "..., US_ID: 123" or "... US_ID: 123, ..."
func extractUSID(description string) string {
	if description == "" {
		return ""
	}

	// Find "US_ID: " or "US_ID:" pattern
	patterns := []string{"US_ID: ", "US_ID:"}
	for _, pattern := range patterns {
		idx := -1
		for i := 0; i <= len(description)-len(pattern); i++ {
			if description[i:i+len(pattern)] == pattern {
				idx = i + len(pattern)
				break
			}
		}
		if idx > 0 {
			// Extract digits after the pattern
			var usID string
			for i := idx; i < len(description); i++ {
				c := description[i]
				if c >= '0' && c <= '9' {
					usID += string(c)
				} else {
					break
				}
			}
			if usID != "" {
				return usID
			}
		}
	}
	return ""
}
