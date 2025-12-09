package aleria

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// Service provides AI-powered analytics using data from storage
type Service struct {
	client *Client
	db     *sql.DB
}

// NewService creates a new Aleria AI analytics service
func NewService(apiKey string, db *sql.DB) *Service {
	return &Service{
		client: NewClient(apiKey),
		db:     db,
	}
}

// IsConfigured returns true if the service is ready to use
func (s *Service) IsConfigured() bool {
	return s.client.IsConfigured()
}

// DataContext represents collected data for AI analysis
type DataContext struct {
	Stats          *OverviewStats       `json:"stats"`
	TopUsers       []UserSummary        `json:"top_users"`
	TopThreats     []ThreatSummary      `json:"top_threats"`
	RecentActivity []RecentActivityItem `json:"recent_activity"`
	Anomalies      []AnomalySummary     `json:"anomalies"`
	GeoStats       []GeoSummary         `json:"geo_stats"`
	NodeStats      []NodeSummary        `json:"node_stats"`
}

type OverviewStats struct {
	TotalUsers         int   `json:"total_users"`
	TotalRequests      int64 `json:"total_requests"`
	TotalThreats       int   `json:"total_threats"`
	TotalBlacklistHits int   `json:"total_blacklist_hits"`
	ActiveToday        int   `json:"active_today"`
	HighRiskUsers      int   `json:"high_risk_users"`
}

type UserSummary struct {
	Email         string `json:"email"`
	TotalRequests int64  `json:"total_requests"`
	ThreatMatches int    `json:"threat_matches"`
	BlacklistHits int    `json:"blacklist_hits"`
	RiskLevel     string `json:"risk_level"`
	LastSeen      string `json:"last_seen"`
}

type ThreatSummary struct {
	ThreatType string `json:"threat_type"`
	MatchCount int    `json:"match_count"`
	LastMatch  string `json:"last_match"`
}

type RecentActivityItem struct {
	Time        string `json:"time"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

type AnomalySummary struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	DetectedAt  string `json:"detected_at"`
}

type GeoSummary struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	UserCount   int    `json:"user_count"`
	ThreatCount int    `json:"threat_count"`
}

type NodeSummary struct {
	NodeID        string `json:"node_id"`
	TotalRequests int64  `json:"total_requests"`
	UniqueUsers   int    `json:"unique_users"`
	BlacklistHits int    `json:"blacklist_hits"`
	LastSeen      string `json:"last_seen"`
}

// CollectContext gathers relevant data from the database for AI analysis
func (s *Service) CollectContext(ctx context.Context) (*DataContext, error) {
	data := &DataContext{}

	// Get overview stats
	stats, err := s.getOverviewStats(ctx)
	if err != nil {
		log.Printf("[aleria] error getting overview stats: %v", err)
	} else {
		data.Stats = stats
	}

	// Get top users by activity
	users, err := s.getTopUsers(ctx, 10)
	if err != nil {
		log.Printf("[aleria] error getting top users: %v", err)
	} else {
		data.TopUsers = users
	}

	// Get threat stats
	threats, err := s.getThreatStats(ctx)
	if err != nil {
		log.Printf("[aleria] error getting threat stats: %v", err)
	} else {
		data.TopThreats = threats
	}

	// Get anomalies
	anomalies, err := s.getRecentAnomalies(ctx, 5)
	if err != nil {
		log.Printf("[aleria] error getting anomalies: %v", err)
	} else {
		data.Anomalies = anomalies
	}

	// Get geo stats
	geoStats, err := s.getGeoStats(ctx)
	if err != nil {
		log.Printf("[aleria] error getting geo stats: %v", err)
	} else {
		data.GeoStats = geoStats
	}

	// Get node stats
	nodeStats, err := s.getNodeStats(ctx)
	if err != nil {
		log.Printf("[aleria] error getting node stats: %v", err)
	} else {
		data.NodeStats = nodeStats
	}

	return data, nil
}

func (s *Service) getOverviewStats(ctx context.Context) (*OverviewStats, error) {
	stats := &OverviewStats{}

	// Total unique users
	row := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT user_email) FROM user_stats`)
	row.Scan(&stats.TotalUsers)

	// Total requests
	row = s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(total_requests), 0) FROM user_stats`)
	row.Scan(&stats.TotalRequests)

	// Total threats
	row = s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(match_count), 0) FROM threat_type_stats`)
	row.Scan(&stats.TotalThreats)

	// Total blacklist hits
	row = s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(blacklist_hits), 0) FROM user_stats`)
	row.Scan(&stats.TotalBlacklistHits)

	// Active today
	row = s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT user_email) FROM user_stats 
		WHERE last_seen >= datetime('now', '-1 day')
	`)
	row.Scan(&stats.ActiveToday)

	// High risk users
	row = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM user_risk_profiles 
		WHERE risk_level IN ('high', 'critical')
	`)
	row.Scan(&stats.HighRiskUsers)

	return stats, nil
}

func (s *Service) getTopUsers(ctx context.Context, limit int) ([]UserSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			us.user_email,
			us.total_requests,
			COALESCE((SELECT SUM(match_count) FROM user_threat_stats WHERE user_email = us.user_email), 0) as threats,
			us.blacklist_hits,
			COALESCE(urp.risk_level, 'unknown') as risk_level,
			us.last_seen
		FROM user_stats us
		LEFT JOIN user_risk_profiles urp ON us.user_email = urp.user_email
		ORDER BY us.total_requests DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []UserSummary
	for rows.Next() {
		var u UserSummary
		var lastSeen sql.NullTime
		if err := rows.Scan(&u.Email, &u.TotalRequests, &u.ThreatMatches, &u.BlacklistHits, &u.RiskLevel, &lastSeen); err != nil {
			continue
		}
		if lastSeen.Valid {
			u.LastSeen = lastSeen.Time.Format(time.RFC3339)
		}
		users = append(users, u)
	}
	return users, nil
}

func (s *Service) getThreatStats(ctx context.Context) ([]ThreatSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT threat_type, match_count, last_match
		FROM threat_type_stats
		ORDER BY match_count DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var threats []ThreatSummary
	for rows.Next() {
		var t ThreatSummary
		var lastMatch sql.NullTime
		if err := rows.Scan(&t.ThreatType, &t.MatchCount, &lastMatch); err != nil {
			continue
		}
		if lastMatch.Valid {
			t.LastMatch = lastMatch.Time.Format(time.RFC3339)
		}
		threats = append(threats, t)
	}
	return threats, nil
}

func (s *Service) getRecentAnomalies(ctx context.Context, limit int) ([]AnomalySummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT type, severity, description, detected_at
		FROM anomalies
		WHERE resolved = 0
		ORDER BY detected_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var anomalies []AnomalySummary
	for rows.Next() {
		var a AnomalySummary
		var detectedAt time.Time
		if err := rows.Scan(&a.Type, &a.Severity, &a.Description, &detectedAt); err != nil {
			continue
		}
		a.DetectedAt = detectedAt.Format(time.RFC3339)
		anomalies = append(anomalies, a)
	}
	return anomalies, nil
}

func (s *Service) getGeoStats(ctx context.Context) ([]GeoSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			country_code,
			country_name,
			COUNT(DISTINCT user_email) as user_count,
			COALESCE(SUM(request_count), 0) as request_count
		FROM user_locations
		GROUP BY country_code, country_name
		ORDER BY user_count DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var geoStats []GeoSummary
	for rows.Next() {
		var g GeoSummary
		var requestCount int
		if err := rows.Scan(&g.CountryCode, &g.Country, &g.UserCount, &requestCount); err != nil {
			continue
		}
		geoStats = append(geoStats, g)
	}
	return geoStats, nil
}

func (s *Service) getNodeStats(ctx context.Context) ([]NodeSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT node_id, total_requests, unique_users, blacklist_hits, last_seen
		FROM node_stats
		ORDER BY total_requests DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []NodeSummary
	for rows.Next() {
		var n NodeSummary
		var lastSeen sql.NullTime
		if err := rows.Scan(&n.NodeID, &n.TotalRequests, &n.UniqueUsers, &n.BlacklistHits, &lastSeen); err != nil {
			continue
		}
		if lastSeen.Valid {
			n.LastSeen = lastSeen.Time.Format(time.RFC3339)
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// buildSystemPrompt creates the system prompt with current data context
func (s *Service) buildSystemPrompt(data *DataContext) string {
	contextJSON, _ := json.MarshalIndent(data, "", "  ")

	return fmt.Sprintf(`Ты — AI-ассистент для анализа данных VPN-сервиса XRay Log Analyzer.

Твоя задача — помогать администратору анализировать:
- Активность пользователей и их поведение
- Угрозы безопасности (торренты, TOR, блоклисты, подозрительные домены)
- Географию подключений
- Аномалии в поведении пользователей
- Статистику по нодам VPN

Текущие данные системы:
%s

Правила ответов:
1. Отвечай на русском языке
2. Будь конкретным — используй данные из контекста
3. При анализе угроз указывай конкретных пользователей и типы угроз
4. Предлагай действия (например: "рекомендую заблокировать пользователя X")
5. Форматируй ответы для удобного чтения (списки, абзацы)
6. Если данных недостаточно — честно об этом скажи

Ты можешь:
- Анализировать пользователей по уровню риска
- Выявлять подозрительную активность
- Сравнивать статистику между нодами
- Отвечать на вопросы о трафике и угрозах
- Давать рекомендации по безопасности`, string(contextJSON))
}

// ChatRequest represents a user chat request
type ChatQueryRequest struct {
	Message string    `json:"message"`
	History []Message `json:"history,omitempty"`
}

// ChatQueryResponse represents the response to a chat query
type ChatQueryResponse struct {
	Response   string `json:"response"`
	TokensUsed int    `json:"tokens_used"`
}

// Query sends a question to the AI with current data context
func (s *Service) Query(ctx context.Context, req *ChatQueryRequest) (*ChatQueryResponse, error) {
	if !s.IsConfigured() {
		return nil, fmt.Errorf("aleria: service not configured")
	}

	// Collect current data context
	data, err := s.CollectContext(ctx)
	if err != nil {
		log.Printf("[aleria] warning: failed to collect full context: %v", err)
	}

	// Build messages
	messages := []Message{
		{Role: "system", Content: s.buildSystemPrompt(data)},
	}

	// Add conversation history
	for _, m := range req.History {
		messages = append(messages, m)
	}

	// Add current user message
	messages = append(messages, Message{Role: "user", Content: req.Message})

	// Send to AI
	chatReq := &ChatRequest{
		Messages:    messages,
		Temperature: 0.7,
		MaxTokens:   2000,
	}

	resp, err := s.client.Chat(ctx, chatReq)
	if err != nil {
		return nil, fmt.Errorf("aleria: chat failed: %w", err)
	}

	return &ChatQueryResponse{
		Response:   resp.GetContent(),
		TokensUsed: resp.Usage.TotalTokens,
	}, nil
}

// QuickAnalysis performs a quick analysis of the system
func (s *Service) QuickAnalysis(ctx context.Context) (*ChatQueryResponse, error) {
	return s.Query(ctx, &ChatQueryRequest{
		Message: "Дай краткий обзор текущего состояния системы: сколько пользователей, какие угрозы, есть ли аномалии. Выдели главное.",
	})
}

// AnalyzeUser performs detailed analysis of a specific user
func (s *Service) AnalyzeUser(ctx context.Context, email string) (*ChatQueryResponse, error) {
	// Get user-specific data
	userData, err := s.getUserData(ctx, email)
	if err != nil {
		return nil, err
	}

	return s.Query(ctx, &ChatQueryRequest{
		Message: fmt.Sprintf("Проанализируй пользователя %s. Вот его данные:\n%s\n\nКакой у него уровень риска? Есть ли подозрительная активность? Нужны ли действия?", email, userData),
	})
}

func (s *Service) getUserData(ctx context.Context, email string) (string, error) {
	var data struct {
		TotalRequests int64    `json:"total_requests"`
		BlacklistHits int      `json:"blacklist_hits"`
		ThreatsCount  int      `json:"threats_count"`
		RiskLevel     string   `json:"risk_level"`
		Countries     string   `json:"countries"`
		LastSeen      string   `json:"last_seen"`
		RecentDomains []string `json:"recent_domains"`
	}

	// Basic stats
	row := s.db.QueryRowContext(ctx, `
		SELECT total_requests, blacklist_hits, last_seen
		FROM user_stats 
		WHERE user_email = ?
	`, email)
	var lastSeen sql.NullTime
	row.Scan(&data.TotalRequests, &data.BlacklistHits, &lastSeen)
	if lastSeen.Valid {
		data.LastSeen = lastSeen.Time.Format(time.RFC3339)
	}

	// Threats
	row = s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(match_count), 0) FROM user_threat_stats WHERE user_email = ?
	`, email)
	row.Scan(&data.ThreatsCount)

	// Risk level
	row = s.db.QueryRowContext(ctx, `
		SELECT risk_level FROM user_risk_profiles WHERE user_email = ?
	`, email)
	row.Scan(&data.RiskLevel)

	// Countries
	rows, _ := s.db.QueryContext(ctx, `
		SELECT country_name FROM user_locations WHERE user_email = ? ORDER BY request_count DESC LIMIT 5
	`, email)
	if rows != nil {
		defer rows.Close()
		var countries []string
		for rows.Next() {
			var c string
			rows.Scan(&c)
			countries = append(countries, c)
		}
		data.Countries = strings.Join(countries, ", ")
	}

	// Recent domains (from threats)
	rows, _ = s.db.QueryContext(ctx, `
		SELECT DISTINCT destination FROM threat_matches 
		WHERE user_email = ? 
		ORDER BY matched_at DESC LIMIT 10
	`, email)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var d string
			rows.Scan(&d)
			data.RecentDomains = append(data.RecentDomains, d)
		}
	}

	jsonData, _ := json.MarshalIndent(data, "", "  ")
	return string(jsonData), nil
}
