package aleria

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/xray-log-analyzer/server/internal/storage"
)

// Service provides AI-powered analytics with smart database queries
type Service struct {
	client  *Client
	storage *storage.Storage
}

// NewService creates a new Aleria AI service
func NewService(apiKey string, store *storage.Storage) *Service {
	return &Service{
		client:  NewClient(apiKey),
		storage: store,
	}
}

// IsConfigured returns true if the service is properly configured
func (s *Service) IsConfigured() bool {
	return s.client.IsConfigured()
}

// ChatQueryRequest represents a chat query request
type ChatQueryRequest struct {
	Message string `json:"message"`
	History []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"history,omitempty"`
}

// ChatQueryResponse represents a chat query response
type ChatQueryResponse struct {
	Response   string `json:"response"`
	TokensUsed int    `json:"tokens_used"`
}

// Tool definitions for function calling
var tools = []map[string]interface{}{
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_global_stats",
			"description": "Get global statistics: total users, requests, blacklist hits, active nodes",
			"parameters": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
				"required":   []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_threat_stats",
			"description": "Get threat intelligence statistics: total threats by category (tor, torrent, malware, etc), top threat types, hourly trends",
			"parameters": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
				"required":   []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_top_risky_users",
			"description": "Get top users by risk score with their threat categories and risk factors",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Number of users to return (default 10, max 50)",
					},
					"min_risk_score": map[string]interface{}{
						"type":        "integer",
						"description": "Minimum risk score filter (0-100)",
					},
				},
				"required": []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "search_user",
			"description": "Search for a specific user by email and get their full profile: risk score, threat history, IP locations, HWID correlations",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"email": map[string]interface{}{
						"type":        "string",
						"description": "User email to search for (partial match supported)",
					},
				},
				"required": []string{"email"},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_geo_stats",
			"description": "Get geographic statistics: connections by country, top cities, suspicious geo patterns",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Number of countries to return (default 20)",
					},
				},
				"required": []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_anomalies",
			"description": "Get detected anomalies: activity spikes, night activity, threat bursts, multi-country access",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"include_resolved": map[string]interface{}{
						"type":        "boolean",
						"description": "Include resolved anomalies (default false)",
					},
				},
				"required": []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_shared_hwid_analysis",
			"description": "Get HWID sharing analysis: users sharing same hardware IDs, potential subscription abuse",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Number of shared HWIDs to return (default 20)",
					},
				},
				"required": []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_node_stats",
			"description": "Get statistics for VPN nodes: total requests, blacklist hits, unique users per node",
			"parameters": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
				"required":   []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_hourly_activity",
			"description": "Get hourly activity statistics for trend analysis",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"hours": map[string]interface{}{
						"type":        "integer",
						"description": "Number of hours to look back (default 24, max 168)",
					},
				},
				"required": []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_blacklist_analytics",
			"description": "Get blacklist analytics: top blocked domains, users with most hits, recent matches",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"hours": map[string]interface{}{
						"type":        "integer",
						"description": "Hours to look back (default 24)",
					},
				},
				"required": []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_correlation_stats",
			"description": "Get correlation statistics: IP sharing patterns, HWID sharing, fingerprint analysis",
			"parameters": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
				"required":   []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_dns_stats",
			"description": "Get DNS query statistics: blocked queries, threat categories, top blocked domains",
			"parameters": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
				"required":   []string{},
			},
		},
	},
	// Remnawave data functions
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_remnawave_stats",
			"description": "Get VPN subscription statistics from Remnawave: total users, active/disabled/expired users, online count, traffic usage, nodes status",
			"parameters": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
				"required":   []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_remnawave_users",
			"description": "Get list of VPN users with their subscription status, traffic usage, expiry dates. Can filter by status or search by name/email",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Number of users to return (default 50)",
					},
					"status": map[string]interface{}{
						"type":        "string",
						"description": "Filter by status: ACTIVE, DISABLED, EXPIRED, LIMITED",
					},
					"search": map[string]interface{}{
						"type":        "string",
						"description": "Search by username, email, or name",
					},
				},
				"required": []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_remnawave_user_profile",
			"description": "Get comprehensive user profile combining VPN subscription data (Remnawave) with security data (threats, risk score, HWID, IP history)",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"email": map[string]interface{}{
						"type":        "string",
						"description": "User email or username to look up",
					},
				},
				"required": []string{"email"},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_remnawave_hwid_abusers",
			"description": "Get users with multiple HWID devices - potential subscription sharing abuse",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Number of users to return (default 20)",
					},
				},
				"required": []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_remnawave_shared_hwids",
			"description": "Get HWIDs used by multiple different users - clear subscription abuse indicator",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Number of shared HWIDs to return (default 20)",
					},
				},
				"required": []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_remnawave_expiring_users",
			"description": "Get users whose subscriptions are expiring soon",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"days": map[string]interface{}{
						"type":        "integer",
						"description": "Days until expiry (default 7)",
					},
				},
				"required": []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_remnawave_traffic_abusers",
			"description": "Get users close to or exceeding their traffic limits",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"threshold_percent": map[string]interface{}{
						"type":        "integer",
						"description": "Traffic usage threshold percentage (default 80)",
					},
				},
				"required": []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "get_remnawave_nodes",
			"description": "Get VPN nodes status: connected/disconnected, users online, traffic",
			"parameters": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
				"required":   []string{},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]interface{}{
			"name":        "search_remnawave_users",
			"description": "Search VPN users by username, email, phone, telegram, or any text in their profile",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "Search query",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Number of results (default 20)",
					},
				},
				"required": []string{"query"},
			},
		},
	},
}

// Query processes a user query using function calling
func (s *Service) Query(ctx context.Context, req *ChatQueryRequest) (*ChatQueryResponse, error) {
	systemPrompt := `Ты - AI-аналитик безопасности VPN-системы. Ты анализируешь данные о пользователях, угрозах и активности.

У тебя есть доступ к инструментам для получения данных из базы. Используй их умно:
- Сначала определи, какие данные нужны для ответа на вопрос
- Запрашивай только релевантные данные
- Если нужна информация о конкретном пользователе - используй search_user или get_remnawave_user_profile
- Для общей статистики - get_global_stats, get_threat_stats или get_remnawave_stats
- Для анализа угроз - get_threat_stats, get_anomalies
- Для географии - get_geo_stats
- Для анализа абьюза подписок - get_remnawave_hwid_abusers, get_remnawave_shared_hwids
- Для данных о подписках VPN - get_remnawave_users, get_remnawave_expiring_users
- Для анализа трафика - get_remnawave_traffic_abusers

Данные из Remnawave - это информация о VPN подписках пользователей (статус, трафик, устройства).
Данные из локальной базы - это информация о безопасности (угрозы, риски, IP, геолокация).

Отвечай на русском языке. Будь конкретным и приводи цифры из данных.
Если данных недостаточно - запроси дополнительные через инструменты.`

	messages := []map[string]interface{}{
		{"role": "system", "content": systemPrompt},
	}

	// Add history if present
	for _, h := range req.History {
		messages = append(messages, map[string]interface{}{
			"role":    h.Role,
			"content": h.Content,
		})
	}

	// Add current message
	messages = append(messages, map[string]interface{}{
		"role":    "user",
		"content": req.Message,
	})

	totalTokens := 0
	maxIterations := 5

	for i := 0; i < maxIterations; i++ {
		resp, err := s.client.ChatWithTools(ctx, messages, tools)
		if err != nil {
			return nil, fmt.Errorf("chat request failed: %w", err)
		}

		totalTokens += resp.Usage.TotalTokens

		if len(resp.Choices) == 0 {
			return nil, fmt.Errorf("no response from AI")
		}

		choice := resp.Choices[0]

		// If there are tool calls, execute them
		if len(choice.Message.ToolCalls) > 0 {
			// Add assistant message with tool calls
			messages = append(messages, map[string]interface{}{
				"role":       "assistant",
				"content":    choice.Message.Content,
				"tool_calls": choice.Message.ToolCalls,
			})

			// Execute each tool call
			for _, toolCall := range choice.Message.ToolCalls {
				result, err := s.executeFunction(ctx, toolCall.Function.Name, toolCall.Function.Arguments)
				if err != nil {
					result = fmt.Sprintf(`{"error": "%s"}`, err.Error())
				}

				messages = append(messages, map[string]interface{}{
					"role":         "tool",
					"tool_call_id": toolCall.ID,
					"content":      result,
				})
			}
			continue
		}

		// No more tool calls - we have the final response
		return &ChatQueryResponse{
			Response:   choice.Message.Content,
			TokensUsed: totalTokens,
		}, nil
	}

	return nil, fmt.Errorf("max iterations reached without final response")
}

// executeFunction executes a function call and returns the result as JSON
func (s *Service) executeFunction(ctx context.Context, name string, argsJSON string) (string, error) {
	log.Printf("[aleria] executing function: %s with args: %s", name, argsJSON)

	var args map[string]interface{}
	if argsJSON != "" && argsJSON != "{}" {
		if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
			return "", fmt.Errorf("parse args: %w", err)
		}
	}

	var result interface{}
	var err error

	switch name {
	case "get_global_stats":
		result, err = s.storage.GetGlobalStats(ctx)

	case "get_threat_stats":
		result, err = s.storage.GetThreatStats(ctx)

	case "get_top_risky_users":
		limit := getIntArg(args, "limit", 10)
		minScore := getIntArg(args, "min_risk_score", 0)
		if limit > 50 {
			limit = 50
		}
		result, err = s.storage.GetAllUserAIProfiles(ctx, limit, minScore)

	case "search_user":
		email, ok := args["email"].(string)
		if !ok || email == "" {
			return "", fmt.Errorf("email is required")
		}
		result, err = s.getUserProfile(ctx, email)

	case "get_geo_stats":
		limit := getIntArg(args, "limit", 20)
		result, err = s.storage.GetGeoStats(ctx, limit)

	case "get_anomalies":
		includeResolved := getBoolArg(args, "include_resolved", false)
		result, err = s.storage.GetAnomalies(ctx, 50, includeResolved)

	case "get_shared_hwid_analysis":
		limit := getIntArg(args, "limit", 20)
		result, err = s.storage.GetTopSharedHWIDs(ctx, limit)

	case "get_node_stats":
		result, err = s.storage.GetNodeStats(ctx)

	case "get_hourly_activity":
		hours := getIntArg(args, "hours", 24)
		if hours > 168 {
			hours = 168
		}
		result, err = s.storage.GetHourlyStats(ctx, hours)

	case "get_blacklist_analytics":
		hours := getIntArg(args, "hours", 24)
		since := time.Now().Add(-time.Duration(hours) * time.Hour)
		result, err = s.storage.GetBlacklistAnalytics(ctx, since)

	case "get_correlation_stats":
		result, err = s.storage.GetCorrelationStats(ctx)

	case "get_dns_stats":
		result, err = s.storage.GetDNSQueryStats(ctx)

	// Remnawave functions
	case "get_remnawave_stats":
		result, err = s.storage.GetRemnaStats(ctx)

	case "get_remnawave_users":
		limit := getIntArg(args, "limit", 50)
		status := getStringArg(args, "status", "")
		search := getStringArg(args, "search", "")
		result, err = s.storage.GetRemnaUsers(ctx, limit, status, search)

	case "get_remnawave_user_profile":
		email, ok := args["email"].(string)
		if !ok || email == "" {
			return "", fmt.Errorf("email is required")
		}
		result, err = s.storage.GetRemnaUserFullProfile(ctx, email)

	case "get_remnawave_hwid_abusers":
		limit := getIntArg(args, "limit", 20)
		result, err = s.storage.GetRemnaTopHwidAbusers(ctx, limit)

	case "get_remnawave_shared_hwids":
		limit := getIntArg(args, "limit", 20)
		result, err = s.storage.GetRemnaSharedHwids(ctx, limit)

	case "get_remnawave_expiring_users":
		days := getIntArg(args, "days", 7)
		result, err = s.storage.GetRemnaExpiringSoon(ctx, days)

	case "get_remnawave_traffic_abusers":
		threshold := getIntArg(args, "threshold_percent", 80)
		result, err = s.storage.GetRemnaTrafficAbusers(ctx, threshold)

	case "get_remnawave_nodes":
		result, err = s.storage.GetRemnaNodes(ctx)

	case "search_remnawave_users":
		query, ok := args["query"].(string)
		if !ok || query == "" {
			return "", fmt.Errorf("query is required")
		}
		limit := getIntArg(args, "limit", 20)
		result, err = s.storage.SearchRemnaUsers(ctx, query, limit)

	default:
		return "", fmt.Errorf("unknown function: %s", name)
	}

	if err != nil {
		log.Printf("[aleria] function %s error: %v", name, err)
		return "", err
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("marshal result: %w", err)
	}

	log.Printf("[aleria] function %s returned %d bytes", name, len(jsonBytes))
	return string(jsonBytes), nil
}

// getUserProfile gets comprehensive user profile
func (s *Service) getUserProfile(ctx context.Context, email string) (map[string]interface{}, error) {
	profile := make(map[string]interface{})

	// Get user details
	details, err := s.storage.GetUserDetails(ctx, email)
	if err == nil && details != nil {
		profile["user_details"] = details
	}

	// Get risk profile
	risk, err := s.storage.GetUserRiskProfile(ctx, email)
	if err == nil && risk != nil {
		profile["risk_profile"] = risk
	}

	// Get AI profile
	aiProfile, err := s.storage.GetUserAIProfile(ctx, email)
	if err == nil && aiProfile != nil {
		profile["ai_profile"] = aiProfile
	}

	// Get IP history
	ipHistory, err := s.storage.GetUserIPHistory(ctx, email)
	if err == nil {
		profile["ip_history"] = ipHistory
	}

	// Get shared HWID users
	sharedHWID, err := s.storage.GetSharedHWIDUsers(ctx, email)
	if err == nil {
		profile["shared_hwid_users"] = sharedHWID
	}

	// Get threat matches
	threats, err := s.storage.GetThreatMatchesByUser(ctx, email, 20)
	if err == nil {
		profile["recent_threats"] = threats
	}

	// Get locations
	locations, err := s.storage.GetUserLocations(ctx, email, 10)
	if err == nil {
		profile["locations"] = locations
	}

	if len(profile) == 0 {
		return map[string]interface{}{
			"error": "user not found",
			"email": email,
		}, nil
	}

	return profile, nil
}

// AnalyzeUser generates AI analysis for a specific user
func (s *Service) AnalyzeUser(ctx context.Context, email string) (*ChatQueryResponse, error) {
	return s.Query(ctx, &ChatQueryRequest{
		Message: fmt.Sprintf("Проанализируй пользователя %s: его риск-профиль, угрозы, геолокацию, подозрительную активность. Дай рекомендации.", email),
	})
}

// QueryStream processes a user query with streaming response
func (s *Service) QueryStream(ctx context.Context, req *ChatQueryRequest, onChunk func(content string, done bool)) error {
	systemPrompt := `Ты - AI-аналитик безопасности VPN-системы. Ты анализируешь данные о пользователях, угрозах и активности.

У тебя есть доступ к инструментам для получения данных из базы. Используй их умно:
- Сначала определи, какие данные нужны для ответа на вопрос
- Запрашивай только релевантные данные
- Если нужна информация о конкретном пользователе - используй search_user или get_remnawave_user_profile
- Для общей статистики - get_global_stats, get_threat_stats или get_remnawave_stats
- Для анализа угроз - get_threat_stats, get_anomalies
- Для географии - get_geo_stats
- Для анализа абьюза подписок - get_remnawave_hwid_abusers, get_remnawave_shared_hwids
- Для данных о подписках VPN - get_remnawave_users, get_remnawave_expiring_users
- Для анализа трафика - get_remnawave_traffic_abusers

Данные из Remnawave - это информация о VPN подписках пользователей (статус, трафик, устройства).
Данные из локальной базы - это информация о безопасности (угрозы, риски, IP, геолокация).

Отвечай на русском языке. Будь конкретным и приводи цифры из данных.
Если данных недостаточно - запроси дополнительные через инструменты.`

	messages := []map[string]interface{}{
		{"role": "system", "content": systemPrompt},
	}

	// Add history if present
	for _, h := range req.History {
		messages = append(messages, map[string]interface{}{
			"role":    h.Role,
			"content": h.Content,
		})
	}

	// Add current message
	messages = append(messages, map[string]interface{}{
		"role":    "user",
		"content": req.Message,
	})

	maxIterations := 5

	for i := 0; i < maxIterations; i++ {
		// First, check if we need tool calls (non-streaming)
		resp, err := s.client.ChatWithTools(ctx, messages, tools)
		if err != nil {
			return fmt.Errorf("chat request failed: %w", err)
		}

		if len(resp.Choices) == 0 {
			return fmt.Errorf("no response from AI")
		}

		choice := resp.Choices[0]

		// If there are tool calls, execute them
		if len(choice.Message.ToolCalls) > 0 {
			// Add assistant message with tool calls
			messages = append(messages, map[string]interface{}{
				"role":       "assistant",
				"content":    choice.Message.Content,
				"tool_calls": choice.Message.ToolCalls,
			})

			// Execute each tool call
			for _, toolCall := range choice.Message.ToolCalls {
				result, err := s.executeFunction(ctx, toolCall.Function.Name, toolCall.Function.Arguments)
				if err != nil {
					result = fmt.Sprintf(`{"error": "%s"}`, err.Error())
				}

				messages = append(messages, map[string]interface{}{
					"role":         "tool",
					"tool_call_id": toolCall.ID,
					"content":      result,
				})
			}
			continue
		}

		// No more tool calls - stream the final response
		// Remove tools for final streaming response
		return s.client.ChatStream(ctx, messages, nil, onChunk)
	}

	return fmt.Errorf("max iterations reached without final response")
}

// Helper functions
func getIntArg(args map[string]interface{}, key string, defaultVal int) int {
	if v, ok := args[key]; ok {
		switch val := v.(type) {
		case float64:
			return int(val)
		case int:
			return val
		}
	}
	return defaultVal
}

func getBoolArg(args map[string]interface{}, key string, defaultVal bool) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return defaultVal
}

func getStringArg(args map[string]interface{}, key string, defaultVal string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return defaultVal
}
