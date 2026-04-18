//go:build sqlite_legacy

package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// ChatSession represents an AI chat session
type ChatSession struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	TotalTokens int       `json:"total_tokens"`
}

// ChatMessage represents a message in a chat session
type ChatMessage struct {
	ID         int64     `json:"id"`
	SessionID  string    `json:"session_id"`
	Role       string    `json:"role"`
	Content    string    `json:"content"`
	TokensUsed int       `json:"tokens_used"`
	CreatedAt  time.Time `json:"created_at"`
}

// CreateChatSession creates a new chat session
func (s *Storage) CreateChatSession(ctx context.Context, title string) (*ChatSession, error) {
	id := uuid.New().String()
	now := time.Now()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ai_chat_sessions (id, title, created_at, updated_at, total_tokens)
		VALUES (?, ?, ?, ?, 0)
	`, id, title, now, now)
	if err != nil {
		return nil, err
	}

	return &ChatSession{
		ID:          id,
		Title:       title,
		CreatedAt:   now,
		UpdatedAt:   now,
		TotalTokens: 0,
	}, nil
}

// GetChatSession retrieves a chat session by ID
func (s *Storage) GetChatSession(ctx context.Context, sessionID string) (*ChatSession, error) {
	var session ChatSession
	err := s.db.QueryRowContext(ctx, `
		SELECT id, title, created_at, updated_at, total_tokens
		FROM ai_chat_sessions
		WHERE id = ?
	`, sessionID).Scan(&session.ID, &session.Title, &session.CreatedAt, &session.UpdatedAt, &session.TotalTokens)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// GetChatSessions retrieves all chat sessions, ordered by most recent
func (s *Storage) GetChatSessions(ctx context.Context, limit int) ([]ChatSession, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, title, created_at, updated_at, total_tokens
		FROM ai_chat_sessions
		ORDER BY updated_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []ChatSession
	for rows.Next() {
		var session ChatSession
		if err := rows.Scan(&session.ID, &session.Title, &session.CreatedAt, &session.UpdatedAt, &session.TotalTokens); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

// UpdateChatSessionTitle updates the title of a chat session
func (s *Storage) UpdateChatSessionTitle(ctx context.Context, sessionID, title string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE ai_chat_sessions SET title = ?, updated_at = ? WHERE id = ?
	`, title, time.Now(), sessionID)
	return err
}

// DeleteChatSession deletes a chat session and all its messages
func (s *Storage) DeleteChatSession(ctx context.Context, sessionID string) error {
	// Messages will be deleted via CASCADE
	_, err := s.db.ExecContext(ctx, `DELETE FROM ai_chat_sessions WHERE id = ?`, sessionID)
	return err
}

// ClearAllChatSessions deletes all chat sessions
func (s *Storage) ClearAllChatSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ai_chat_sessions`)
	return err
}

// AddChatMessage adds a message to a chat session
func (s *Storage) AddChatMessage(ctx context.Context, sessionID, role, content string, tokensUsed int) (*ChatMessage, error) {
	now := time.Now()

	result, err := s.db.ExecContext(ctx, `
		INSERT INTO ai_chat_messages (session_id, role, content, tokens_used, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, sessionID, role, content, tokensUsed, now)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	// Update session's updated_at and total_tokens
	_, err = s.db.ExecContext(ctx, `
		UPDATE ai_chat_sessions 
		SET updated_at = ?, total_tokens = total_tokens + ?
		WHERE id = ?
	`, now, tokensUsed, sessionID)
	if err != nil {
		return nil, err
	}

	return &ChatMessage{
		ID:         id,
		SessionID:  sessionID,
		Role:       role,
		Content:    content,
		TokensUsed: tokensUsed,
		CreatedAt:  now,
	}, nil
}

// GetChatMessages retrieves all messages for a session
func (s *Storage) GetChatMessages(ctx context.Context, sessionID string, limit int) ([]ChatMessage, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, session_id, role, content, tokens_used, created_at
		FROM ai_chat_messages
		WHERE session_id = ?
		ORDER BY created_at ASC
		LIMIT ?
	`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []ChatMessage
	for rows.Next() {
		var msg ChatMessage
		if err := rows.Scan(&msg.ID, &msg.SessionID, &msg.Role, &msg.Content, &msg.TokensUsed, &msg.CreatedAt); err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}
	return messages, rows.Err()
}

// GetRecentChatMessages retrieves the last N messages for a session (for context)
func (s *Storage) GetRecentChatMessages(ctx context.Context, sessionID string, limit int) ([]ChatMessage, error) {
	if limit <= 0 {
		limit = 10
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, session_id, role, content, tokens_used, created_at
		FROM ai_chat_messages
		WHERE session_id = ?
		ORDER BY created_at DESC
		LIMIT ?
	`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []ChatMessage
	for rows.Next() {
		var msg ChatMessage
		if err := rows.Scan(&msg.ID, &msg.SessionID, &msg.Role, &msg.Content, &msg.TokensUsed, &msg.CreatedAt); err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Reverse to get chronological order
	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}

	return messages, nil
}
