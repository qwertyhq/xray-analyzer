package storage

import (
	"context"
	"testing"
)

func TestChat_CreateAndGetSession(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	sess, err := s.CreateChatSession(ctx, "Test Session")
	if err != nil {
		t.Fatalf("CreateChatSession: %v", err)
	}
	if sess == nil {
		t.Fatal("expected non-nil session")
	}
	if sess.ID == "" {
		t.Error("expected non-empty session ID")
	}
	if sess.Title != "Test Session" {
		t.Errorf("Title = %q, want %q", sess.Title, "Test Session")
	}
	if sess.TotalTokens != 0 {
		t.Errorf("TotalTokens = %d, want 0", sess.TotalTokens)
	}

	// GetChatSession round-trip
	got, err := s.GetChatSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetChatSession: %v", err)
	}
	if got == nil {
		t.Fatal("GetChatSession returned nil for existing session")
	}
	if got.ID != sess.ID {
		t.Errorf("ID = %q, want %q", got.ID, sess.ID)
	}
	if got.Title != sess.Title {
		t.Errorf("Title = %q, want %q", got.Title, sess.Title)
	}
}

func TestChat_GetChatSession_NotFound(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	got, err := s.GetChatSession(ctx, "nonexistent-uuid")
	if err != nil {
		t.Fatalf("GetChatSession: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for missing session, got %+v", got)
	}
}

func TestChat_AddMessage_RequiresExistingSession(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Adding a message without a parent session must fail (FK constraint)
	_, err := s.AddChatMessage(ctx, "nonexistent-session", "user", "hello", 5)
	if err == nil {
		t.Error("expected FK violation error when session does not exist, got nil")
	}
}

func TestChat_AddMessageAndGet(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	sess, err := s.CreateChatSession(ctx, "Msg Session")
	if err != nil {
		t.Fatalf("CreateChatSession: %v", err)
	}

	msg, err := s.AddChatMessage(ctx, sess.ID, "user", "hello", 10)
	if err != nil {
		t.Fatalf("AddChatMessage: %v", err)
	}
	if msg.ID == 0 {
		t.Error("expected non-zero message ID")
	}
	if msg.Role != "user" {
		t.Errorf("Role = %q, want user", msg.Role)
	}
	if msg.Content != "hello" {
		t.Errorf("Content = %q, want hello", msg.Content)
	}
	if msg.TokensUsed != 10 {
		t.Errorf("TokensUsed = %d, want 10", msg.TokensUsed)
	}

	// GetChatMessages should return the message
	messages, err := s.GetChatMessages(ctx, sess.ID, 50)
	if err != nil {
		t.Fatalf("GetChatMessages: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
	if messages[0].ID != msg.ID {
		t.Errorf("message ID mismatch: got %d want %d", messages[0].ID, msg.ID)
	}
}

func TestChat_TotalTokensAccumulate(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	sess, err := s.CreateChatSession(ctx, "Token Session")
	if err != nil {
		t.Fatalf("CreateChatSession: %v", err)
	}

	if _, err := s.AddChatMessage(ctx, sess.ID, "user", "msg1", 20); err != nil {
		t.Fatalf("AddChatMessage #1: %v", err)
	}
	if _, err := s.AddChatMessage(ctx, sess.ID, "assistant", "reply", 30); err != nil {
		t.Fatalf("AddChatMessage #2: %v", err)
	}

	got, err := s.GetChatSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetChatSession: %v", err)
	}
	if got.TotalTokens != 50 {
		t.Errorf("TotalTokens = %d, want 50", got.TotalTokens)
	}
}

func TestChat_GetChatSessions_OrderedByUpdatedAt(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	s1, err := s.CreateChatSession(ctx, "First")
	if err != nil {
		t.Fatalf("CreateChatSession first: %v", err)
	}
	s2, err := s.CreateChatSession(ctx, "Second")
	if err != nil {
		t.Fatalf("CreateChatSession second: %v", err)
	}
	_ = s2 // we'll update s1 to make it the newest

	// Touch s1 by adding a message — this bumps its updated_at
	if _, err := s.AddChatMessage(ctx, s1.ID, "user", "bump", 1); err != nil {
		t.Fatalf("AddChatMessage: %v", err)
	}

	sessions, err := s.GetChatSessions(ctx, 10)
	if err != nil {
		t.Fatalf("GetChatSessions: %v", err)
	}
	if len(sessions) < 2 {
		t.Fatalf("expected at least 2 sessions, got %d", len(sessions))
	}
	// s1 was touched most recently — must be first
	if sessions[0].ID != s1.ID {
		t.Errorf("expected session %q first (most recent), got %q", s1.ID, sessions[0].ID)
	}
}

func TestChat_DeleteSession_CascadesMessages(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	sess, err := s.CreateChatSession(ctx, "To Delete")
	if err != nil {
		t.Fatalf("CreateChatSession: %v", err)
	}
	if _, err := s.AddChatMessage(ctx, sess.ID, "user", "bye", 5); err != nil {
		t.Fatalf("AddChatMessage: %v", err)
	}

	if err := s.DeleteChatSession(ctx, sess.ID); err != nil {
		t.Fatalf("DeleteChatSession: %v", err)
	}

	// Session should be gone
	got, err := s.GetChatSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetChatSession after delete: %v", err)
	}
	if got != nil {
		t.Error("expected nil after delete, session still exists")
	}

	// Messages should be cascaded away
	messages, err := s.GetChatMessages(ctx, sess.ID, 10)
	if err != nil {
		t.Fatalf("GetChatMessages after delete: %v", err)
	}
	if len(messages) != 0 {
		t.Errorf("expected 0 messages after cascade delete, got %d", len(messages))
	}
}

func TestChat_GetRecentChatMessages_ChronologicalOrder(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	sess, err := s.CreateChatSession(ctx, "Order Session")
	if err != nil {
		t.Fatalf("CreateChatSession: %v", err)
	}

	roles := []string{"user", "assistant", "user"}
	for i, role := range roles {
		if _, err := s.AddChatMessage(ctx, sess.ID, role, "msg", i+1); err != nil {
			t.Fatalf("AddChatMessage #%d: %v", i, err)
		}
	}

	// GetRecentChatMessages returns in chronological order despite DESC query
	msgs, err := s.GetRecentChatMessages(ctx, sess.ID, 10)
	if err != nil {
		t.Fatalf("GetRecentChatMessages: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}
	for i := 1; i < len(msgs); i++ {
		if msgs[i].CreatedAt.Before(msgs[i-1].CreatedAt) {
			t.Errorf("messages[%d].CreatedAt %v is before messages[%d].CreatedAt %v — not chronological",
				i, msgs[i].CreatedAt, i-1, msgs[i-1].CreatedAt)
		}
	}
}

func TestChat_UpdateChatSessionTitle(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	sess, err := s.CreateChatSession(ctx, "Old Title")
	if err != nil {
		t.Fatalf("CreateChatSession: %v", err)
	}

	if err := s.UpdateChatSessionTitle(ctx, sess.ID, "New Title"); err != nil {
		t.Fatalf("UpdateChatSessionTitle: %v", err)
	}

	got, err := s.GetChatSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetChatSession: %v", err)
	}
	if got.Title != "New Title" {
		t.Errorf("Title = %q, want %q", got.Title, "New Title")
	}
}

func TestChat_ClearAllChatSessions(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := s.CreateChatSession(ctx, "session"); err != nil {
			t.Fatalf("CreateChatSession #%d: %v", i, err)
		}
	}

	if err := s.ClearAllChatSessions(ctx); err != nil {
		t.Fatalf("ClearAllChatSessions: %v", err)
	}

	sessions, err := s.GetChatSessions(ctx, 50)
	if err != nil {
		t.Fatalf("GetChatSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions after clear, got %d", len(sessions))
	}
}
