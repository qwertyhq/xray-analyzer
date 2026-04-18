package storage

import (
	"context"
	"testing"

	"github.com/xray-log-analyzer/server/internal/models"
)

func TestAlerts_CreateAndGetUnsent(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	a := &models.Alert{
		Type:        "blacklist",
		NodeID:      "node-alert-1",
		UserEmail:   "alert-user@example.com",
		SourceIP:    "1.2.3.4",
		Destination: "bad.com",
		Count:       5,
		Message:     "too many hits",
	}

	if err := s.CreateAlert(ctx, a); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}
	if a.ID == 0 {
		t.Fatal("expected non-zero alert ID after insert")
	}

	// Should appear in unsent list
	unsent, err := s.GetUnsentAlerts(ctx)
	if err != nil {
		t.Fatalf("GetUnsentAlerts: %v", err)
	}
	if len(unsent) == 0 {
		t.Fatal("expected at least one unsent alert")
	}
	found := false
	for _, u := range unsent {
		if u.ID == a.ID {
			found = true
			if u.Type != a.Type {
				t.Errorf("Type = %q, want %q", u.Type, a.Type)
			}
			if u.Message != a.Message {
				t.Errorf("Message = %q, want %q", u.Message, a.Message)
			}
			if u.Sent {
				t.Error("Sent should be false before MarkAlertSent")
			}
		}
	}
	if !found {
		t.Errorf("inserted alert ID %d not found in unsent list", a.ID)
	}
}

func TestAlerts_MarkSent(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	a := &models.Alert{
		Type:      "geo_anomaly",
		NodeID:    "n1",
		UserEmail: "sent-user@example.com",
		Count:     1,
		Message:   "new country",
	}
	if err := s.CreateAlert(ctx, a); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}

	if err := s.MarkAlertSent(ctx, a.ID); err != nil {
		t.Fatalf("MarkAlertSent: %v", err)
	}

	// Should no longer appear in unsent list
	unsent, err := s.GetUnsentAlerts(ctx)
	if err != nil {
		t.Fatalf("GetUnsentAlerts: %v", err)
	}
	for _, u := range unsent {
		if u.ID == a.ID {
			t.Errorf("alert %d should be marked sent but still appears in unsent list", a.ID)
		}
	}
}

func TestAlerts_GetUserAlerts_Pagination(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := "page-user@example.com"

	// Insert 3 alerts for the same user
	for i := 0; i < 3; i++ {
		a := &models.Alert{
			Type:      "test",
			NodeID:    "n1",
			UserEmail: email,
			Count:     i + 1,
			Message:   "msg",
		}
		if err := s.CreateAlert(ctx, a); err != nil {
			t.Fatalf("CreateAlert #%d: %v", i, err)
		}
	}

	// Page 1, pageSize 2
	resp, err := s.GetUserAlerts(ctx, email, 1, 2)
	if err != nil {
		t.Fatalf("GetUserAlerts: %v", err)
	}
	if resp.Total != 3 {
		t.Errorf("Total = %d, want 3", resp.Total)
	}
	if len(resp.Alerts) != 2 {
		t.Errorf("page 1 len = %d, want 2", len(resp.Alerts))
	}
	if resp.TotalPages != 2 {
		t.Errorf("TotalPages = %d, want 2", resp.TotalPages)
	}

	// Page 2 — 1 remaining
	resp2, err := s.GetUserAlerts(ctx, email, 2, 2)
	if err != nil {
		t.Fatalf("GetUserAlerts page 2: %v", err)
	}
	if len(resp2.Alerts) != 1 {
		t.Errorf("page 2 len = %d, want 1", len(resp2.Alerts))
	}
}

func TestAlerts_GetUserAlerts_OtherUserNotVisible(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	a := &models.Alert{
		Type:      "test",
		NodeID:    "n1",
		UserEmail: "owner@example.com",
		Count:     1,
		Message:   "private",
	}
	if err := s.CreateAlert(ctx, a); err != nil {
		t.Fatal(err)
	}

	resp, err := s.GetUserAlerts(ctx, "stranger@example.com", 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Total != 0 {
		t.Errorf("stranger should see 0 alerts, got %d", resp.Total)
	}
}
