package storage

import (
	"context"
	"testing"
)

func TestGeoStats_SaveAndGet(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if err := s.SaveGeoStats(ctx, "DE", "Germany", "malware", testUUID("geo-user-1")); err != nil {
		t.Fatalf("SaveGeoStats: %v", err)
	}

	stats, err := s.GetGeoStats(ctx, 10)
	if err != nil {
		t.Fatalf("GetGeoStats: %v", err)
	}
	if len(stats) == 0 {
		t.Fatal("GetGeoStats returned empty result")
	}

	found := false
	for _, s := range stats {
		if s.CountryCode == "DE" && s.ThreatType == "malware" {
			found = true
			if s.MatchCount < 1 {
				t.Errorf("MatchCount = %d, want >= 1", s.MatchCount)
			}
		}
	}
	if !found {
		t.Error("DE/malware entry not found in GetGeoStats")
	}
}

func TestGeoStats_SaveGeoStats_EmptyCountryCode(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Empty country code must be a no-op, not an error
	if err := s.SaveGeoStats(ctx, "", "Unknown", "malware", testUUID("geo-user-empty")); err != nil {
		t.Errorf("SaveGeoStats with empty country: %v", err)
	}

	stats, err := s.GetGeoStats(ctx, 10)
	if err != nil {
		t.Fatalf("GetGeoStats: %v", err)
	}
	for _, s := range stats {
		if s.CountryCode == "" {
			t.Error("empty country_code should not be inserted")
		}
	}
}

func TestGeoStats_SaveUserLocation(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := testUUID("geo-user-loc")

	if err := s.SaveUserLocation(ctx, email, "FR", "France", "Paris", 48.85, 2.35); err != nil {
		t.Fatalf("SaveUserLocation: %v", err)
	}

	locs, err := s.GetUserLocations(ctx, email, 5)
	if err != nil {
		t.Fatalf("GetUserLocations: %v", err)
	}
	if len(locs) == 0 {
		t.Fatal("GetUserLocations returned empty")
	}
	if locs[0].CountryCode != "FR" {
		t.Errorf("CountryCode = %q, want FR", locs[0].CountryCode)
	}

	// Upsert: save again should increment request_count, not duplicate
	if err := s.SaveUserLocation(ctx, email, "FR", "France", "Paris", 48.85, 2.35); err != nil {
		t.Fatalf("SaveUserLocation (2nd): %v", err)
	}
	locs2, err := s.GetUserLocations(ctx, email, 5)
	if err != nil {
		t.Fatalf("GetUserLocations (2nd): %v", err)
	}
	if len(locs2) != 1 {
		t.Errorf("expected 1 location after upsert, got %d", len(locs2))
	}
	if locs2[0].RequestCount < 2 {
		t.Errorf("RequestCount = %d after 2 saves, want >= 2", locs2[0].RequestCount)
	}
}

func TestGeoStats_GetGeoSummary(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if err := s.SaveGeoStats(ctx, "US", "United States", "tor", testUUID("geo-summary-u1")); err != nil {
		t.Fatalf("SaveGeoStats: %v", err)
	}
	if err := s.SaveGeoStats(ctx, "CN", "China", "malware", testUUID("geo-summary-u2")); err != nil {
		t.Fatalf("SaveGeoStats CN: %v", err)
	}

	summary, err := s.GetGeoSummary(ctx)
	if err != nil {
		t.Fatalf("GetGeoSummary: %v", err)
	}
	if summary.TotalCountries < 2 {
		t.Errorf("TotalCountries = %d, want >= 2", summary.TotalCountries)
	}
	if len(summary.TopCountries) == 0 {
		t.Error("TopCountries is empty")
	}
	if len(summary.ByThreatType) == 0 {
		t.Error("ByThreatType is empty")
	}
}

func TestGeoStats_GetConnectionGeoStats(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if err := s.SaveUserLocation(ctx, testUUID("geo-conn-user"), "JP", "Japan", "Tokyo", 35.68, 139.69); err != nil {
		t.Fatalf("SaveUserLocation: %v", err)
	}

	stats, err := s.GetConnectionGeoStats(ctx, 10)
	if err != nil {
		t.Fatalf("GetConnectionGeoStats: %v", err)
	}
	found := false
	for _, st := range stats {
		if st.CountryCode == "JP" {
			found = true
		}
	}
	if !found {
		t.Error("JP not found in GetConnectionGeoStats")
	}
}

func TestGeoStats_UpdateLocationCoords(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := testUUID("geo-coord-user")
	if err := s.SaveUserLocation(ctx, email, "IT", "Italy", "", 0, 0); err != nil {
		t.Fatalf("SaveUserLocation: %v", err)
	}

	// Verify it shows up as needing coords
	noCoords, err := s.GetLocationsWithoutCoords(ctx, 10)
	if err != nil {
		t.Fatalf("GetLocationsWithoutCoords: %v", err)
	}
	found := false
	for _, l := range noCoords {
		if l.UserEmail == email {
			found = true
		}
	}
	if !found {
		t.Error("user with zero coords not found in GetLocationsWithoutCoords")
	}

	// Update coords
	if err := s.UpdateLocationCoords(ctx, email, "IT", "Rome", 41.9, 12.5); err != nil {
		t.Fatalf("UpdateLocationCoords: %v", err)
	}

	// Should no longer appear in no-coords list
	noCoords2, err := s.GetLocationsWithoutCoords(ctx, 10)
	if err != nil {
		t.Fatalf("GetLocationsWithoutCoords after update: %v", err)
	}
	for _, l := range noCoords2 {
		if l.UserEmail == email {
			t.Error("user still appears in GetLocationsWithoutCoords after coord update")
		}
	}
}
