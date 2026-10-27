package remnawave

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Remnawave 3.x: users have no uuid (only id + vlessUuid), devices carry userId.
func TestRemnawaveV3UsersAndDevices(t *testing.T) {
	var deleteBody map[string]any
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/api/users":
			w.Write([]byte(`{"response":{"total":2,"users":[
				{"id":107,"vlessUuid":"11111111-1111-4111-8111-111111111111","username":"us_107","status":"ACTIVE"},
				{"id":65,"vlessUuid":"22222222-2222-4222-8222-222222222222","username":"us_65","status":"ACTIVE"}]}}`))
		case "/api/hwid/devices":
			w.Write([]byte(`{"response":{"total":2,"devices":[
				{"hwid":"a","userId":107},{"hwid":"b","userId":999}]}}`))
		case "/api/users/107/subscription-request-history":
			w.Write([]byte(`{"response":{"total":0,"records":[]}}`))
		case "/api/users/65":
			w.Write([]byte(`{"response":{"id":65,"vlessUuid":"22222222-2222-4222-8222-222222222222","username":"us_65"}}`))
		case "/api/hwid/devices/delete-all":
			json.NewDecoder(r.Body).Decode(&deleteBody)
			w.Write([]byte(`{"response":{"total":0,"devices":[]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "t")
	ctx := context.Background()
	resp, err := c.GetUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Users) != 2 || resp.Users[0].UUID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("users not normalized: %+v", resp.Users)
	}

	s := NewSyncService(c, 0)
	if err := s.syncUsers(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.syncHwidDevices(ctx); err != nil {
		t.Fatal(err)
	}
	if d := s.GetUserHwidDevices("11111111-1111-4111-8111-111111111111"); len(d) != 1 || d[0].Hwid != "a" {
		t.Fatalf("device not attached to user: %+v", d)
	}
	if n := s.countHwidDevices(); n != 1 {
		t.Fatalf("orphan device kept: %d", n)
	}

	if _, err := c.GetUserSubscriptionHistory(ctx, "11111111-1111-4111-8111-111111111111"); err != nil {
		t.Fatalf("history by id: %v", err)
	}
	if u, err := c.GetUserByID(ctx, "65"); err != nil || u.UUID != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("GetUserByID: %v %+v", err, u)
	}
	if _, err := c.DeleteAllUserHwidDevices(ctx, "11111111-1111-4111-8111-111111111111"); err != nil {
		t.Fatal(err)
	}
	if deleteBody["userId"] != float64(107) {
		t.Fatalf("delete-all payload: %v", deleteBody)
	}
}
