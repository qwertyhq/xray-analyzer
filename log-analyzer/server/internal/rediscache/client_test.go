package rediscache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// TestClient_NilSafe verifies the "Redis is optional" contract: a nil
// *Client must never panic and must report misses / no-ops so the rest of
// the codebase can skip defensive checks.
func TestClient_NilSafe(t *testing.T) {
	var c *Client
	ctx := context.Background()

	var v string
	ok, err := c.GetJSON(ctx, "anything", &v)
	if err != nil || ok {
		t.Fatalf("nil GetJSON: got (%v, %v), want (false, nil)", ok, err)
	}
	if err := c.SetJSON(ctx, "anything", "value", time.Minute); err != nil {
		t.Fatalf("nil SetJSON: %v", err)
	}
	if err := c.Delete(ctx, "anything"); err != nil {
		t.Fatalf("nil Delete: %v", err)
	}
	if err := c.DeletePrefix(ctx, "anything"); err != nil {
		t.Fatalf("nil DeletePrefix: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
}

// TestClient_RoundTrip: set a value, get it back, confirm the JSON-encoded
// bytes live under the configured prefix (so multiple services can share
// one Redis without collision).
func TestClient_RoundTrip(t *testing.T) {
	mr := miniredis.RunT(t)

	c, err := New(mr.Addr(), "", "testprefix")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	type userRow struct{ Name string; Score int }

	if err := c.SetJSON(ctx, "user:42", userRow{Name: "alice", Score: 99}, time.Hour); err != nil {
		t.Fatal(err)
	}

	var got userRow
	ok, err := c.GetJSON(ctx, "user:42", &got)
	if err != nil || !ok {
		t.Fatalf("GetJSON: got (%v, %v)", ok, err)
	}
	if got.Name != "alice" || got.Score != 99 {
		t.Errorf("round-trip payload: %+v", got)
	}

	// miniredis-level sanity: value stored under "testprefix:user:42".
	if raw, err := mr.Get("testprefix:user:42"); err != nil {
		t.Errorf("miniredis Get: %v", err)
	} else if raw == "" {
		t.Errorf("expected non-empty stored value")
	}
}

// TestClient_Miss: an unset key reports miss without error (not an exception).
func TestClient_Miss(t *testing.T) {
	mr := miniredis.RunT(t)
	c, _ := New(mr.Addr(), "", "")
	defer c.Close()

	var v string
	ok, err := c.GetJSON(context.Background(), "nope", &v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Errorf("expected miss, got value %q", v)
	}
}

// TestClient_TTL: values honour their TTL — helpful to guard cache freshness.
func TestClient_TTL(t *testing.T) {
	mr := miniredis.RunT(t)
	c, _ := New(mr.Addr(), "", "")
	defer c.Close()

	ctx := context.Background()
	_ = c.SetJSON(ctx, "short", "x", 100*time.Millisecond)

	mr.FastForward(200 * time.Millisecond)

	var v string
	ok, _ := c.GetJSON(ctx, "short", &v)
	if ok {
		t.Errorf("expected expired miss, got %q", v)
	}
}

// TestClient_DeletePrefix scans and wipes a namespace. Used when the id
// cache is cleared (e.g. on resync).
func TestClient_DeletePrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	c, _ := New(mr.Addr(), "", "ns")
	defer c.Close()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_ = c.SetJSON(ctx, "remna:id:"+itoa(i), "u", time.Hour)
	}
	_ = c.SetJSON(ctx, "unrelated:1", "u", time.Hour)

	if err := c.DeletePrefix(ctx, "remna:id:"); err != nil {
		t.Fatal(err)
	}

	var v string
	ok, _ := c.GetJSON(ctx, "remna:id:0", &v)
	if ok {
		t.Errorf("remna:id:0 survived DeletePrefix")
	}
	ok, _ = c.GetJSON(ctx, "unrelated:1", &v)
	if !ok {
		t.Errorf("unrelated key was wiped by DeletePrefix")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var out []byte
	for i > 0 {
		out = append([]byte{byte('0' + i%10)}, out...)
		i /= 10
	}
	return string(out)
}
