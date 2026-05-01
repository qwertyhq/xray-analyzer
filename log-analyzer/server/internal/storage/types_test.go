package storage

import (
	"testing"
)

func TestNodeID_Zero(t *testing.T) {
	var n NodeID
	if n != 0 {
		t.Fatalf("zero value should be 0, got %d", n)
	}
}

func TestNodeID_String(t *testing.T) {
	n := NodeID(42)
	if got := n.String(); got != "42" {
		t.Fatalf("String() = %q want %q", got, "42")
	}
}

func TestNodeID_IsZero(t *testing.T) {
	var zero NodeID
	if !zero.IsZero() {
		t.Fatal("zero NodeID should report IsZero()")
	}
	if NodeID(1).IsZero() {
		t.Fatal("non-zero NodeID should not report IsZero()")
	}
}
