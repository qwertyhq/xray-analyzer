package storage

import (
	"strconv"

	"github.com/google/uuid"
)

// NodeID is the analyzer-internal smallint identifier for a node,
// foreign-keyed against nodes(id). Use storage.LookupNodeID to convert
// from the agent-provided text node_id (e.g. "ru-bridge", "germany-1").
type NodeID int16

func (n NodeID) String() string { return strconv.Itoa(int(n)) }
func (n NodeID) IsZero() bool   { return n == 0 }

// emailToUUID is the canonical converter for analyzer user_email values.
// On exit-nodes, xray logs the email field as a synthetic identifier
// (e.g. "5117", "u-out") that is not a real UUID. Valid UUID strings are
// returned as-is; everything else is deterministically mapped to a SHA-1
// UUID namespaced under uuid.NameSpaceURL so writes never silently fail.
func emailToUUID(email string) uuid.UUID {
	if u, err := uuid.Parse(email); err == nil {
		return u
	}
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(email))
}
