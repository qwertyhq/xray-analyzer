package storage

import "strconv"

// NodeID is the analyzer-internal smallint identifier for a node,
// foreign-keyed against nodes(id). Use storage.LookupNodeID to convert
// from the agent-provided text node_id (e.g. "ru-bridge", "germany-1").
type NodeID int16

func (n NodeID) String() string { return strconv.Itoa(int(n)) }
func (n NodeID) IsZero() bool   { return n == 0 }
