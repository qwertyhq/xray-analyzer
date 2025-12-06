package models

import "time"

// LogEntry represents a parsed Xray access log entry
type LogEntry struct {
	Timestamp   time.Time `json:"ts"`
	SrcIP       string    `json:"src_ip"`
	SrcPort     int       `json:"src_port"`
	Protocol    string    `json:"proto"`
	Destination string    `json:"dst"`
	DstDomain   string    `json:"dst_domain,omitempty"`
	DstIP       string    `json:"dst_ip,omitempty"`
	DstPort     int       `json:"dst_port"`
	Inbound     string    `json:"inbound"`
	Outbound    string    `json:"outbound"`
	User        string    `json:"user"`
}

// LogBatch represents a batch of log entries to send to server
type LogBatch struct {
	NodeID    string     `json:"node_id"`
	Timestamp time.Time  `json:"timestamp"`
	Entries   []LogEntry `json:"entries"`
	Count     int        `json:"count"`
}

// ServerMessage represents a message from the server
type ServerMessage struct {
	Type      string `json:"type"`
	Message   string `json:"message,omitempty"`
	AckID     int64  `json:"ack_id,omitempty"`
	Processed int    `json:"processed,omitempty"`
	Error     string `json:"error,omitempty"`
}
