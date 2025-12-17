package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xray-log-analyzer/agent/internal/models"
)

// Parser parses Xray access log lines
type Parser struct {
	// Regex to parse log lines
	// Format: 2025/12/06 00:00:14.136976 from 95.25.117.121:10976 accepted udp:142.250.130.106:443 [VTR-PL >> DIRECT] email: 547
	// Note: "email:" field contains Remnawave numeric user ID, not username
	lineRegex *regexp.Regexp
}

// New creates a new Parser
func New() *Parser {
	// Regex breakdown:
	// (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+) - timestamp
	// from (?:tcp:)?([\w.:]+):(\d+) - source IP:port (supports IPv6, optional tcp: prefix)
	// accepted (tcp|udp):(.+?) - protocol and destination
	// \[(.+?) (?:>>|->) (.+?)\] - inbound >> or -> outbound (supports both formats)
	// email: (\S+) - user email
	regex := regexp.MustCompile(
		`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+from\s+(?:tcp:)?([\w\[\]:.-]+):(\d+)\s+accepted\s+(tcp|udp):(.+?)\s+\[(.+?)\s+(?:>>|->)\s+(.+?)\]\s+email:\s+(\S+)`,
	)
	return &Parser{lineRegex: regex}
}

// ParseLine parses a single log line into a LogEntry
func (p *Parser) ParseLine(line string) (*models.LogEntry, error) {
	matches := p.lineRegex.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("line does not match expected format")
	}

	// Parse timestamp
	ts, err := time.Parse("2006/01/02 15:04:05.000000", matches[1])
	if err != nil {
		// Try without microseconds
		ts, err = time.Parse("2006/01/02 15:04:05", matches[1][:19])
		if err != nil {
			return nil, fmt.Errorf("failed to parse timestamp: %w", err)
		}
	}

	// Parse source port
	srcPort, err := strconv.Atoi(matches[3])
	if err != nil {
		return nil, fmt.Errorf("failed to parse source port: %w", err)
	}

	// Parse destination (can be IP:port or domain:port or [IPv6]:port)
	dst := matches[5]
	dstDomain, dstIP, dstPort := parseDestination(dst)

	entry := &models.LogEntry{
		Timestamp:   ts,
		SrcIP:       matches[2],
		SrcPort:     srcPort,
		Protocol:    matches[4],
		Destination: dst,
		DstDomain:   dstDomain,
		DstIP:       dstIP,
		DstPort:     dstPort,
		Inbound:     strings.TrimSpace(matches[6]),
		Outbound:    strings.TrimSpace(matches[7]),
		User:        matches[8],
	}

	return entry, nil
}

// parseDestination extracts domain/IP and port from destination string
func parseDestination(dst string) (domain, ip string, port int) {
	// Handle IPv6: [2a00:1450:4025:807::8b]:443
	if strings.HasPrefix(dst, "[") {
		idx := strings.LastIndex(dst, "]:")
		if idx > 0 {
			ip = dst[1:idx]
			portStr := dst[idx+2:]
			port, _ = strconv.Atoi(portStr)
			return "", ip, port
		}
	}

	// Handle regular format: host:port
	lastColon := strings.LastIndex(dst, ":")
	if lastColon == -1 {
		return dst, "", 0
	}

	host := dst[:lastColon]
	portStr := dst[lastColon+1:]
	port, _ = strconv.Atoi(portStr)

	// Check if host is IP or domain
	if isIPAddress(host) {
		return "", host, port
	}
	return host, "", port
}

// isIPAddress checks if string is an IP address (v4 or v6)
func isIPAddress(s string) bool {
	// Simple check: if contains only digits and dots, it's likely IPv4
	// If contains colons, it's likely IPv6
	for _, c := range s {
		if c == ':' {
			return true // IPv6
		}
		if (c < '0' || c > '9') && c != '.' {
			return false // Has letters, so it's a domain
		}
	}
	return true // Only digits and dots = IPv4
}
