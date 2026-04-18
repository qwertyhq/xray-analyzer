package storage

// dns_stats_stub.go — temporary compile stubs for methods that live in
// dns_stats.go (still behind sqlite_legacy build tag). Remove this file
// once dns_stats.go is ported to Postgres.

import (
	"context"

	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// GetDNSAnalysisSummary is a stub that returns an empty summary until
// dns_stats.go is ported in a future task.
func (s *Storage) GetDNSAnalysisSummary(ctx context.Context) (*threatintel.DNSAnalysisSummary, error) {
	return &threatintel.DNSAnalysisSummary{
		CategoryBreakdown: make(map[string]int),
	}, nil
}
