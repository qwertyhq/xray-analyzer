package partitions

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Table describes one partitioned parent table managed by this module.
type Table struct {
	Name          string
	RetentionDays int
}

// PartitionName returns the daily partition name for a given UTC date.
// Format: <parent>_YYYYMMDD.
func (t Table) PartitionName(day time.Time) string {
	return t.Name + "_" + day.UTC().Format("20060102")
}

// Manager creates and drops daily partitions for the configured tables.
type Manager struct {
	pool   *pgxpool.Pool
	tables []Table
}

// NewManager constructs a Manager.
func NewManager(pool *pgxpool.Pool, tables []Table) *Manager {
	return &Manager{pool: pool, tables: tables}
}

// Run blocks until ctx is cancelled, calling Tick() once immediately and
// then every 6 hours.
func (m *Manager) Run(ctx context.Context) error {
	if err := m.Tick(ctx); err != nil {
		return err
	}
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			_ = m.Tick(ctx)
		}
	}
}

// Tick performs one full reconciliation pass.
func (m *Manager) Tick(ctx context.Context) error {
	if err := m.EnsureFuturePartitions(ctx); err != nil {
		return err
	}
	return m.DropExpiredPartitions(ctx)
}

// EnsureFuturePartitions creates today and the next 2 days' partitions if missing.
func (m *Manager) EnsureFuturePartitions(ctx context.Context) error {
	_ = fmt.Sprintf
	return nil // implemented in Step 1.2
}

// DropExpiredPartitions drops partitions older than RetentionDays.
func (m *Manager) DropExpiredPartitions(ctx context.Context) error {
	return nil // implemented in Step 1.3
}
