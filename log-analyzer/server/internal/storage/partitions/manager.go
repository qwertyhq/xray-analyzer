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
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for _, tbl := range m.tables {
		for offset := 0; offset <= 2; offset++ {
			start := today.AddDate(0, 0, offset)
			end := start.AddDate(0, 0, 1)
			name := tbl.PartitionName(start)
			sql := fmt.Sprintf(`
				CREATE TABLE IF NOT EXISTS %s
				PARTITION OF %s
				FOR VALUES FROM ('%s') TO ('%s')
			`, name, tbl.Name, start.Format(time.RFC3339), end.Format(time.RFC3339))
			if _, err := m.pool.Exec(ctx, sql); err != nil {
				return fmt.Errorf("ensure %s: %w", name, err)
			}
		}
	}
	return nil
}

// Healthy returns nil if every managed table has a partition for today and
// its _default partition is empty. Returns an error otherwise — fed into the
// /health endpoint.
//
// Check order: missing today-partition takes precedence over non-empty default,
// so the most actionable error surfaces first.
func (m *Manager) Healthy(ctx context.Context) error {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for _, tbl := range m.tables {
		// 1. Today's named partition must exist.
		name := tbl.PartitionName(today)
		var exists bool
		err := m.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)`,
			name).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check %s: %w", name, err)
		}
		if !exists {
			return fmt.Errorf("missing partition %s for today", name)
		}

		// 2. The _default catch-all partition must be empty. Rows there mean
		// the partition manager missed a scheduling window and rows fell through.
		var defaultRows int
		err = m.pool.QueryRow(ctx,
			fmt.Sprintf(`SELECT COUNT(*) FROM %s_default`, tbl.Name),
		).Scan(&defaultRows)
		if err != nil {
			return fmt.Errorf("count default %s_default: %w", tbl.Name, err)
		}
		if defaultRows > 0 {
			return fmt.Errorf("%s_default has %d rows — partition manager missed a window", tbl.Name, defaultRows)
		}
	}
	return nil
}

// DropExpiredPartitions drops partitions older than RetentionDays.
func (m *Manager) DropExpiredPartitions(ctx context.Context) error {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for _, tbl := range m.tables {
		cutoff := today.AddDate(0, 0, -tbl.RetentionDays)
		rows, err := m.pool.Query(ctx, `
			SELECT child.relname
			FROM pg_inherits i
			JOIN pg_class parent ON parent.oid = i.inhparent
			JOIN pg_class child  ON child.oid  = i.inhrelid
			WHERE parent.relname = $1
		`, tbl.Name)
		if err != nil {
			return fmt.Errorf("list %s partitions: %w", tbl.Name, err)
		}
		var toDrop []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			if len(name) < len(tbl.Name)+9 {
				continue
			}
			suffix := name[len(tbl.Name)+1:]
			day, err := time.Parse("20060102", suffix)
			if err != nil {
				continue
			}
			if day.Before(cutoff) {
				toDrop = append(toDrop, name)
			}
		}
		rows.Close()
		for _, name := range toDrop {
			if _, err := m.pool.Exec(ctx, "DROP TABLE IF EXISTS "+name); err != nil {
				return fmt.Errorf("drop %s: %w", name, err)
			}
		}
	}
	return nil
}
