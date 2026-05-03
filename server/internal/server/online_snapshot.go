package server

import (
	"context"
	"log"
	"time"
)

// startOnlineSnapshotJob writes a minute-resolution snapshot of total online
// users (summed across mapped Remnawave nodes) into online_snapshots. The
// activity chart reads this to show a trend line that reflects actual XTLS
// sessions rather than access-log freshness.
//
// Runs one shot immediately so the chart has a data point right after a
// deploy, then every minute.
func (s *Server) startOnlineSnapshotJob(ctx context.Context) {
	const tick = time.Minute

	snap := func() {
		// 30s budget — this job has to compete with ProcessBatch writes for
		// the SQLite write lock, and 5s was routinely not enough under
		// bursty load. Missing a minute is still fine, the chart bucket is
		// hourly.
		jobCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		total, err := s.storage.TotalRemnaOnline(jobCtx)
		if err != nil {
			log.Printf("online-snapshot: total query failed: %v", err)
			return
		}
		if err := s.storage.RecordOnlineSnapshot(jobCtx, time.Now().UTC(), total); err != nil {
			log.Printf("online-snapshot: insert failed: %v", err)
		}
	}

	snap()

	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			snap()
		}
	}
}
