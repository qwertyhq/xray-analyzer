package batcher

import (
	"context"
	"log"
	"time"

	"github.com/xray-log-analyzer/agent/internal/models"
)

// Batcher collects log entries and emits batches
type Batcher struct {
	nodeID  string
	maxSize int
	timeout time.Duration
	entryCh chan *models.LogEntry
	batchCh chan *models.LogBatch
	buffer  []models.LogEntry
}

// New creates a new Batcher
func New(nodeID string, maxSize int, timeout time.Duration, entryCh chan *models.LogEntry, batchCh chan *models.LogBatch) *Batcher {
	return &Batcher{
		nodeID:  nodeID,
		maxSize: maxSize,
		timeout: timeout,
		entryCh: entryCh,
		batchCh: batchCh,
		buffer:  make([]models.LogEntry, 0, maxSize),
	}
}

// Start begins batching entries
func (b *Batcher) Start(ctx context.Context) {
	ticker := time.NewTicker(b.timeout)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Flush remaining entries before shutdown
			b.flush()
			log.Println("batcher: shutting down")
			return

		case entry := <-b.entryCh:
			b.buffer = append(b.buffer, *entry)

			// Flush if buffer is full
			if len(b.buffer) >= b.maxSize {
				b.flush()
				ticker.Reset(b.timeout)
			}

		case <-ticker.C:
			// Flush on timeout even if buffer is not full
			if len(b.buffer) > 0 {
				b.flush()
			}
		}
	}
}

// flush sends the current buffer as a batch
func (b *Batcher) flush() {
	if len(b.buffer) == 0 {
		return
	}

	batch := &models.LogBatch{
		NodeID:    b.nodeID,
		Timestamp: time.Now().UTC(),
		Entries:   make([]models.LogEntry, len(b.buffer)),
		Count:     len(b.buffer),
	}
	copy(batch.Entries, b.buffer)

	// Non-blocking send
	select {
	case b.batchCh <- batch:
		log.Printf("batcher: flushed batch with %d entries", len(b.buffer))
	default:
		log.Printf("batcher: batch channel full, dropping %d entries", len(b.buffer))
	}

	// Clear buffer
	b.buffer = b.buffer[:0]
}
