package tailer

import (
	"context"
	"log"

	"github.com/nxadm/tail"
	"github.com/xray-log-analyzer/agent/internal/models"
	"github.com/xray-log-analyzer/agent/internal/parser"
)

// Tailer watches a log file and emits parsed entries
type Tailer struct {
	filePath string
	parser   *parser.Parser
	entryCh  chan *models.LogEntry
}

// New creates a new Tailer
func New(filePath string, entryCh chan *models.LogEntry) *Tailer {
	return &Tailer{
		filePath: filePath,
		parser:   parser.New(),
		entryCh:  entryCh,
	}
}

// Start begins tailing the log file
func (t *Tailer) Start(ctx context.Context) error {
	cfg := tail.Config{
		Follow:    true,  // Follow file like tail -f
		ReOpen:    true,  // Reopen file if rotated (logrotate support)
		MustExist: false, // Don't fail if file doesn't exist yet
		Poll:      false, // Use inotify instead of polling
		Location: &tail.SeekInfo{ // Start from end of file
			Offset: 0,
			Whence: 2, // SEEK_END
		},
	}

	tailer, err := tail.TailFile(t.filePath, cfg)
	if err != nil {
		return err
	}

	go func() {
		defer tailer.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("tailer: shutting down")
				return

			case line, ok := <-tailer.Lines:
				if !ok {
					log.Println("tailer: lines channel closed")
					return
				}

				if line.Err != nil {
					log.Printf("tailer: error reading line: %v", line.Err)
					continue
				}

				if line.Text == "" {
					continue
				}

				entry, err := t.parser.ParseLine(line.Text)
				if err != nil {
					// Skip unparseable lines (could be startup messages, etc.)
					continue
				}

				// Non-blocking send
				select {
				case t.entryCh <- entry:
				default:
					log.Println("tailer: entry channel full, dropping entry")
				}
			}
		}
	}()

	return nil
}
