package blacklist

import (
	"bufio"
	"context"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Blacklist manages the list of blocked domains
type Blacklist struct {
	filePath   string
	reloadInt  time.Duration
	domains    map[string]bool // exact match
	suffixes   []string        // wildcard match (*.example.com)
	mu         sync.RWMutex
	lastModify time.Time
}

// New creates a new Blacklist
func New(filePath string, reloadInterval time.Duration) *Blacklist {
	return &Blacklist{
		filePath:  filePath,
		reloadInt: reloadInterval,
		domains:   make(map[string]bool),
		suffixes:  make([]string, 0),
	}
}

// Start loads the blacklist and starts auto-reload
func (b *Blacklist) Start(ctx context.Context) error {
	// Initial load
	if err := b.reload(); err != nil {
		return err
	}

	// Start reload goroutine
	go func() {
		ticker := time.NewTicker(b.reloadInt)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := b.reloadIfModified(); err != nil {
					log.Printf("blacklist: reload error: %v", err)
				}
			}
		}
	}()

	return nil
}

// Check checks if a domain is blacklisted
// Returns the matched rule or empty string
func (b *Blacklist) Check(domain string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	domain = strings.ToLower(domain)

	// Remove port if present
	if idx := strings.LastIndex(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	// Exact match
	if b.domains[domain] {
		return domain
	}

	// Suffix match (for wildcards)
	for _, suffix := range b.suffixes {
		if strings.HasSuffix(domain, suffix) {
			return "*" + suffix
		}
	}

	return ""
}

// Count returns the number of rules
func (b *Blacklist) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.domains) + len(b.suffixes)
}

// reload loads the blacklist from file
func (b *Blacklist) reload() error {
	file, err := os.Open(b.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	domains := make(map[string]bool)
	suffixes := make([]string, 0)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		line = strings.ToLower(line)

		// Wildcard pattern (*.example.com)
		if strings.HasPrefix(line, "*.") {
			suffix := line[1:] // Keep the dot
			suffixes = append(suffixes, suffix)
		} else {
			domains[line] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	b.domains = domains
	b.suffixes = suffixes
	b.lastModify = info.ModTime()
	b.mu.Unlock()

	log.Printf("blacklist: loaded %d exact domains, %d wildcard patterns",
		len(domains), len(suffixes))

	return nil
}

// reloadIfModified reloads the blacklist if the file was modified
func (b *Blacklist) reloadIfModified() error {
	info, err := os.Stat(b.filePath)
	if err != nil {
		return err
	}

	b.mu.RLock()
	modified := info.ModTime().After(b.lastModify)
	b.mu.RUnlock()

	if modified {
		log.Println("blacklist: file modified, reloading...")
		return b.reload()
	}

	return nil
}
