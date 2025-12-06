package blacklist

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Blacklist manages the list of blocked domains
type Blacklist struct {
	filePath     string
	remoteURL    string // Optional URL to fetch domains from
	reloadInt    time.Duration
	domains      map[string]bool // exact match
	suffixes     []string        // wildcard match (*.example.com)
	mu           sync.RWMutex
	lastModify   time.Time
	lastRemote   time.Time // Last successful remote fetch
	remoteUpdate time.Duration
}

// New creates a new Blacklist
func New(filePath string, reloadInterval time.Duration) *Blacklist {
	return &Blacklist{
		filePath:     filePath,
		reloadInt:    reloadInterval,
		domains:      make(map[string]bool),
		suffixes:     make([]string, 0),
		remoteUpdate: 24 * time.Hour, // Update from remote once a day
	}
}

// SetRemoteURL sets a remote URL to fetch additional domains from
func (b *Blacklist) SetRemoteURL(url string) {
	b.mu.Lock()
	b.remoteURL = url
	b.mu.Unlock()
}

// Start loads the blacklist and starts auto-reload
func (b *Blacklist) Start(ctx context.Context) error {
	// Initial load from file
	if err := b.reload(); err != nil {
		log.Printf("blacklist: local file load error (will continue): %v", err)
	}

	// Initial load from remote URL
	if b.remoteURL != "" {
		if err := b.fetchRemote(); err != nil {
			log.Printf("blacklist: remote fetch error (will continue): %v", err)
		}
	}

	// Start reload goroutine
	go func() {
		ticker := time.NewTicker(b.reloadInt)
		remoteTicker := time.NewTicker(b.remoteUpdate)
		defer ticker.Stop()
		defer remoteTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := b.reloadIfModified(); err != nil {
					log.Printf("blacklist: reload error: %v", err)
				}
			case <-remoteTicker.C:
				if b.remoteURL != "" {
					if err := b.fetchRemote(); err != nil {
						log.Printf("blacklist: remote fetch error: %v", err)
					}
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

// fetchRemote fetches domains from remote URL and merges with existing
func (b *Blacklist) fetchRemote() error {
	b.mu.RLock()
	url := b.remoteURL
	b.mu.RUnlock()

	if url == "" {
		return nil
	}

	log.Printf("blacklist: fetching from %s", url)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("fetch error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	// Limit read to 50MB
	limited := io.LimitReader(resp.Body, 50*1024*1024)

	newDomains := make(map[string]bool)
	scanner := bufio.NewScanner(limited)
	// Increase buffer for long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		domain := strings.ToLower(line)
		// Skip wildcards from remote (we handle them locally)
		if strings.HasPrefix(domain, "*.") {
			continue
		}
		// Skip invalid domains
		if strings.ContainsAny(domain, " \t/\\") {
			continue
		}

		newDomains[domain] = true
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan error: %w", err)
	}

	// Merge with existing
	b.mu.Lock()
	added := 0
	for domain := range newDomains {
		if !b.domains[domain] {
			b.domains[domain] = true
			added++
		}
	}
	b.lastRemote = time.Now()
	total := len(b.domains)
	b.mu.Unlock()

	log.Printf("blacklist: fetched %d domains from remote, added %d new (total: %d)",
		len(newDomains), added, total)

	return nil
}

// ForceRemoteUpdate forces immediate update from remote URL
func (b *Blacklist) ForceRemoteUpdate() error {
	return b.fetchRemote()
}

// Stats returns blacklist statistics
func (b *Blacklist) Stats() (exact int, wildcards int, lastRemote time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.domains), len(b.suffixes), b.lastRemote
}
