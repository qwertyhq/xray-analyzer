package storage

import "time"

// Date/time formats used by SQLite
var dateFormats = []string{
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05Z",
	time.RFC3339,
	time.RFC3339Nano,
}

// parseDateTime parses a date/time string from SQLite into time.Time
func parseDateTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, format := range dateFormats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// parseDateTimePtr parses a date/time string and returns a pointer (nil if empty)
func parseDateTimePtr(s string) *time.Time {
	if s == "" {
		return nil
	}
	t := parseDateTime(s)
	if t.IsZero() {
		return nil
	}
	return &t
}
