package remnawave

import (
	"regexp"
	"strings"
)

// Common patterns for parsing note fields
var (
	// Match "key: value" or "key - value" patterns
	keyValuePattern = regexp.MustCompile(`(?i)^([^:=-]+)[:\-=]\s*(.+)$`)

	// Match phone numbers
	phonePattern = regexp.MustCompile(`(?:\+?[0-9]{1,4}[-.\s]?)?(?:\(?[0-9]{1,4}\)?[-.\s]?)?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}`)

	// Match telegram usernames
	telegramPattern = regexp.MustCompile(`@[a-zA-Z][a-zA-Z0-9_]{4,31}`)

	// Match US_ID: <number> pattern (Xray log user ID)
	usIDPattern = regexp.MustCompile(`(?i)US_ID[:\s]*(\d+)`)

	// Common key aliases
	keyAliases = map[string]string{
		"name":       "real_name",
		"имя":        "real_name",
		"фио":        "real_name",
		"телефон":    "phone",
		"phone":      "phone",
		"тел":        "phone",
		"telegram":   "telegram_user",
		"телеграм":   "telegram_user",
		"тг":         "telegram_user",
		"tg":         "telegram_user",
		"payment":    "payment_info",
		"оплата":     "payment_info",
		"pay":        "payment_info",
		"plan":       "plan",
		"тариф":      "plan",
		"пакет":      "plan",
		"expiry":     "expiry_date",
		"срок":       "expiry_date",
		"до":         "expiry_date",
		"expires":    "expiry_date",
		"note":       "notes",
		"notes":      "notes",
		"заметки":    "notes",
		"примечание": "notes",
	}
)

// ParseNote parses the Description/Note field and extracts structured metadata
func ParseNote(note string) *ParsedNote {
	if note == "" {
		return nil
	}

	parsed := &ParsedNote{
		RawText: note,
		Custom:  make(map[string]string),
	}

	// Extract US_ID from anywhere in the note
	if matches := usIDPattern.FindStringSubmatch(note); len(matches) == 2 {
		parsed.USID = matches[1]
	}

	// Split by newlines and process each line
	lines := strings.Split(note, "\n")
	var unmatchedLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try to match key-value pattern
		if matches := keyValuePattern.FindStringSubmatch(line); len(matches) == 3 {
			key := strings.ToLower(strings.TrimSpace(matches[1]))
			value := strings.TrimSpace(matches[2])

			// Try to match against known aliases
			if normalizedKey, ok := keyAliases[key]; ok {
				setField(parsed, normalizedKey, value)
			} else {
				// Store as custom field
				parsed.Custom[key] = value
			}
			continue
		}

		// Try to extract phone number
		if parsed.Phone == "" {
			if phone := phonePattern.FindString(line); phone != "" {
				parsed.Phone = phone
				continue
			}
		}

		// Try to extract telegram username
		if parsed.TelegramUser == "" {
			if tg := telegramPattern.FindString(line); tg != "" {
				parsed.TelegramUser = tg
				continue
			}
		}

		// Unmatched line
		unmatchedLines = append(unmatchedLines, line)
	}

	// If there are unmatched lines and no notes set, use first unmatched as name
	if len(unmatchedLines) > 0 {
		if parsed.RealName == "" && !containsKeywords(unmatchedLines[0]) {
			parsed.RealName = unmatchedLines[0]
			unmatchedLines = unmatchedLines[1:]
		}

		// Remaining lines go to notes
		if len(unmatchedLines) > 0 && parsed.Notes == "" {
			parsed.Notes = strings.Join(unmatchedLines, "; ")
		}
	}

	return parsed
}

// setField sets a field on ParsedNote by name
func setField(p *ParsedNote, fieldName, value string) {
	switch fieldName {
	case "real_name":
		p.RealName = value
	case "phone":
		p.Phone = value
	case "telegram_user":
		p.TelegramUser = value
	case "payment_info":
		p.PaymentInfo = value
	case "plan":
		p.Plan = value
	case "expiry_date":
		p.ExpiryDate = value
	case "notes":
		p.Notes = value
	default:
		p.Custom[fieldName] = value
	}
}

// containsKeywords checks if the line contains common keywords
func containsKeywords(line string) bool {
	lower := strings.ToLower(line)
	keywords := []string{"http", "://", "тариф", "план", "до ", "оплат", "payment"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// ParseNotesForUsers parses notes for all users
func ParseNotesForUsers(users []*User) {
	for _, u := range users {
		if u.Description != nil && *u.Description != "" {
			u.ParsedNote = ParseNote(*u.Description)
		}
	}
}
