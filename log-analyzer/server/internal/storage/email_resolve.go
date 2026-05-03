package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// ResolveUserEmailToUUID converts a raw xray user_email identifier into a
// Remnawave user UUID for storage. Resolution order:
//  1. If the input is already a valid UUID, returns it unchanged.
//  2. Looks up remna_users by username or email.
//  3. If numeric, looks up remna_users by id (bigint), then us_id (text),
//     then by US_ID pattern embedded in description (legacy fallback).
//  4. Falls back to a deterministic SHA-1 derivative of the input,
//     additionally writing (uuid, original_email) into email_index so the UI
//     can resolve the original string later.
//
// Returns a uuid that is safe to insert into user_email columns.
func (s *Storage) ResolveUserEmailToUUID(ctx context.Context, email string) (uuid.UUID, error) {
	if email == "" {
		return uuid.Nil, fmt.Errorf("empty email")
	}

	// Step 1: already a valid UUID — pass through.
	if id, err := uuid.Parse(email); err == nil {
		return id, nil
	}

	// Step 2: direct match by username or email in remna_users.
	var idStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT uuid::text FROM remna_users WHERE username = $1 OR email = $1 LIMIT 1
	`, email).Scan(&idStr)
	if err == nil && idStr != "" {
		if id, perr := uuid.Parse(idStr); perr == nil {
			return id, nil
		}
	}

	// Step 3: numeric → look up by remna_users.id (bigint, primary mapping
	// from xray's email field), then us_id (text), then description LIKE.
	if isNumericString(email) {
		// 3a: remna_users.id — the bigint identifier xray emits as `email`.
		err = s.db.QueryRowContext(ctx, `
			SELECT uuid::text FROM remna_users WHERE id = $1::bigint LIMIT 1
		`, email).Scan(&idStr)
		if err == nil && idStr != "" {
			if id, perr := uuid.Parse(idStr); perr == nil {
				return id, nil
			}
		}

		// 3b: us_id — SHM-side identifier in dedicated text column.
		err = s.db.QueryRowContext(ctx, `
			SELECT uuid::text FROM remna_users WHERE us_id = $1 LIMIT 1
		`, email).Scan(&idStr)
		if err == nil && idStr != "" {
			if id, perr := uuid.Parse(idStr); perr == nil {
				return id, nil
			}
		}

		// 3c: description LIKE '%US_ID: N%' — legacy pattern for users
		// whose us_id column wasn't parsed out at sync time.
		err = s.db.QueryRowContext(ctx, `
			SELECT uuid::text FROM remna_users WHERE description LIKE $1 LIMIT 1
		`, "%US_ID: "+email+"%").Scan(&idStr)
		if err == nil && idStr != "" {
			if id, perr := uuid.Parse(idStr); perr == nil {
				return id, nil
			}
		}
	}

	// Step 4: SHA-1 fallback + register in email_index for reverse lookup.
	derived := emailToUUID(email)
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO email_index (uuid, original_email) VALUES ($1, $2)
		ON CONFLICT (uuid) DO NOTHING
	`, derived, email)
	return derived, nil
}
