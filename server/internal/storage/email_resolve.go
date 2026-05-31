package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// ResolveUUIDUsernames batch-resolves Remnawave UUIDs to usernames straight
// from remna_users. The dashboard's in-memory resolver only knows users loaded
// into the (now-throttled) full sync, so UUID-keyed rows like anomalies showed
// the raw UUID when the user wasn't cached. remna_users is authoritative and
// gets populated on-demand, so a direct DB lookup resolves everyone present.
// Non-UUID / unknown ids are simply absent from the returned map.
func (s *Storage) ResolveUUIDUsernames(ctx context.Context, ids []string) (map[string]string, error) {
	out := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	// Keep only well-formed UUIDs so the ::uuid[] cast can't error on a stray
	// hash/numeric id.
	valid := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if _, err := uuid.Parse(id); err == nil {
			valid = append(valid, id)
		}
	}
	if len(valid) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT uuid::text, username
		FROM remna_users
		WHERE uuid = ANY($1::uuid[]) AND username <> ''
	`, valid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, username string
		if err := rows.Scan(&id, &username); err != nil {
			continue
		}
		out[id] = username
	}
	return out, rows.Err()
}

// UserResolver resolves a numeric xray-email id (e.g. "791947") to a Remnawave
// user UUID on demand, fetching from the panel and persisting into remna_users
// when the id isn't cached. Implemented by *remnawave.SyncService and wired in
// via SetUserResolver. Kept as a local interface so storage doesn't import the
// remnawave package (the dependency runs the other way).
type UserResolver interface {
	ResolveNumericID(ctx context.Context, id string) (string, bool)
}

// SetUserResolver wires the on-demand numeric-id resolver used by
// ResolveUserEmailToUUID step 3d. Safe to leave nil (falls back to the SHA-1
// derivation, preserving pre-resolver behaviour).
func (s *Storage) SetUserResolver(r UserResolver) {
	s.userResolver = r
}

// cacheResolvedEmail stores a positive email→uuid mapping, clearing the cache
// wholesale if it grows past the cap (entries are cheap to re-resolve).
func (s *Storage) cacheResolvedEmail(email string, id uuid.UUID) {
	if s.userUUIDCache == nil {
		return
	}
	s.userUUIDCacheMu.Lock()
	if len(s.userUUIDCache) >= userUUIDCacheMax {
		s.userUUIDCache = make(map[string]uuid.UUID)
	}
	s.userUUIDCache[email] = id
	s.userUUIDCacheMu.Unlock()
}

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

	// Step 1b: positive in-memory cache (raw email → resolved UUID). Avoids a
	// DB round-trip per write for hot users; mirrors nodeIDCache.
	if s.userUUIDCache != nil {
		s.userUUIDCacheMu.RLock()
		cached, ok := s.userUUIDCache[email]
		s.userUUIDCacheMu.RUnlock()
		if ok {
			return cached, nil
		}
	}

	// Step 2: direct match by username or email in remna_users.
	var idStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT uuid::text FROM remna_users WHERE username = $1 OR email = $1 LIMIT 1
	`, email).Scan(&idStr)
	if err == nil && idStr != "" {
		if id, perr := uuid.Parse(idStr); perr == nil {
			s.cacheResolvedEmail(email, id)
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

		// 3d: on-demand resolve. remna_users no longer holds the full fleet
		// (the per-minute bulk sweep was dropped because it 500'd the panel),
		// so an id missing above is the common case for an active user. Ask the
		// resolver to fetch+persist this single user, then it's joinable here
		// and on the dashboard. The resolver caches positives and negatives so
		// this isn't a per-write API/DB hit.
		if s.userResolver != nil {
			if uuidStr, ok := s.userResolver.ResolveNumericID(ctx, email); ok {
				if id, perr := uuid.Parse(uuidStr); perr == nil {
					return id, nil
				}
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
