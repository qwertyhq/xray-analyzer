// Package rediscache is a thin, typed JSON-backed wrapper around go-redis.
//
// It exists so storage/analyzer code can cache arbitrary structs across
// restarts without sprinkling json.Marshal / Unmarshal and error handling
// in every call site. The in-process memory cache (internal/cache) stays
// the L1 — Redis is the L2 that survives rebuilds.
package rediscache

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client wraps a Redis client with JSON helpers. A nil *Client is safe and
// behaves as "no cache" — every call returns a miss / no-op. That lets the
// rest of the codebase treat Redis as optional: works with or without.
type Client struct {
	r      *redis.Client
	prefix string
}

// New dials Redis. Empty addr disables it and returns nil. ping attempts are
// bounded — Redis being down shouldn't make analyzer unable to start.
func New(addr, password, keyPrefix string) (*Client, error) {
	if addr == "" {
		return nil, nil
	}
	r := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           0,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := r.Ping(ctx).Err(); err != nil {
		_ = r.Close()
		return nil, err
	}
	if keyPrefix != "" && keyPrefix[len(keyPrefix)-1] != ':' {
		keyPrefix += ":"
	}
	return &Client{r: r, prefix: keyPrefix}, nil
}

// Close releases the underlying connection. Safe on nil.
func (c *Client) Close() error {
	if c == nil || c.r == nil {
		return nil
	}
	return c.r.Close()
}

// GetJSON unmarshals the value at key into dest. Returns (false, nil) on
// miss, (false, err) on decode/transport error. Safe on nil receiver.
func (c *Client) GetJSON(ctx context.Context, key string, dest interface{}) (bool, error) {
	if c == nil || c.r == nil {
		return false, nil
	}
	b, err := c.r.Get(ctx, c.prefix+key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		return false, err
	}
	if err := json.Unmarshal(b, dest); err != nil {
		return false, err
	}
	return true, nil
}

// SetJSON marshals value and stores it with TTL. Zero TTL = no expiry.
// Safe on nil receiver (no-op).
func (c *Client) SetJSON(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if c == nil || c.r == nil {
		return nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.r.Set(ctx, c.prefix+key, b, ttl).Err()
}

// Delete removes a key. Safe on nil.
func (c *Client) Delete(ctx context.Context, key string) error {
	if c == nil || c.r == nil {
		return nil
	}
	return c.r.Del(ctx, c.prefix+key).Err()
}

// DeletePrefix removes every key matching "<prefix>*" via SCAN. Safe on nil.
func (c *Client) DeletePrefix(ctx context.Context, keyPrefix string) error {
	if c == nil || c.r == nil {
		return nil
	}
	match := c.prefix + keyPrefix + "*"
	iter := c.r.Scan(ctx, 0, match, 100).Iterator()
	var batch []string
	for iter.Next(ctx) {
		batch = append(batch, iter.Val())
		if len(batch) >= 500 {
			if err := c.r.Del(ctx, batch...).Err(); err != nil {
				return err
			}
			batch = batch[:0]
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	if len(batch) > 0 {
		return c.r.Del(ctx, batch...).Err()
	}
	return nil
}

// Ping verifies the connection. Safe on nil (returns nil).
func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.r == nil {
		return nil
	}
	return c.r.Ping(ctx).Err()
}
