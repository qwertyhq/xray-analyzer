package remnawave

import (
	"context"
	"fmt"
	"log"
	"time"
)

// GetUsers fetches all users from Remnawave with pagination.
//
// Hardened against the panel's intermittent "A024 / Get all users error" 500s
// on deep offsets: each page is retried with backoff, and a page that still
// fails after retries is skipped (logged) rather than aborting the whole sweep
// — a single bad page no longer leaves remna_users empty. The loop is bounded
// by the reported total, and paces between pages to avoid hammering the API.
func (c *Client) GetUsers(ctx context.Context) (*UsersResponse, error) {
	const (
		pageSize    = 1000
		maxAttempts = 3
		pagePause   = 200 * time.Millisecond
	)

	var allUsers []User
	total := -1
	start := 0

	for {
		if total >= 0 && start >= total {
			break
		}

		var resp *UsersResponse
		var lastErr error
		for attempt := 0; attempt < maxAttempts; attempt++ {
			endpoint := fmt.Sprintf("/api/users?start=%d&size=%d", start, pageSize)
			data, err := c.doRequest(ctx, "GET", endpoint, nil)
			if err == nil {
				resp, lastErr = parseResponse[*UsersResponse](data)
				if lastErr == nil {
					break
				}
			} else {
				lastErr = err
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
			}
		}

		if lastErr != nil {
			// Can't continue without a total to bound the loop — fail hard only
			// if even the first page is unreachable.
			if total < 0 {
				return nil, fmt.Errorf("users first page failed: %w", lastErr)
			}
			log.Printf("[remnawave] users page start=%d failed after %d attempts, skipping: %v",
				start, maxAttempts, lastErr)
			start += pageSize
			continue
		}

		if total < 0 {
			total = resp.Total
		}
		allUsers = append(allUsers, resp.Users...)

		// Short page = reached the end (only trustworthy when total is unknown).
		if len(resp.Users) < pageSize {
			break
		}

		start += pageSize
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pagePause):
		}
	}

	return &UsersResponse{Users: allUsers, Total: total}, nil
}

// GetUserByUUID fetches a specific user by UUID
func (c *Client) GetUserByUUID(ctx context.Context, uuid string) (*User, error) {
	data, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/users/%s", uuid), nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*User](data)
}

// GetUserByEmail fetches users by email
func (c *Client) GetUserByEmail(ctx context.Context, email string) ([]User, error) {
	data, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/users/by-email/%s", email), nil)
	if err != nil {
		return nil, err
	}
	resp, err := parseResponse[*UsersResponse](data)
	if err != nil {
		return nil, err
	}
	return resp.Users, nil
}

// GetUserByUsername fetches a user by username
func (c *Client) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	data, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/users/by-username/%s", username), nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*User](data)
}

// GetUserByID fetches a user by numeric ID (the ID used in xray logs)
func (c *Client) GetUserByID(ctx context.Context, id string) (*User, error) {
	data, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/users/by-id/%s", id), nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*User](data)
}
