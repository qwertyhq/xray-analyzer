package remnawave

import (
	"context"
)

// GetSystemStats fetches system statistics
func (c *Client) GetSystemStats(ctx context.Context) (*SystemStats, error) {
	data, err := c.doRequest(ctx, "GET", "/api/system/stats", nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*SystemStats](data)
}

// GetHealth checks Remnawave API health
func (c *Client) GetHealth(ctx context.Context) error {
	_, err := c.doRequest(ctx, "GET", "/api/system/health", nil)
	return err
}
