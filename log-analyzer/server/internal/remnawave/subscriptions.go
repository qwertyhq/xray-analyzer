package remnawave

import (
	"context"
	"fmt"
)

// GetSubscriptionHistory fetches subscription request history with pagination
func (c *Client) GetSubscriptionHistory(ctx context.Context, start, size int) (*SubscriptionRequestsResponse, error) {
	endpoint := fmt.Sprintf("/api/subscription-request-history?start=%d&size=%d", start, size)
	data, err := c.doRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*SubscriptionRequestsResponse](data)
}

// GetSubscriptionHistoryStats fetches subscription request statistics
func (c *Client) GetSubscriptionHistoryStats(ctx context.Context) (*SubscriptionRequestStats, error) {
	data, err := c.doRequest(ctx, "GET", "/api/subscription-request-history/stats", nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*SubscriptionRequestStats](data)
}

// GetUserSubscriptionHistory fetches subscription history for a specific user
func (c *Client) GetUserSubscriptionHistory(ctx context.Context, userUUID string) ([]SubscriptionRequest, error) {
	data, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/users/%s/subscription-request-history", userUUID), nil)
	if err != nil {
		return nil, err
	}
	resp, err := parseResponse[*SubscriptionRequestsResponse](data)
	if err != nil {
		return nil, err
	}
	return resp.Records, nil
}
