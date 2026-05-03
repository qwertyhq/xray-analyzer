package remnawave

import (
	"context"
	"fmt"
	"time"
)

// GetNodes fetches all nodes
func (c *Client) GetNodes(ctx context.Context) ([]Node, error) {
	data, err := c.doRequest(ctx, "GET", "/api/nodes", nil)
	if err != nil {
		return nil, err
	}
	resp, err := parseResponse[[]Node](data)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetNodeByUUID fetches a specific node by UUID
func (c *Client) GetNodeByUUID(ctx context.Context, uuid string) (*Node, error) {
	data, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/nodes/%s", uuid), nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*Node](data)
}

// GetNodesUsageByRange fetches node usage statistics for a date range
func (c *Client) GetNodesUsageByRange(ctx context.Context, start, end time.Time) ([]NodeUsage, error) {
	endpoint := fmt.Sprintf("/api/nodes/usage/range?start=%s&end=%s",
		start.Format(time.RFC3339),
		end.Format(time.RFC3339),
	)
	data, err := c.doRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[[]NodeUsage](data)
}

// GetNodesRealtimeUsage fetches realtime node usage
func (c *Client) GetNodesRealtimeUsage(ctx context.Context) ([]NodeUsage, error) {
	data, err := c.doRequest(ctx, "GET", "/api/nodes/usage/realtime", nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[[]NodeUsage](data)
}
