package remnawave

import (
	"context"
	"fmt"
)

// GetAllHwidDevices fetches all HWID devices with pagination
func (c *Client) GetAllHwidDevices(ctx context.Context, start, size int) (*HwidDevicesResponse, error) {
	endpoint := fmt.Sprintf("/api/hwid/devices?start=%d&size=%d", start, size)
	data, err := c.doRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*HwidDevicesResponse](data)
}

// GetUserHwidDevices fetches HWID devices for a specific user
func (c *Client) GetUserHwidDevices(ctx context.Context, userUUID string) (*HwidDevicesResponse, error) {
	data, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/hwid/devices/%s", userUUID), nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*HwidDevicesResponse](data)
}

// GetHwidStats fetches HWID device statistics
func (c *Client) GetHwidStats(ctx context.Context) (*HwidStats, error) {
	data, err := c.doRequest(ctx, "GET", "/api/hwid/devices/stats", nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*HwidStats](data)
}
