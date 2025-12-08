package remnawave

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
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

// DeleteAllUserHwidDevices deletes all HWID devices for a specific user
func (c *Client) DeleteAllUserHwidDevices(ctx context.Context, userUUID string) (*HwidDevicesResponse, error) {
	payload := map[string]string{"userUuid": userUUID}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	log.Printf("[remnawave-client] DELETE ALL HWID - sending payload: %s", string(body))

	data, err := c.doRequest(ctx, "POST", "/api/hwid/devices/delete-all", bytes.NewReader(body))
	if err != nil {
		log.Printf("[remnawave-client] DELETE ALL HWID - error: %v", err)
		return nil, err
	}

	log.Printf("[remnawave-client] DELETE ALL HWID - response: %s", string(data))

	return parseResponse[*HwidDevicesResponse](data)
}
