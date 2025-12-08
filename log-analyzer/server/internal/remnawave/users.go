package remnawave

import (
	"context"
	"fmt"
)

// GetUsers fetches all users from Remnawave
func (c *Client) GetUsers(ctx context.Context) (*UsersResponse, error) {
	data, err := c.doRequest(ctx, "GET", "/api/users?start=0&size=100000", nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*UsersResponse](data)
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
