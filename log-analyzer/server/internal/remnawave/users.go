package remnawave

import (
	"context"
	"fmt"
)

// GetUsers fetches all users from Remnawave with pagination
func (c *Client) GetUsers(ctx context.Context) (*UsersResponse, error) {
	const pageSize = 1000
	var allUsers []User
	start := 0

	for {
		endpoint := fmt.Sprintf("/api/users?start=%d&size=%d", start, pageSize)
		data, err := c.doRequest(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, err
		}

		resp, err := parseResponse[*UsersResponse](data)
		if err != nil {
			return nil, err
		}

		allUsers = append(allUsers, resp.Users...)

		// If we got less than pageSize, we've reached the end
		if len(resp.Users) < pageSize {
			return &UsersResponse{
				Users: allUsers,
				Total: resp.Total,
			}, nil
		}

		start += pageSize
	}
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
