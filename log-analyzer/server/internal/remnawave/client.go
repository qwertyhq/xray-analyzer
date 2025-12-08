package remnawave

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Client provides access to Remnawave API
type Client struct {
	baseURL    string
	apiToken   string
	httpClient *http.Client
	mu         sync.RWMutex
}

// NewClient creates a new Remnawave API client
func NewClient(baseURL, apiToken string) *Client {
	return &Client{
		baseURL:  baseURL,
		apiToken: apiToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetCredentials updates the API credentials
func (c *Client) SetCredentials(baseURL, apiToken string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baseURL = baseURL
	c.apiToken = apiToken
}

// IsConfigured returns true if the client has valid credentials
func (c *Client) IsConfigured() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.baseURL != "" && c.apiToken != ""
}

// doRequest performs an authenticated HTTP request to the Remnawave API
func (c *Client) doRequest(ctx context.Context, method, endpoint string, body io.Reader) ([]byte, error) {
	c.mu.RLock()
	baseURL := c.baseURL
	token := c.apiToken
	c.mu.RUnlock()

	if baseURL == "" || token == "" {
		return nil, fmt.Errorf("remnawave client not configured")
	}

	url := baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api error: status %d, body: %s", resp.StatusCode, string(data))
	}

	return data, nil
}

// parseResponse extracts the "response" field from API response
func parseResponse[T any](data []byte) (T, error) {
	var wrapper struct {
		Response T `json:"response"`
	}
	var zero T
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return zero, fmt.Errorf("parse response: %w", err)
	}
	return wrapper.Response, nil
}
