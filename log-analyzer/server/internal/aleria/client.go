package aleria

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	DefaultBaseURL = "https://aleria.com/_inference/v1"
	DefaultModel   = "default"
)

// Client is the Aleria AI API client
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new Aleria AI client
func NewClient(apiKey string) *Client {
	return &Client{
		baseURL: DefaultBaseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// IsConfigured returns true if the client has an API key
func (c *Client) IsConfigured() bool {
	return c.apiKey != ""
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ToolCall represents a function call from the model
type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// ChatRequest represents a chat completion request
type ChatRequest struct {
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
}

// ChatRequestWithTools represents a chat request with function calling
type ChatRequestWithTools struct {
	Messages    []map[string]interface{} `json:"messages"`
	Tools       []map[string]interface{} `json:"tools,omitempty"`
	Temperature float64                  `json:"temperature,omitempty"`
	MaxTokens   int                      `json:"max_tokens,omitempty"`
}

// ChatResponse represents a chat completion response
type ChatResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role      string     `json:"role"`
			Content   string     `json:"content"`
			ToolCalls []ToolCall `json:"tool_calls,omitempty"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// Chat sends a chat completion request
func (c *Client) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("aleria: API key not configured")
	}

	// Set defaults
	if req.Temperature == 0 {
		req.Temperature = 0.7
	}
	if req.MaxTokens == 0 {
		req.MaxTokens = 2000
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("aleria: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("aleria: create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("aleria: send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("aleria: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aleria: API error %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("aleria: unmarshal response: %w", err)
	}

	return &chatResp, nil
}

// ChatWithTools sends a chat request with function calling support
func (c *Client) ChatWithTools(ctx context.Context, messages []map[string]interface{}, tools []map[string]interface{}) (*ChatResponse, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("aleria: API key not configured")
	}

	req := ChatRequestWithTools{
		Messages:    messages,
		Tools:       tools,
		Temperature: 0.3,
		MaxTokens:   4000,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("aleria: marshal request: %w", err)
	}

	log.Printf("[aleria] API request (truncated): %s", truncateString(string(body), 2000))

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("aleria: create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("aleria: send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("aleria: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aleria: API error %d: %s", resp.StatusCode, string(respBody))
	}

	log.Printf("[aleria] API response: %s", string(respBody))

	var chatResp ChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("aleria: unmarshal response: %w", err)
	}

	return &chatResp, nil
}

// GetContent extracts the content from the first choice
func (r *ChatResponse) GetContent() string {
	if len(r.Choices) > 0 {
		return r.Choices[0].Message.Content
	}
	return ""
}

// StreamDelta represents a chunk from streaming response
type StreamDelta struct {
	Content      string     `json:"content,omitempty"`
	ToolCalls    []ToolCall `json:"tool_calls,omitempty"`
	FinishReason string     `json:"finish_reason,omitempty"`
}

// StreamChunk represents a single chunk from SSE stream
type StreamChunk struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role      string     `json:"role,omitempty"`
			Content   string     `json:"content,omitempty"`
			ToolCalls []ToolCall `json:"tool_calls,omitempty"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

// ChatStream sends a streaming chat request and returns chunks via channel
func (c *Client) ChatStream(ctx context.Context, messages []map[string]interface{}, tools []map[string]interface{}, onChunk func(content string, done bool)) error {
	if !c.IsConfigured() {
		return fmt.Errorf("aleria: API key not configured")
	}

	req := map[string]interface{}{
		"messages":    messages,
		"temperature": 0.3,
		"max_tokens":  4000,
		"stream":      true,
	}
	if len(tools) > 0 {
		req["tools"] = tools
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("aleria: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("aleria: create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("aleria: send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("aleria: API error %d: %s", resp.StatusCode, string(respBody))
	}

	reader := bufio.NewReader(resp.Body)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				onChunk("", true)
				return nil
			}
			return fmt.Errorf("aleria: read stream: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			onChunk("", true)
			return nil
		}

		var chunk StreamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue // Skip malformed chunks
		}

		if len(chunk.Choices) > 0 {
			delta := chunk.Choices[0].Delta
			if delta.Content != "" {
				onChunk(delta.Content, false)
			}
			if chunk.Choices[0].FinishReason != nil && *chunk.Choices[0].FinishReason == "stop" {
				onChunk("", true)
				return nil
			}
		}
	}
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
