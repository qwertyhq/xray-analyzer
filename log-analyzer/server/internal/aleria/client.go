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
	// DefaultBaseURL points to Aleria's hosted inference endpoint, but any
	// OpenAI-compatible /v1 base URL works (OpenAI, Together, OpenRouter,
	// local llama.cpp/vLLM, etc.) — the wire format is identical.
	DefaultBaseURL = "https://aleria.com/_inference/v1"
	DefaultModel   = "default"
)

// Client is an OpenAI-compatible chat-completions client. It speaks the
// standard /v1/chat/completions wire format so any compatible endpoint
// can be plugged in via env (OPENAI_BASE_URL, OPENAI_MODEL, OPENAI_API_KEY).
type Client struct {
	baseURL    string
	apiKey     string
	model      string
	httpClient *http.Client
}

// NewClient creates a new client. Empty baseURL falls back to DefaultBaseURL,
// empty model falls back to DefaultModel — this preserves backward
// compatibility with the original Aleria-only configuration.
func NewClient(apiKey, baseURL, model string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if model == "" {
		model = DefaultModel
	}
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		model:   model,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// Model returns the configured model name.
func (c *Client) Model() string { return c.model }

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

// ChatRequest represents a chat completion request.
// Model is set automatically from Client.model when sent via Chat().
type ChatRequest struct {
	Model       string    `json:"model,omitempty"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
}

// ChatRequestWithTools represents a chat request with function calling.
type ChatRequestWithTools struct {
	Model       string                   `json:"model,omitempty"`
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
	if req.Model == "" {
		req.Model = c.model
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
		Model:       c.model,
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
		"model":       c.model,
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
