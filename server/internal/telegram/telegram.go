package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
)

// Bot sends alerts to Telegram, optionally routing each alert category to its
// own forum topic (message_thread_id) within a single supergroup chat.
type Bot struct {
	token   string
	chatID  string
	alertCh chan *models.Alert
	client  *http.Client

	// topics maps an alert Category (models.AlertCategory*) to a Telegram forum
	// topic id (message_thread_id). Categories without an entry fall back to
	// defaultTopic. nil/empty means "send everything to the chat's General".
	topics map[string]int

	// defaultTopic is the message_thread_id used for alerts whose category has
	// no explicit topic mapping. 0 means the chat's General topic / a regular
	// (non-forum) chat.
	defaultTopic int
}

// New creates a new Telegram bot.
//
// topics maps alert categories to forum topic ids; pass nil to send everything
// to one chat. defaultTopic is the fallback topic id for uncategorised alerts
// (0 = General / non-forum chat).
func New(token, chatID string, topics map[string]int, defaultTopic int, alertCh chan *models.Alert) *Bot {
	return &Bot{
		token:        token,
		chatID:       chatID,
		alertCh:      alertCh,
		topics:       topics,
		defaultTopic: defaultTopic,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Start begins processing alerts
func (b *Bot) Start(ctx context.Context) {
	if len(b.topics) > 0 {
		log.Printf("telegram: bot started with topic routing: %v (default thread %d)", b.topics, b.defaultTopic)
	} else {
		log.Println("telegram: bot started")
	}

	for {
		select {
		case <-ctx.Done():
			return
		case alert := <-b.alertCh:
			if err := b.sendMessage(alert.Message, b.threadFor(alert.Category)); err != nil {
				log.Printf("telegram: failed to send message: %v", err)
			}
		}
	}
}

// threadFor resolves the forum topic id for an alert category, falling back to
// the configured default topic when the category has no explicit mapping.
func (b *Bot) threadFor(category string) int {
	if category != "" {
		if id, ok := b.topics[category]; ok {
			return id
		}
	}
	return b.defaultTopic
}

// sendMessage sends a message to the Telegram chat. When threadID > 0 the
// message is posted into that forum topic (message_thread_id).
func (b *Bot) sendMessage(text string, threadID int) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", b.token)

	payload := map[string]interface{}{
		"chat_id":    b.chatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	if threadID > 0 {
		payload["message_thread_id"] = threadID
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := b.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status %d", resp.StatusCode)
	}

	return nil
}

// SendTestMessage sends a test message to the default topic.
func (b *Bot) SendTestMessage() error {
	return b.sendMessage("✅ Xray Log Analyzer подключен к Telegram!", b.defaultTopic)
}
