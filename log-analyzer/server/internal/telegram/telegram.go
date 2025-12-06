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

// Bot sends alerts to Telegram
type Bot struct {
	token   string
	chatID  string
	alertCh chan *models.Alert
	client  *http.Client
}

// New creates a new Telegram bot
func New(token, chatID string, alertCh chan *models.Alert) *Bot {
	return &Bot{
		token:   token,
		chatID:  chatID,
		alertCh: alertCh,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Start begins processing alerts
func (b *Bot) Start(ctx context.Context) {
	log.Println("telegram: bot started")

	for {
		select {
		case <-ctx.Done():
			return
		case alert := <-b.alertCh:
			if err := b.sendMessage(alert.Message); err != nil {
				log.Printf("telegram: failed to send message: %v", err)
			}
		}
	}
}

// sendMessage sends a message to the Telegram chat
func (b *Bot) sendMessage(text string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", b.token)

	payload := map[string]interface{}{
		"chat_id":    b.chatID,
		"text":       text,
		"parse_mode": "HTML",
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

// SendTestMessage sends a test message
func (b *Bot) SendTestMessage() error {
	return b.sendMessage("✅ Xray Log Analyzer подключен к Telegram!")
}
