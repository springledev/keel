package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// chatChannel posts a JSON text message to a chat webhook (Discord or
// Slack). The URL is a secret and never appears in errors.
type chatChannel struct {
	typ    string
	url    string
	field  string // JSON field carrying the text
	client *http.Client
}

// DiscordChannel posts events to a Discord webhook URL.
type DiscordChannel struct{ chatChannel }

// SlackChannel posts events to a Slack incoming-webhook URL.
type SlackChannel struct{ chatChannel }

// NewDiscordChannel creates a Discord channel; url is a secret.
func NewDiscordChannel(url string) *DiscordChannel {
	return &DiscordChannel{chatChannel{typ: "discord", url: url, field: "content", client: clientWithTimeout()}}
}

// NewSlackChannel creates a Slack channel; url is a secret.
func NewSlackChannel(url string) *SlackChannel {
	return &SlackChannel{chatChannel{typ: "slack", url: url, field: "text", client: clientWithTimeout()}}
}

// Type returns "discord" or "slack".
func (c *chatChannel) Type() string { return c.typ }

// Send posts the event. Neither the error nor logs built from it contain
// the webhook URL (see stripURLSecret).
func (c *chatChannel) Send(ctx context.Context, event Event) error {
	if c.url == "" {
		return fmt.Errorf("%s: %s webhook URL not configured", event.Service, c.typ)
	}
	text := event.Message
	if event.Title != "" {
		text = event.Title + "\n" + text
	}
	if event.Detail != "" {
		text += "\n" + event.Detail
	}
	data, err := json.Marshal(map[string]string{c.field: text})
	if err != nil {
		return fmt.Errorf("%s: marshaling %s payload: %w", event.Service, c.typ, err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%s: creating %s request: %w", event.Service, c.typ, stripURLSecret(err))
	}
	req.Header.Set("Content-Type", "application/json")
	client := c.client
	if client == nil {
		client = clientWithTimeout()
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: sending to %s: %w", event.Service, c.typ, stripURLSecret(err))
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 512)) //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s returned status %d", event.Service, c.typ, resp.StatusCode)
	}
	return nil
}
