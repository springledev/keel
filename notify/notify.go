// Package notify is the domain-free notification half shared by
// programs that need alerts: the Channel interface, a per-service Notifier, and ntfy,
// generic webhook, Discord, Slack and email channels.
//
// IMPORTANT: Channel secrets (ntfy topic URL, webhook URL) must never
// be stored in a database or logged. Callers read them from
// root-only credential files and pass them to channel constructors.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// EventType describes the kind of notification being sent.
type EventType string

const (
	// EventTest is the test notification a channel's test-send delivers
	// through the very same Send path as real events.
	EventTest EventType = "test"
)

// Event describes a notification event.
type Event struct {
	// Service names what the event is about (a product, host or service).
	Service string
	// Type is the kind of event.
	Type EventType
	// Message is the human-readable event description.
	Message string
	// Detail includes structured information (run ID, state, etc).
	Detail string
	// Severity is "error", "warning", or "info" for display purposes.
	Severity string
	// Timestamp is when the event occurred.
	Timestamp time.Time
	// Title, when set, is the headline channels show instead of a
	// generated one (e.g. "Example test notification").
	Title string
}

// Channel is the interface for a notification delivery mechanism.
type Channel interface {
	// Send delivers the event, returning a non-nil error if delivery
	// failed. ctx bounds how long delivery may block (e.g. so a
	// pending SIGTERM is not held up by a stuck HTTP call while the
	// caller's lock is held).
	Send(ctx context.Context, event Event) error
	// Type returns a short label for this channel (e.g. "ntfy", "webhook").
	Type() string
}

// clientWithTimeout returns an http.Client with a reasonable timeout.
func clientWithTimeout() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
	}
}

// stripURLSecret removes the request URL from an error returned by
// http.NewRequestWithContext or (*http.Client).Do.
//
// Both wrap failures in a *url.Error carrying the full request URL —
// for a Channel, that URL is the ntfy topic or webhook URL, a secret
// read from a root-only credential file  that must never
// reach the DB, logs, or an API response. *url.Error.Error() embeds
// the URL directly, so it can never be logged as-is; this unwraps to
// url.Error.Err instead, which describes the failure ("connection
// refused", "no such host", an invalid-URL parse complaint, ...)
// without repeating the URL that was being requested.
func stripURLSecret(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}

// NtfyChannel sends notifications via ntfy.sh HTTP POST.
// Secrets (topic URL) are passed from the caller and never logged.
type NtfyChannel struct {
	Topic string // ntfy topic URL from credential file
	// Secret is the optional access credential for a protected ntfy
	// server, from the credential store: a bearer token, or — when
	// Username is set — that user's password.
	Secret string
	// Username is the optional ntfy login name
	Username string
	Client   *http.Client // injected for tests; nil defaults to clientWithTimeout()
}

// NewNtfyChannel creates a channel that sends to the given ntfy topic.
// topic must be a full URL read from a root-only credential file.
func NewNtfyChannel(topic string) *NtfyChannel {
	return &NtfyChannel{
		Topic:  topic,
		Client: clientWithTimeout(),
	}
}

// Send delivers the event to ntfy.
//
// Neither the returned error nor any log line built from it may
// contain the ntfy topic URL: it is a secret read from a root-only
// credential file . See stripURLSecret.
func (n *NtfyChannel) Send(ctx context.Context, event Event) error {
	if n.Topic == "" {
		return fmt.Errorf("%s: ntfy topic not configured", event.Service)
	}

	client := n.Client
	if client == nil {
		client = clientWithTimeout()
	}

	// Message body includes all details
	msgBody := event.Message
	if event.Detail != "" {
		msgBody = msgBody + "\n" + event.Detail
	}

	req, err := http.NewRequestWithContext(ctx, "POST", n.Topic, bytes.NewBufferString(msgBody))
	if err != nil {
		return fmt.Errorf("%s: creating ntfy request: %w", event.Service, stripURLSecret(err))
	}

	// Set headers per ntfy API
	title := event.Title
	if title == "" {
		title = fmt.Sprintf("[%s] %s", event.Service, event.Type)
	}
	req.Header.Set("Title", title)
	switch {
	case n.Secret != "" && n.Username != "":
		req.SetBasicAuth(n.Username, n.Secret)
	case n.Secret != "":
		req.Header.Set("Authorization", "Bearer "+n.Secret)
	}
	req.Header.Set("Priority", priorityFromSeverity(event.Severity))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: sending to ntfy: %w", event.Service, stripURLSecret(err))
	}
	defer resp.Body.Close()
	// Drain (without keeping) the body so the connection can be reused;
	// its contents are never included in the error (finding: response
	// bodies must not be echoed into logs).
	io.Copy(io.Discard, io.LimitReader(resp.Body, 512)) //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s: ntfy returned status %d", event.Service, resp.StatusCode)
	}
	return nil
}

// Type returns "ntfy".
func (n *NtfyChannel) Type() string { return "ntfy" }

// WebhookChannel sends notifications via a generic HTTP webhook.
// Secrets (webhook URL) are passed from the caller and never logged.
type WebhookChannel struct {
	URL    string       // webhook URL from credential file
	Client *http.Client // injected for tests; nil defaults to clientWithTimeout()
	// Secret, when set, signs each body: the SignatureHeader header
	// carries "sha256=" and the hex HMAC-SHA256 of the body.
	Secret string
	// SignatureHeader names the signature header; empty means
	// "X-Signature".
	SignatureHeader string

	lastStatus int // HTTP status of the latest delivery, shown on test-send
}

// NewWebhookChannel creates a channel that POSTs to the given URL.
// url must be read from a root-only credential file.
func NewWebhookChannel(url string) *WebhookChannel {
	return &WebhookChannel{
		URL:    url,
		Client: clientWithTimeout(),
	}
}

// webhookPayload is the JSON structure sent to webhooks.
type webhookPayload struct {
	Service   string    `json:"service"`
	Type      EventType `json:"type"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Detail    string    `json:"detail"`
	Timestamp time.Time `json:"timestamp"`
}

// Send delivers the event as JSON to the webhook URL.
//
// Neither the returned error nor any log line built from it may
// contain the webhook URL: it is a secret read from a root-only
// credential file . See stripURLSecret.
func (w *WebhookChannel) Send(ctx context.Context, event Event) error {
	if w.URL == "" {
		return fmt.Errorf("%s: webhook URL not configured", event.Service)
	}

	client := w.Client
	if client == nil {
		client = clientWithTimeout()
	}

	payload := webhookPayload{
		Service:   event.Service,
		Type:      event.Type,
		Severity:  event.Severity,
		Message:   event.Message,
		Detail:    event.Detail,
		Timestamp: event.Timestamp,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%s: marshaling webhook payload: %w", event.Service, err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", w.URL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%s: creating webhook request: %w", event.Service, stripURLSecret(err))
	}
	req.Header.Set("Content-Type", "application/json")
	if w.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.Secret))
		mac.Write(data)
		hdr := w.SignatureHeader
		if hdr == "" {
			hdr = "X-Signature"
		}
		req.Header.Set(hdr, "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	w.lastStatus = 0
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: sending webhook: %w", event.Service, stripURLSecret(err))
	}
	defer resp.Body.Close()
	w.lastStatus = resp.StatusCode
	// Drain (without keeping) the body so the connection can be reused;
	// its contents are never included in the error (finding: response
	// bodies must not be echoed into logs).
	io.Copy(io.Discard, io.LimitReader(resp.Body, 512)) //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s: webhook returned status %d", event.Service, resp.StatusCode)
	}
	return nil
}

// Type returns "webhook".
func (w *WebhookChannel) Type() string { return "webhook" }

// priorityFromSeverity maps severity to ntfy priority values.
func priorityFromSeverity(severity string) string {
	switch severity {
	case "error":
		return "high"
	case "warning":
		return "default"
	default:
		return "low"
	}
}

// ErrNoChannels is returned by Notifier.Send when the event's service
// has no registered delivery channel. It is a loud signal, not a
// silent success: a caller like SweepFreshness must not treat a
// freshness breach as reported when nothing was actually able to
// deliver it, or a service configured after the fact would never
// hear about a breach that happened before its channels existed.
var ErrNoChannels = errors.New("no notifications are set up for this service (set up a notification channel first)")

// Notifier sends events to the channels registered for a service.
type Notifier struct {
	channels map[string][]Channel // keyed by service; multiple channels per service

	// Resolve, when set, is asked for a service's channels at send time
	// whenever none were registered for it up front. This is what lets
	// a long-running a long-running process notify about a service added
	// after it started (from the web UI, say) — or pick up a channel
	// credential file written after startup — without a restart. An
	// error from Resolve is returned from Send, never swallowed.
	Resolve func(service string) ([]Channel, error)
}

// NewNotifier creates a new notifier with empty channel registry.
func NewNotifier() *Notifier {
	return &Notifier{
		channels: make(map[string][]Channel),
	}
}

// RegisterChannel registers a delivery channel for a service. Multiple
// channels can be registered per service; each Send call delivers to all.
func (n *Notifier) RegisterChannel(service string, ch Channel) {
	if n.channels == nil {
		n.channels = make(map[string][]Channel)
	}
	n.channels[service] = append(n.channels[service], ch)
}

// Send delivers an event to all registered channels for that service.
// If delivery fails on any channel, every failure is collected and
// returned together (via errors.Join) so one channel's outage can
// never hide another's — the isolation-of-failure principle. All channels are attempted
// regardless of individual failures.
//
// If the service has no registered channel at all, Send returns
// ErrNoChannels rather than silently succeeding: notifications are
// optional to configure, but once a caller asks to send one, "nobody
// was listening" must be visible, not indistinguishable from success.
func (n *Notifier) Send(ctx context.Context, event Event) error {
	chs := n.channels[event.Service]
	if len(chs) == 0 && n.Resolve != nil {
		var err error
		if chs, err = n.Resolve(event.Service); err != nil {
			return fmt.Errorf("%s: loading notification channels: %w", event.Service, err)
		}
	}
	if len(chs) == 0 {
		return fmt.Errorf("%s: %w", event.Service, ErrNoChannels)
	}

	var errs []error
	for _, ch := range chs {
		if err := ch.Send(ctx, event); err != nil {
			errs = append(errs, fmt.Errorf("%s channel: %w", ch.Type(), err))
		}
	}

	return errors.Join(errs...)
}
