package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockChannel is a test implementation of Channel that records every
// event it receives.
type mockChannel struct {
	events *[]Event
}

func (m *mockChannel) Send(ctx context.Context, e Event) error {
	*m.events = append(*m.events, e)
	return nil
}

func (m *mockChannel) Type() string { return "mock" }

// erroringChannel always fails with a fixed error, for testing that
// Notifier.Send joins every channel's failure rather than dropping any
// of them.
type erroringChannel struct {
	err error
	typ string
}

func (e *erroringChannel) Send(ctx context.Context, event Event) error { return e.err }
func (e *erroringChannel) Type() string                                { return e.typ }

func TestNtfyChannel_Send(t *testing.T) {
	tests := []struct {
		name       string
		topic      string
		event      Event
		statusCode int
		wantErr    bool
		wantTitle  string
	}{
		{
			name:  "success",
			topic: "https://ntfy.sh/test-topic",
			event: Event{
				Service:   "immich",
				Type:      EventType("job_failure"),
				Message:   "Backup failed: database lock",
				Detail:    "Run ID: 123",
				Severity:  "error",
				Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			statusCode: 200,
			wantErr:    false,
			wantTitle:  "[immich] job_failure",
		},
		{
			name:    "empty topic",
			topic:   "",
			event:   Event{Service: "test", Type: EventType("job_failure")},
			wantErr: true,
		},
		{
			name:       "http error",
			topic:      "https://ntfy.sh/test-topic",
			statusCode: 500,
			event: Event{
				Service: "test",
				Type:    EventType("job_failure"),
				Message: "Backup failed",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotReq *http.Request
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotReq = r
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			if tt.topic != "" {
				tt.topic = server.URL + "/test-topic"
			}

			ch := NewNtfyChannel(tt.topic)
			ch.Client = server.Client()

			err := ch.Send(context.Background(), tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("Send() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if got := gotReq.Header.Get("Title"); got != tt.wantTitle {
				t.Errorf("Title = %q, want %q", got, tt.wantTitle)
			}
		})
	}
}

func TestNtfyChannel_PriorityMapping(t *testing.T) {
	tests := []struct {
		severity string
		wantPrio string
	}{
		{"error", "high"},
		{"warning", "default"},
		{"info", "low"},
		{"", "low"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := priorityFromSeverity(tt.severity)
			if got != tt.wantPrio {
				t.Errorf("priorityFromSeverity(%q) = %q, want %q", tt.severity, got, tt.wantPrio)
			}
		})
	}
}

func TestWebhookChannel_Send(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		event      Event
		statusCode int
		wantErr    bool
	}{
		{
			name: "success",
			url:  "https://example.com/webhook",
			event: Event{
				Service:   "vaultwarden",
				Type:      EventType("verification_failure"),
				Message:   "Archive check failed",
				Detail:    "tar: checksum mismatch",
				Severity:  "error",
				Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			statusCode: 200,
			wantErr:    false,
		},
		{
			name:    "empty url",
			url:     "",
			event:   Event{Service: "test", Type: EventType("job_failure")},
			wantErr: true,
		},
		{
			name:       "http error",
			url:        "https://example.com/webhook",
			statusCode: 500,
			event:      Event{Service: "test", Type: EventType("job_failure"), Message: "Backup failed"},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPayload map[string]interface{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&gotPayload)
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			if tt.url != "" {
				tt.url = server.URL + "/webhook"
			}

			ch := NewWebhookChannel(tt.url)
			ch.Client = server.Client()

			err := ch.Send(context.Background(), tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("Send() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestChannelSend_NeverLeaksSecretURL pins finding 1 (BLOCKER): a
// transport-level failure (closed port, unparseable URL) wraps the
// request URL into a *url.Error whose Error() text embeds the full
// URL. For a Channel, that URL is the ntfy topic or webhook URL — a
// secret from a root-only credential file (spec rule 2) — so it must
// never survive into the error Send returns. Exercised against both
// channel implementations and both failure shapes.
func TestChannelSend_NeverLeaksSecretURL(t *testing.T) {
	const secret = "s3cret-topic-9f8e7d6c2b1a"

	newChannel := map[string]func(url string) Channel{
		"ntfy":    func(url string) Channel { return NewNtfyChannel(url) },
		"webhook": func(url string) Channel { return NewWebhookChannel(url) },
	}

	for chName, newCh := range newChannel {
		t.Run(chName, func(t *testing.T) {
			t.Run("closed port", func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				secretURL := server.URL + "/" + secret
				server.Close() // the port now refuses connections

				err := newCh(secretURL).Send(context.Background(), Event{Service: "svc", Type: EventType("job_failure")})
				if err == nil {
					t.Fatal("want an error from a closed port")
				}
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error leaks the secret URL: %v", err)
				}
			})

			t.Run("unparseable URL", func(t *testing.T) {
				// A raw control character (newline) in the URL makes
				// net/url refuse to parse it, before any connection is
				// even attempted.
				secretURL := "http://example.com/" + secret + "\n"

				err := newCh(secretURL).Send(context.Background(), Event{Service: "svc", Type: EventType("job_failure")})
				if err == nil {
					t.Fatal("want an error from an unparseable URL")
				}
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error leaks the secret URL: %v", err)
				}
			})
		})
	}
}

// TestChannelSend_ResponseBodyNotEchoed pins finding 2: a non-2xx
// response's body must never be echoed into the returned error — only
// the status code — since a server behind a secret ntfy/webhook URL
// could otherwise leak arbitrary response content (or simply noise)
// into logs.
func TestChannelSend_ResponseBodyNotEchoed(t *testing.T) {
	const bodyMarker = "response-body-should-never-appear-in-error"

	newChannel := map[string]func(url string) Channel{
		"ntfy":    func(url string) Channel { return NewNtfyChannel(url) },
		"webhook": func(url string) Channel { return NewWebhookChannel(url) },
	}

	for chName, newCh := range newChannel {
		t.Run(chName, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(bodyMarker))
			}))
			defer server.Close()

			err := newCh(server.URL).Send(context.Background(), Event{Service: "svc", Type: EventType("job_failure")})
			if err == nil {
				t.Fatal("want an error from a 500 response")
			}
			if strings.Contains(err.Error(), bodyMarker) {
				t.Errorf("error echoes the response body: %v", err)
			}
			if !strings.Contains(err.Error(), "500") {
				t.Errorf("error = %q, want it to at least report the status code", err.Error())
			}
		})
	}
}

func TestNotifier_MultipleChannels(t *testing.T) {
	var sent []Event
	ch1 := &mockChannel{events: &sent}
	ch2 := &mockChannel{events: &sent}

	notifier := NewNotifier()
	notifier.RegisterChannel("immich", ch1)
	notifier.RegisterChannel("immich", ch2)

	event := Event{
		Service:   "immich",
		Type:      EventType("job_failure"),
		Message:   "test",
		Severity:  "error",
		Timestamp: time.Now().UTC(),
	}

	err := notifier.Send(context.Background(), event)
	if err != nil {
		t.Errorf("Send() error = %v", err)
	}

	if len(sent) != 2 {
		t.Errorf("expected 2 sent events, got %d", len(sent))
	}
}

// TestNotifier_Send_JoinsAllChannelErrors pins finding 3: when
// multiple channels are registered for a service and more than one
// fails, Send must join every failure (via errors.Join) rather than
// reporting only the first or last — one channel's outage must never
// hide another's, mirroring the isolation-of-failure principle spec
// rule 3 requires between backup tiers.
func TestNotifier_Send_JoinsAllChannelErrors(t *testing.T) {
	err1 := errors.New("channel one is down")
	err2 := errors.New("channel two is down")

	notifier := NewNotifier()
	notifier.RegisterChannel("svc", &erroringChannel{err: err1, typ: "one"})
	notifier.RegisterChannel("svc", &erroringChannel{err: err2, typ: "two"})

	event := Event{Service: "svc", Type: EventType("job_failure"), Message: "test", Severity: "error", Timestamp: time.Now().UTC()}
	err := notifier.Send(context.Background(), event)
	if err == nil {
		t.Fatal("Send() error = nil, want a joined error from both failing channels")
	}
	if !errors.Is(err, err1) {
		t.Errorf("Send() error = %v, want it to wrap channel one's error %v", err, err1)
	}
	if !errors.Is(err, err2) {
		t.Errorf("Send() error = %v, want it to wrap channel two's error %v", err, err2)
	}
}

// TestNotifier_UnregisteredService pins finding 6: a service with no
// registered channel at all must return ErrNoChannels, not nil — a
// caller like SweepFreshness must be able to tell "nothing was
// listening" apart from a successful delivery.
func TestNotifier_UnregisteredService(t *testing.T) {
	notifier := NewNotifier()

	event := Event{
		Service:   "unknown",
		Type:      EventType("job_failure"),
		Message:   "test",
		Severity:  "error",
		Timestamp: time.Now().UTC(),
	}

	err := notifier.Send(context.Background(), event)
	if !errors.Is(err, ErrNoChannels) {
		t.Errorf("Send() error = %v, want ErrNoChannels", err)
	}
}

// TestNotifier_Resolve: a service with no channel registered up front
// (e.g. one added from the web UI after the program started) is
// looked up at send time, and a lookup failure or empty result is
// reported, never treated as delivered.
func TestNotifier_Resolve(t *testing.T) {
	lookupErr := errors.New("credential file unreadable")
	tests := []struct {
		name      string
		resolve   func(string) ([]Channel, error)
		wantSent  int
		wantErrIs error
	}{
		{
			name:     "resolved channel receives the event",
			resolve:  nil, // filled in below: needs the shared sent slice
			wantSent: 1,
		},
		{
			name:      "lookup error is returned",
			resolve:   func(string) ([]Channel, error) { return nil, lookupErr },
			wantErrIs: lookupErr,
		},
		{
			name:      "no channels found is still ErrNoChannels",
			resolve:   func(string) ([]Channel, error) { return nil, nil },
			wantErrIs: ErrNoChannels,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sent []Event
			n := NewNotifier()
			n.Resolve = tt.resolve
			if n.Resolve == nil {
				n.Resolve = func(svc string) ([]Channel, error) {
					if svc != "added-later" {
						t.Errorf("Resolve(%q), want added-later", svc)
					}
					return []Channel{&mockChannel{events: &sent}}, nil
				}
			}
			err := n.Send(context.Background(), Event{Service: "added-later", Type: EventType("job_failure"), Timestamp: time.Now().UTC()})
			if tt.wantErrIs != nil {
				if !errors.Is(err, tt.wantErrIs) {
					t.Errorf("Send() error = %v, want %v", err, tt.wantErrIs)
				}
			} else if err != nil {
				t.Errorf("Send() error = %v", err)
			}
			if len(sent) != tt.wantSent {
				t.Errorf("sent %d events, want %d", len(sent), tt.wantSent)
			}
		})
	}
}

// TestNotifier_RegisteredChannelsSkipResolve: up-front registration
// wins; Resolve is only a fallback.
func TestNotifier_RegisteredChannelsSkipResolve(t *testing.T) {
	var sent []Event
	n := NewNotifier()
	n.RegisterChannel("svc", &mockChannel{events: &sent})
	n.Resolve = func(string) ([]Channel, error) {
		t.Error("Resolve called for a service with registered channels")
		return nil, nil
	}
	if err := n.Send(context.Background(), Event{Service: "svc", Type: EventType("job_failure"), Timestamp: time.Now().UTC()}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if len(sent) != 1 {
		t.Errorf("sent %d events, want 1", len(sent))
	}
}

// TestWebhookExtraFields pins the body with and without Event.Extra:
// no Extra leaves the standard body byte for byte, extra keys follow
// in key order, standard keys cannot be overridden, and the signature
// covers the whole body.
func TestWebhookExtraFields(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := `{"service":"app","type":"job_failure","severity":"error","message":"m","detail":"d","timestamp":"2026-01-01T00:00:00Z"`
	tests := []struct {
		name  string
		extra map[string]any
		want  string
	}{
		{"no extra", nil, base + `}`},
		{"empty extra", map[string]any{}, base + `}`},
		{"extra keys sorted", map[string]any{"zone": "b", "attempt": 2}, base + `,"attempt":2,"zone":"b"}`},
		{"standard keys ignored", map[string]any{"service": "other", "message": "x", "region": "eu"}, base + `,"region":"eu"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			var sig string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ = io.ReadAll(r.Body)
				sig = r.Header.Get("X-Signature")
			}))
			defer srv.Close()
			w := NewWebhookChannel(srv.URL)
			w.Secret = "k"
			ev := Event{Service: "app", Type: "job_failure", Severity: "error", Message: "m", Detail: "d", Timestamp: ts, Extra: tt.extra}
			if err := w.Send(context.Background(), ev); err != nil {
				t.Fatal(err)
			}
			if string(body) != tt.want {
				t.Errorf("body = %s\nwant   %s", body, tt.want)
			}
			mac := hmac.New(sha256.New, []byte("k"))
			mac.Write(body)
			if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); sig != want {
				t.Errorf("signature = %q, want %q", sig, want)
			}
		})
	}
}

func TestWebhookExtraUnmarshalable(t *testing.T) {
	w := NewWebhookChannel("http://127.0.0.1:1/")
	err := w.Send(context.Background(), Event{Service: "app", Extra: map[string]any{"bad": make(chan int)}})
	if err == nil || !strings.Contains(err.Error(), "marshaling webhook payload") {
		t.Fatalf("err = %v", err)
	}
}
