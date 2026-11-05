package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChatChannels(t *testing.T) {
	tests := []struct {
		name  string
		mk    func(string) Channel
		field string
	}{
		{"discord", func(u string) Channel { return NewDiscordChannel(u) }, "content"},
		{"slack", func(u string) Channel { return NewSlackChannel(u) }, "text"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got map[string]string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(b, &got)
			}))
			ch := tt.mk(srv.URL + "/secret-token")
			if ch.Type() != tt.name {
				t.Errorf("Type = %q", ch.Type())
			}
			ev := Event{Service: "example", Message: "drift", Detail: "extra rule", Title: "T"}
			if err := ch.Send(context.Background(), ev); err != nil {
				t.Fatal(err)
			}
			if want := "T\ndrift\nextra rule"; got[tt.field] != want {
				t.Errorf("%s = %q, want %q", tt.field, got[tt.field], want)
			}
			srv.Close()
			err := ch.Send(context.Background(), ev)
			if err == nil || strings.Contains(err.Error(), "secret-token") {
				t.Errorf("want error without URL, got %v", err)
			}
		})
	}
	if err := NewSlackChannel("").Send(context.Background(), Event{}); err == nil {
		t.Error("empty URL should fail")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	if err := NewDiscordChannel(srv.URL).Send(context.Background(), Event{}); err == nil {
		t.Error("500 should fail")
	}
}

func TestWebhookSignatureHeader(t *testing.T) {
	for _, hdr := range []string{"", "X-Example-Signature"} {
		var gotBody []byte
		var r0 *http.Request
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r0 = r
			gotBody, _ = io.ReadAll(r.Body)
		}))
		ch := NewWebhookChannel(srv.URL)
		ch.Secret = "k"
		ch.SignatureHeader = hdr
		if err := ch.Send(context.Background(), Event{Service: "s", Message: "m"}); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		name := hdr
		if name == "" {
			name = "X-Signature"
		}
		mac := hmac.New(sha256.New, []byte("k"))
		mac.Write(gotBody)
		if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); r0.Header.Get(name) != want {
			t.Errorf("%s = %q, want %q", name, r0.Header.Get(name), want)
		}
	}
}

func TestNtfyExplicitTitle(t *testing.T) {
	var title string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { title = r.Header.Get("Title") }))
	defer srv.Close()
	if err := NewNtfyChannel(srv.URL).Send(context.Background(), Event{Service: "s", Title: "Example test notification"}); err != nil {
		t.Fatal(err)
	}
	if title != "Example test notification" {
		t.Errorf("title = %q", title)
	}
}
