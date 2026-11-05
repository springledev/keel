package proxmox

import (
	"strings"
	"testing"
)

func TestConnectionNormalize(t *testing.T) {
	tests := []struct {
		name        string
		conn        Connection
		wantHost    string
		wantTokenID string
		wantErr     string
	}{
		{"bare host", Connection{Host: "192.168.1.10", TokenID: "app@pve!mytoken"}, "https://192.168.1.10:8006", "app@pve!mytoken", ""},
		{"host with port", Connection{Host: "pve.local:8443", TokenID: "app@pve!mytoken"}, "https://pve.local:8443", "app@pve!mytoken", ""},
		{"https url", Connection{Host: "https://pve.local:8006", TokenID: "app@pve!mytoken"}, "https://pve.local:8006", "app@pve!mytoken", ""},
		{"trims spaces", Connection{Host: "  pve.local  ", TokenID: " app@pve!mytoken "}, "https://pve.local:8006", "app@pve!mytoken", ""},
		{"empty host", Connection{TokenID: "app@pve!mytoken"}, "", "", "address is required"},
		{"http scheme", Connection{Host: "http://pve.local", TokenID: "app@pve!mytoken"}, "", "", "reached over HTTPS"},
		{"user in address", Connection{Host: "https://root@pve.local", TokenID: "app@pve!mytoken"}, "", "", "don't put a user"},
		{"path in address", Connection{Host: "https://pve.local/api2", TokenID: "app@pve!mytoken"}, "", "", "nothing after it"},
		{"empty token", Connection{Host: "pve.local"}, "", "", "token ID is required"},
		{"bad token format", Connection{Host: "pve.local", TokenID: "not-a-token"}, "", "", "doesn't look like a Proxmox API token"},
		{"token missing bang", Connection{Host: "pve.local", TokenID: "app@pve"}, "", "", "doesn't look like a Proxmox API token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.conn
			err := c.Normalize()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Normalize() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize() unexpected error: %v", err)
			}
			if c.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", c.Host, tt.wantHost)
			}
			if c.TokenID != tt.wantTokenID {
				t.Errorf("TokenID = %q, want %q", c.TokenID, tt.wantTokenID)
			}
		})
	}
}

func TestRenderCredentials(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		_, _, err := RenderCredentials(Credentials{})
		if err != ErrNoCredentials {
			t.Fatalf("err = %v, want ErrNoCredentials", err)
		}
	})
	t.Run("multiline rejected", func(t *testing.T) {
		_, _, err := RenderCredentials(Credentials{TokenSecret: "abc\ndef"})
		if err == nil || !strings.Contains(err.Error(), "single line") {
			t.Fatalf("err = %v, want single-line complaint", err)
		}
	})
	t.Run("valid", func(t *testing.T) {
		data, secrets, err := RenderCredentials(Credentials{TokenSecret: "  abc-123  "})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) != "abc-123\n" {
			t.Errorf("data = %q, want %q", data, "abc-123\n")
		}
		if len(secrets) != 1 || secrets[0] != "abc-123" {
			t.Errorf("secrets = %v, want [abc-123]", secrets)
		}
	})
}

func TestGuestIsLXC(t *testing.T) {
	if !(Guest{Type: "lxc"}).IsLXC() {
		t.Error("lxc guest should report IsLXC")
	}
	if (Guest{Type: "qemu"}).IsLXC() {
		t.Error("qemu guest should not report IsLXC")
	}
}

func TestDefaultCredentialName(t *testing.T) {
	if got := DefaultCredentialName("myapp"); got != "myapp-proxmox-token" {
		t.Errorf("got %q", got)
	}
}
