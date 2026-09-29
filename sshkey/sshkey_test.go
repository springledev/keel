package sshkey

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderRejects(t *testing.T) {
	tests := []struct {
		name, key, want string
	}{
		{"malformed", "not a key at all", "full contents"},
		{"PEM encrypted", "-----BEGIN RSA PRIVATE KEY-----\n" +
			"Proc-Type: 4,ENCRYPTED\n" +
			"DEK-Info: AES-128-CBC,ABCDEF\n\n" +
			"garbagebase64data\n" +
			"-----END RSA PRIVATE KEY-----", "protected by a passphrase"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Render(tc.key)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// genKey generates a real ed25519 key (OpenSSH format) with the given
// passphrase ("" for none) in t.TempDir() and returns its text.
func genKey(t *testing.T, passphrase string) string {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", passphrase, "-f", path, "-C", "keel-test")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading generated key: %v", err)
	}
	return string(data)
}

func TestRenderRealKeys(t *testing.T) {
	t.Run("unencrypted accepted", func(t *testing.T) {
		key := genKey(t, "")
		data, secret, err := Render(key)
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		if !strings.HasSuffix(string(data), "\n") {
			t.Error("rendered key must end with a trailing newline")
		}
		if secret == "" || secret != strings.TrimSpace(key) {
			t.Error("secret must be the trimmed key")
		}
	})
	t.Run("openssh passphrase-protected rejected", func(t *testing.T) {
		_, _, err := Render(genKey(t, "hunter2pass"))
		if err == nil || !strings.Contains(err.Error(), "protected by a passphrase") {
			t.Errorf("error = %v, want passphrase rejection", err)
		}
	})
	t.Run("CRLF normalized and trailing newline added", func(t *testing.T) {
		key := genKey(t, "")
		crlf := strings.ReplaceAll(strings.TrimRight(key, "\n"), "\n", "\r\n")
		data, _, err := Render(crlf)
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		if strings.Contains(string(data), "\r") {
			t.Error("rendered key must have CRLF normalized to LF")
		}
		if !strings.HasSuffix(string(data), "-----\n") {
			t.Errorf("rendered key = %q, want it to end with the END line plus one newline", data)
		}
	})
}

func TestOpensshEncryptedMalformed(t *testing.T) {
	for _, k := range []string{
		"-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----\n!!!\n-----END OPENSSH PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----\naGVsbG8=\n-----END OPENSSH PRIVATE KEY-----",
	} {
		if opensshEncrypted(k) {
			t.Errorf("opensshEncrypted(%q) = true, want false", k)
		}
	}
}
