// Package sshkey validates SSH private keys that a program will use
// unattended. It was moved from Ballast's backend package (the SSH
// branch of RenderCredentials) so that dockerhost no longer depends on
// Ballast's backup code.
package sshkey

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// Render validates key as the full contents of an unencrypted SSH
// private key file and returns the file contents to write (CRLF
// normalized, one trailing newline) plus the secret value the caller
// must register for redaction before anything can log it.
func Render(key string) (data []byte, secret string, err error) {
	k := strings.TrimSpace(strings.ReplaceAll(key, "\r\n", "\n"))
	if !strings.HasPrefix(k, "-----BEGIN ") || !strings.Contains(k, "PRIVATE KEY-----") || !strings.HasSuffix(k, "-----") {
		return nil, "", fmt.Errorf("the SSH key must be a private key file's full contents, from -----BEGIN ... PRIVATE KEY----- to the matching END line")
	}
	if strings.Contains(k, "ENCRYPTED") || opensshEncrypted(k) {
		return nil, "", fmt.Errorf("the SSH key is protected by a passphrase; this program runs unattended and needs a key without one (create a dedicated key with: ssh-keygen -t ed25519 -N '' -f automation_key)")
	}
	// ssh refuses a key file without a trailing newline.
	return []byte(k + "\n"), k, nil
}

// opensshEncrypted reports whether an "OPENSSH PRIVATE KEY" block is
// passphrase-protected. That format hides the cipher inside its
// base64 body (unlike PEM keys' "ENCRYPTED" header): the body starts
// "openssh-key-v1\x00" followed by a length-prefixed cipher name,
// which is "none" for an unprotected key.
func opensshEncrypted(key string) bool {
	const begin, end = "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"
	body, ok := strings.CutPrefix(key, begin)
	if !ok {
		return false
	}
	body, _ = strings.CutSuffix(body, end)
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
	if err != nil {
		return false
	}
	const magic = "openssh-key-v1\x00"
	rest, ok := strings.CutPrefix(string(raw), magic)
	if !ok || len(rest) < 4 {
		return false
	}
	n := binary.BigEndian.Uint32([]byte(rest[:4]))
	if uint64(len(rest)-4) < uint64(n) {
		return false
	}
	return rest[4:4+n] != "none"
}
