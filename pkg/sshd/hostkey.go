package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// LoadOrCreateHostKey returns the ed25519 host key for the SSH
// server. On first boot it generates a fresh key + persists the
// PEM-encoded private half to path with mode 0600 ; on subsequent
// boots it loads the existing key so the fingerprint stays stable
// (operators add `vmname,ip ssh-ed25519 ...` to their known_hosts
// once and trust it across reboots).
//
// path must point at a writable directory the agent has access to ;
// /var/lib/weft is the convention. The parent directory is created
// with 0700 on first run.
func LoadOrCreateHostKey(path string) (ssh.Signer, error) {
	if path == "" {
		return nil, errors.New("hostkey path is empty")
	}
	if b, err := os.ReadFile(path); err == nil {
		signer, perr := parseHostKey(b)
		if perr != nil {
			return nil, fmt.Errorf("parse host key %s: %w", path, perr)
		}
		return signer, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read host key %s: %w", path, err)
	}

	// First boot : generate + persist.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519: %w", err)
	}
	blob, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal ed25519: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: blob})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write tmp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("commit %s: %w", path, err)
	}
	return parseHostKey(pemBytes)
}

func parseHostKey(pemBytes []byte) (ssh.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}
