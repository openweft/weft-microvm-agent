package network

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/openweft/weft-microvm-init/pkg/pod"
	"github.com/openweft/weft-microvm-init/pkg/secretclient"
)

// keyFetchTimeout bounds the fetch of the WireGuard key at boot (the client
// retries with backoff inside it).
const keyFetchTimeout = 60 * time.Second

// resolveWireGuardKey returns the base64 private key as bytes the caller
// wipes with the returned func. A private_key_ref is fetched over vsock from
// src; an inline private_key is used with a loud deprecation warning; both
// set, or neither, is an error. The key is never logged.
func resolveWireGuardKey(ctx context.Context, wg *pod.WireGuard, src secretclient.Source) ([]byte, func(), error) {
	noop := func() {}
	switch {
	case wg.PrivateKey != "" && wg.PrivateKeyRef != "":
		return nil, noop, errors.New("wireguard: private_key and private_key_ref are both set")
	case wg.PrivateKeyRef != "":
		if src == nil {
			return nil, noop, errors.New("wireguard: private_key_ref is set but no secret source is configured")
		}
		if !secretclient.ValidID(wg.PrivateKeyRef) {
			return nil, noop, errors.New("wireguard: private_key_ref is not a valid secret id")
		}
		ctx, cancel := context.WithTimeout(ctx, keyFetchTimeout)
		defer cancel()
		s, err := src.Fetch(ctx, wg.PrivateKeyRef, 0)
		if err != nil {
			return nil, noop, fmt.Errorf("wireguard private_key_ref: %w", err)
		}
		key := bytes.TrimSpace(s.Value)
		return key, s.Wipe, nil
	case wg.PrivateKey != "":
		slog.Warn("inline wireguard private_key in the pod spec is deprecated: use private_key_ref (inline will be refused in a future release)")
		key := []byte(wg.PrivateKey)
		return key, func() { clear(key) }, nil
	}
	return nil, noop, errors.New("wireguard: private_key or private_key_ref is required")
}
