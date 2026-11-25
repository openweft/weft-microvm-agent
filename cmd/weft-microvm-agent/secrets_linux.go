//go:build linux

package main

import "github.com/openweft/weft-microvm-init/pkg/secretclient"

// newSecretSource returns the GuestSecrets client over AF_VSOCK to the host,
// used to resolve the *_ref fields of a share-mount message. There is no
// boot-token channel yet, so the token is empty.
func newSecretSource(port uint32) secretclient.Source {
	return secretclient.NewVsock(port, nil)
}
