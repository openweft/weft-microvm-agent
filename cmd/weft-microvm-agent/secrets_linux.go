//go:build linux

package main

import "github.com/openweft/weft-microvm-init/pkg/secretclient"

// newSecretSource returns the GuestSecrets client over AF_VSOCK to the host,
// used to resolve the *_ref fields of a share-mount message. The per-boot
// token comes from the QEMU fw_cfg entry (read once, kept in memory only);
// without that entry the token is empty and the host relies on the vsock
// peer CID alone.
func newSecretSource(port uint32) secretclient.Source {
	return secretclient.NewVsock(port, secretclient.FileTokenSource(secretclient.FWCfgTokenPath))
}
