//go:build !linux

package main

import "github.com/openweft/weft-microvm-init/pkg/secretclient"

// newSecretSource has no vsock transport off Linux: a mount message carrying
// a *_ref is refused ("no secret source configured"), inline keys still work.
func newSecretSource(uint32) secretclient.Source { return nil }
