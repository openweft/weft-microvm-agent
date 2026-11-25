//go:build linux

package secretclient

import (
	"context"
	"net"

	"github.com/openweft/weft-microvm-init/pkg/transport"
)

// NewVsock returns a Client that dials the host (CID 2) on port; each attempt
// opens a fresh connection, and the client's own backoff paces the retries.
// tok may be nil (no per-boot token).
func NewVsock(port uint32, tok TokenSource) *Client {
	if port == 0 {
		port = DefaultPort
	}
	return &Client{
		Dial: func(context.Context) (net.Conn, error) {
			return transport.Dial(transport.VsockCIDHost, port)
		},
		Token: tok,
	}
}
