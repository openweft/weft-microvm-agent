// Package secretclient is the guest side of weft.guest.v1.GuestSecrets: it
// fetches one secret by ID from the host over the vsock channel, so a key
// never rests in the pod spec, on the config share or on the event bus.
//
// The host identifies the caller from the transport (and the per-boot token
// when the driver provides one), never from the request; a secret ID is an
// opaque name the host maps to a source, not a reference the guest chooses.
//
// Rules this client keeps:
//   - a value is returned as bytes the caller wipes (Secret.Wipe); the client
//     never logs a value or a token, and error text is constant per gRPC code;
//   - Unavailable and ResourceExhausted (and a failed dial) are retried a
//     bounded number of times with exponential backoff; every other code is
//     final (PermissionDenied is also the answer for an unknown ID, so
//     retrying it would only spend the rate budget);
//   - a value over MaxValue is refused.
package secretclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"time"

	guestv1 "github.com/openweft/weft-proto/guestv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	// MaxValue is the largest value the host may return (64 KiB).
	MaxValue = 64 << 10
	// TokenLen is the length of the per-boot token, when there is one.
	TokenLen = 32
	// DefaultPort is the host vsock port GuestPodPlane and GuestSecrets are
	// served on; it matches weft-microvm-agent's guestplane.DefaultPort.
	DefaultPort uint32 = 7777

	defaultAttempts   = 5
	defaultBackoff    = 200 * time.Millisecond
	maxBackoff        = 5 * time.Second
	defaultTimeout    = 10 * time.Second
	maxRecvMessageLen = 1 << 20 // generous: oversize is judged on the value, not by a transport error
)

// newClient is grpc.NewClient; a variable so a test can make it fail.
var newClient = grpc.NewClient

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidID reports whether id is a well-formed secret ID.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// ErrOversize is returned when the host answers with a value over MaxValue.
var ErrOversize = errors.New("secret value exceeds 64 KiB")

// Secret is one fetched value. Value is empty when Unchanged.
type Secret struct {
	Value     []byte
	Version   uint64
	Unchanged bool
}

// Wipe zeroes the value in place.
func (s *Secret) Wipe() {
	if s == nil {
		return
	}
	clear(s.Value)
	s.Value = nil
}

// TokenSource yields the per-boot token: nil or empty when the driver
// provides none (KVM today), exactly TokenLen bytes otherwise. It is called
// on every attempt so a source that learns the token late is honoured.
type TokenSource func() ([]byte, error)

// Dialer opens one connection to the host's GuestSecrets server.
type Dialer func(ctx context.Context) (net.Conn, error)

// Source is what callers depend on, so tests can stand in for the host.
type Source interface {
	Fetch(ctx context.Context, id string, known uint64) (*Secret, error)
}

// Client fetches secrets. The zero value of every field but Dial is usable.
type Client struct {
	Dial  Dialer
	Token TokenSource
	// Attempts bounds the tries per Fetch (0 = 5). Backoff is the first
	// pause, doubled each retry up to 5 s (0 = 200 ms). Timeout bounds one
	// attempt (0 = 10 s).
	Attempts int
	Backoff  time.Duration
	Timeout  time.Duration

	sleep func(context.Context, time.Duration) error // test hook
}

// Fetch returns the current value of id. known is the version the caller
// already holds (0 = none); when it is current the result has Unchanged set
// and no value.
func (c *Client) Fetch(ctx context.Context, id string, known uint64) (*Secret, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("secret id %q: malformed", id)
	}
	if c.Dial == nil {
		return nil, errors.New("secretclient: no dialer")
	}
	attempts, backoff, timeout := c.Attempts, c.Backoff, c.Timeout
	if attempts <= 0 {
		attempts = defaultAttempts
	}
	if backoff <= 0 {
		backoff = defaultBackoff
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			if err := c.wait(ctx, backoff); err != nil {
				return nil, fmt.Errorf("secret %q: %w", id, err)
			}
			backoff = min(backoff*2, maxBackoff)
		}
		s, err := c.fetchOnce(ctx, id, known, timeout)
		if err == nil {
			return s, nil
		}
		if !retryable(err) {
			return nil, fmt.Errorf("secret %q: %w", id, err)
		}
		last = err
	}
	return nil, fmt.Errorf("secret %q: gave up after %d attempts: %w", id, attempts, last)
}

func (c *Client) wait(ctx context.Context, d time.Duration) error {
	if c.sleep != nil {
		return c.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// dialError marks a failed dial: retryable, like Unavailable.
type dialError struct{ err error }

func (e *dialError) Error() string { return "dial host: " + e.err.Error() }
func (e *dialError) Unwrap() error { return e.err }

func retryable(err error) bool {
	var de *dialError
	if errors.As(err, &de) {
		return true
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.ResourceExhausted:
		return true
	}
	return false
}

func (c *Client) fetchOnce(ctx context.Context, id string, known uint64, timeout time.Duration) (*Secret, error) {
	var token []byte
	if c.Token != nil {
		t, err := c.Token()
		if err != nil {
			return nil, fmt.Errorf("boot token: %w", err)
		}
		if len(t) != 0 && len(t) != TokenLen {
			return nil, fmt.Errorf("boot token: want 0 or %d bytes, got %d", TokenLen, len(t))
		}
		token = t
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := c.Dial(ctx)
	if err != nil {
		return nil, &dialError{err}
	}
	cc, err := newClient("passthrough:///guest-secrets",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return conn, nil }),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxRecvMessageLen)),
	)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("grpc client: %w", err)
	}
	defer cc.Close()
	resp, err := guestv1.NewGuestSecretsClient(cc).Fetch(ctx, &guestv1.FetchRequest{
		SecretId: id, BootToken: token, KnownVersion: known,
	})
	if err != nil {
		// Constant text: the gRPC code only, never the server's message.
		return nil, codeError{status.Code(err)}
	}
	// Copy out of the protobuf message and zero its buffer.
	v := resp.GetValue()
	out := &Secret{Version: resp.GetVersion(), Unchanged: resp.GetUnchanged()}
	if len(v) > MaxValue {
		clear(v)
		return nil, ErrOversize
	}
	if len(v) > 0 {
		out.Value = append([]byte(nil), v...)
		clear(v)
	}
	if !out.Unchanged && len(out.Value) == 0 {
		return nil, errors.New("host returned an empty value")
	}
	return out, nil
}

// codeError carries only a gRPC code, so no server text can leak a value.
type codeError struct{ code codes.Code }

func (e codeError) Error() string              { return "host refused: " + e.code.String() }
func (e codeError) GRPCStatus() *status.Status { return status.New(e.code, "") }
