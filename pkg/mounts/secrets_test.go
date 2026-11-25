package mounts

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openweft/weft-microvm-init/pkg/cubefs"
	"github.com/openweft/weft-microvm-init/pkg/pod"
	"github.com/openweft/weft-microvm-init/pkg/secretclient"
	guestv1 "github.com/openweft/weft-proto/guestv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// hostSecrets is an in-process GuestSecrets server, the host side of the
// vsock channel: secrets by ID with a version.
type hostSecrets struct {
	guestv1.UnimplementedGuestSecretsServer
	mu      sync.Mutex
	secrets map[string]*guestv1.FetchResponse
	calls   int
}

func (h *hostSecrets) Fetch(_ context.Context, r *guestv1.FetchRequest) (*guestv1.FetchResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	s, ok := h.secrets[r.SecretId]
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "denied")
	}
	if r.KnownVersion == s.Version {
		return &guestv1.FetchResponse{Version: s.Version, Unchanged: true}, nil
	}
	return &guestv1.FetchResponse{Value: append([]byte(nil), s.Value...), Version: s.Version}, nil
}

func (h *hostSecrets) set(id, val string, version uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.secrets[id] = &guestv1.FetchResponse{Value: []byte(val), Version: version}
}

func newHost(t *testing.T) (*hostSecrets, *secretclient.Client) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &hostSecrets{secrets: map[string]*guestv1.FetchResponse{}}
	srv := grpc.NewServer()
	guestv1.RegisterGuestSecretsServer(srv, h)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return h, &secretclient.Client{
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", lis.Addr().String())
		},
		Attempts: 1,
		Backoff:  time.Millisecond,
	}
}

func refMessage(t *testing.T, mod func(*pod.CubeFSMount)) []byte {
	t.Helper()
	m := cubefsMount()
	m.CubeFS.AccessKeyRef = "team-ak"
	m.CubeFS.SecretKeyRef = "team-sk"
	m.CubeFS.SecretVersion = 1
	if mod != nil {
		mod(m.CubeFS)
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// applier is the dynamic-mount ApplyFunc the agent wires: resolve the refs
// over vsock, then hand the filled spec to the mount step (recorded here).
func applier(src secretclient.Source, got *[]pod.ShareMount) ApplyFunc {
	return func(m pod.ShareMount) error {
		out, wipe, err := cubefs.Resolve(context.Background(), m, src)
		if err != nil {
			return err
		}
		defer wipe()
		cp := out
		c := *out.CubeFS
		cp.CubeFS = &c
		*got = append(*got, cp)
		return nil
	}
}

func TestDynamicMountFetchesRefsOverVsock(t *testing.T) {
	h, c := newHost(t)
	h.set("team-ak", "AK1", 1)
	h.set("team-sk", "SK1", 1)
	var got []pod.ShareMount
	if err := HandleMessage(refMessage(t, nil), applier(c, &got)); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CubeFS.AccessKey != "AK1" || got[0].CubeFS.SecretKey != "SK1" {
		t.Fatalf("keys not resolved: %+v", got)
	}
	if got[0].CubeFS.SecretVersion != 1 {
		t.Fatalf("secret_version lost: %d", got[0].CubeFS.SecretVersion)
	}
}

func TestDynamicMountRotationRefetches(t *testing.T) {
	h, c := newHost(t)
	h.set("team-ak", "AK1", 1)
	h.set("team-sk", "SK1", 1)
	var got []pod.ShareMount
	apply := applier(c, &got)
	if err := HandleMessage(refMessage(t, nil), apply); err != nil {
		t.Fatal(err)
	}
	// the operator rotates the secret and re-publishes with a higher version
	h.set("team-sk", "SK2", 2)
	msg := refMessage(t, func(c *pod.CubeFSMount) { c.SecretVersion = 2 })
	if err := HandleMessage(msg, apply); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].CubeFS.SecretKey != "SK2" || got[1].CubeFS.SecretVersion != 2 {
		t.Fatalf("rotation not picked up: %+v", got)
	}
	if got[0].CubeFS.SecretKey != "SK1" {
		t.Fatal("first mount was mutated by the second")
	}
}

func TestDynamicMountDeniedAndWrongID(t *testing.T) {
	h, c := newHost(t)
	h.set("team-ak", "AK1", 1) // team-sk is not granted to this VM
	var got []pod.ShareMount
	err := HandleMessage(refMessage(t, nil), applier(c, &got))
	if err == nil || !strings.Contains(err.Error(), "PermissionDenied") {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 0 {
		t.Fatal("mounted despite a denied secret")
	}
	if strings.Contains(err.Error(), "AK1") {
		t.Fatal("error leaks a fetched value")
	}
	bad := refMessage(t, func(c *pod.CubeFSMount) { c.SecretKeyRef = "Bad ID" })
	if err := HandleMessage(bad, applier(c, &got)); err == nil || !strings.Contains(err.Error(), "invalid mount update") {
		t.Fatalf("malformed ref: %v", err)
	}
}

func TestDynamicMountRefAndInlineIsRefusedBeforeAnyFetch(t *testing.T) {
	h, c := newHost(t)
	h.set("team-ak", "AK1", 1)
	h.set("team-sk", "SK1", 1)
	msg := refMessage(t, func(c *pod.CubeFSMount) { c.SecretKey = "inline" })
	var got []pod.ShareMount
	if err := HandleMessage(msg, applier(c, &got)); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Fatalf("err = %v", err)
	}
	if h.calls != 0 || len(got) != 0 {
		t.Fatalf("fetched or mounted: calls=%d mounts=%d", h.calls, len(got))
	}
}

func TestDynamicMountOversizeSecretIsRefused(t *testing.T) {
	h, c := newHost(t)
	h.set("team-ak", "AK1", 1)
	h.set("team-sk", string(bytes.Repeat([]byte("x"), secretclient.MaxValue+1)), 1)
	var got []pod.ShareMount
	if err := HandleMessage(refMessage(t, nil), applier(c, &got)); err == nil {
		t.Fatal("oversize secret accepted")
	}
	if len(got) != 0 {
		t.Fatal("mounted with an oversize secret")
	}
}

func TestSecretClientUnchangedForKnownVersion(t *testing.T) {
	h, c := newHost(t)
	h.set("team-sk", "SK1", 7)
	s, err := c.Fetch(context.Background(), "team-sk", 7)
	if err != nil || !s.Unchanged || len(s.Value) != 0 {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestDynamicMountRefWithoutSourceIsRefused(t *testing.T) {
	var got []pod.ShareMount
	err := HandleMessage(refMessage(t, nil), applier(nil, &got))
	if err == nil || len(got) != 0 {
		t.Fatalf("err=%v mounts=%d", err, len(got))
	}
}
