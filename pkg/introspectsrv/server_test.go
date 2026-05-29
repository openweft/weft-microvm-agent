package introspectsrv

import (
	"context"
	"net"
	"testing"
	"time"

	introspectv1 "github.com/openweft/weft-proto/introspectv1"
	"github.com/openweft/weft-vm-agent/pkg/procps"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestListProcesses_RoundTrip serves the Introspect API over a real
// loopback TCP listener (standing in for the wg0-bound socket), dials it
// with a gRPC client, and checks the process table is faithfully mapped.
func TestListProcesses_RoundTrip(t *testing.T) {
	fixture := []procps.Process{
		{PID: 1, PPID: 0, User: "root", State: "S", CPUPercent: 0.5, MemPercent: 1.2, VSZKB: 168944, RSSKB: 13056, TTY: "?", StartTimeMS: 1600000001000, Command: "/sbin/init --system"},
		{PID: 2, PPID: 0, User: "root", State: "S", VSZKB: 0, RSSKB: 0, TTY: "?", Command: "[kthreadd]"},
	}

	srv := &Server{list: func() ([]procps.Process, error) { return fixture, nil }}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	introspectv1.RegisterIntrospectServer(gs, srv)
	go gs.Serve(lis)
	defer gs.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := introspectv1.NewIntrospectClient(conn).ListProcesses(ctx, &introspectv1.ListProcessesRequest{})
	if err != nil {
		t.Fatalf("ListProcesses: %v", err)
	}

	if len(resp.Processes) != 2 {
		t.Fatalf("got %d processes, want 2", len(resp.Processes))
	}
	p1 := resp.Processes[0]
	if p1.Pid != 1 || p1.User != "root" || p1.Command != "/sbin/init --system" {
		t.Errorf("p1 mapped wrong: %+v", p1)
	}
	if p1.VszKb != 168944 || p1.RssKb != 13056 {
		t.Errorf("p1 mem fields wrong: vsz=%d rss=%d", p1.VszKb, p1.RssKb)
	}
	if resp.Processes[1].Command != "[kthreadd]" {
		t.Errorf("p2 command = %q, want [kthreadd]", resp.Processes[1].Command)
	}
}
