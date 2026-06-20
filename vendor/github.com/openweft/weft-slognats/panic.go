package weftslognats

// panic.go provides a top-level recover() helper that captures a Go
// panic via slog before re-panicking. Designed for `defer
// weftslognats.PanicReporter()` at the top of main() in every weft
// binary — agent, drivers, microvm-agent, weft-doctor, etc. — so a
// runtime crash reaches the NATS log subject the same way a
// regular slog.Error does.
//
// Without this helper, a Go panic prints its stack to stderr only ;
// the NATS fan-out (which sits in front of slog) never sees it, so
// the AI log triage in weft-doctor and every dashboard subscribing
// to weft.> is blind to the most diagnostic event.
//
// Usage :
//
//	func main() {
//	    defer weftslognats.PanicReporter()
//	    // … rest of main …
//	}

import (
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"
)

// PanicReporter recovers a panic, slog.Errors the value + stack
// trace, sleeps briefly to let the NATS publish flush, then
// re-panics so systemd still observes the abnormal exit and
// journalctl still prints the runtime's canonical stack.
//
// `name` defaults to "weft" if empty ; pass the binary name when
// you have multiple binaries logging to the same NATS subject so
// classifiers can disambiguate (e.g. "weft-driver-qemu",
// "weft-microvm-agent").
//
// Off-NATS hosts get identical behaviour as before : slog falls
// back to stderr, which is where the stack was going to land
// anyway.
func PanicReporter(name ...string) {
	r := recover()
	if r == nil {
		return
	}
	binary := "weft"
	if len(name) > 0 && name[0] != "" {
		binary = name[0]
	}
	stack := debug.Stack()
	slog.Error(binary+" : panic in main",
		"value", fmt.Sprintf("%v", r),
		"stack", string(stack),
	)
	// Brief flush window — the NATS publisher is async, so give
	// the line a chance to leave the host before the runtime exits.
	// 100ms is generous compared to intra-rack RTT ; if the
	// publisher is wedged we lose the line but the process exit
	// still goes through.
	time.Sleep(100 * time.Millisecond)
	panic(r)
}
