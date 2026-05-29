package procps

import (
	"math"
	"testing"
)

func byPID(procs []Process, pid int32) (Process, bool) {
	for _, p := range procs {
		if p.PID == pid {
			return p, true
		}
	}
	return Process{}, false
}

func TestListFrom_Fixture(t *testing.T) {
	procs, err := listFrom("testdata/proc")
	if err != nil {
		t.Fatalf("listFrom: %v", err)
	}
	if len(procs) != 2 {
		t.Fatalf("expected 2 processes, got %d: %+v", len(procs), procs)
	}

	p1, ok := byPID(procs, 1)
	if !ok {
		t.Fatal("pid 1 not found")
	}
	if p1.PPID != 0 {
		t.Errorf("pid1 ppid = %d, want 0", p1.PPID)
	}
	if p1.State != "S" {
		t.Errorf("pid1 state = %q, want S", p1.State)
	}
	if p1.User != "root" {
		t.Errorf("pid1 user = %q, want root (uid 0)", p1.User)
	}
	if p1.VSZKB != 168944 {
		t.Errorf("pid1 vsz = %d, want 168944", p1.VSZKB)
	}
	if p1.RSSKB != 13056 {
		t.Errorf("pid1 rss = %d, want 13056", p1.RSSKB)
	}
	if p1.Command != "/sbin/init --system" {
		t.Errorf("pid1 command = %q, want %q", p1.Command, "/sbin/init --system")
	}
	// MemPercent = 100 * 13056 / 2048000.
	if want := 100 * 13056.0 / 2048000.0; math.Abs(p1.MemPercent-want) > 1e-6 {
		t.Errorf("pid1 mem%% = %v, want %v", p1.MemPercent, want)
	}
	// elapsed = uptime(1000.50) - starttime/clk(100/100=1.0) = 999.5;
	// cpu = 100 * (utime+stime)/clk / elapsed = 100 * 0.6 / 999.5.
	if want := 100 * 0.6 / 999.5; math.Abs(p1.CPUPercent-want) > 1e-6 {
		t.Errorf("pid1 cpu%% = %v, want %v", p1.CPUPercent, want)
	}
	// StartTimeMS = (btime 1600000000 + 1.0s) * 1000.
	if p1.StartTimeMS != 1600000001000 {
		t.Errorf("pid1 start = %d, want 1600000001000", p1.StartTimeMS)
	}

	p2, ok := byPID(procs, 2)
	if !ok {
		t.Fatal("pid 2 not found")
	}
	// Kernel thread: empty cmdline → [comm], no VmRSS line → 0.
	if p2.Command != "[kthreadd]" {
		t.Errorf("pid2 command = %q, want [kthreadd]", p2.Command)
	}
	if p2.RSSKB != 0 {
		t.Errorf("pid2 rss = %d, want 0", p2.RSSKB)
	}
}

func TestParseStat_CommWithSpacesAndParens(t *testing.T) {
	// comm can contain spaces and ')'. Field extraction must use the last
	// ')' and still read state/ppid/starttime correctly.
	line := "1234 (weird )name) ) R 7 1 1 0 -1 0 0 0 0 0 12 34 0 0 20 0 1 0 999"
	f, ok := parseStat(line)
	if !ok {
		t.Fatal("parseStat returned !ok")
	}
	if f.comm != "weird )name) " {
		t.Errorf("comm = %q", f.comm)
	}
	if f.state != "R" {
		t.Errorf("state = %q, want R", f.state)
	}
	if f.ppid != 7 {
		t.Errorf("ppid = %d, want 7", f.ppid)
	}
	if f.utime != 12 || f.stime != 34 {
		t.Errorf("utime/stime = %d/%d, want 12/34", f.utime, f.stime)
	}
	if f.starttime != 999 {
		t.Errorf("starttime = %d, want 999", f.starttime)
	}
}

func TestParseStat_TooFewFields(t *testing.T) {
	if _, ok := parseStat("1 (x) S 0 1 2 3"); ok {
		t.Error("expected !ok for truncated stat line")
	}
}
