// Package procps reads the Linux /proc filesystem to produce a
// process table equivalent to `ps aux`. The parsing is pure stdlib
// and OS-independent — List defaults to "/proc" (only meaningful on
// Linux), but listFrom accepts any procfs-shaped root so the logic is
// testable on any host with fixtures.
package procps

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// clkTck is the kernel's USER_HZ. 100 on every mainstream Linux build;
// hardcoded because cgo's sysconf(_SC_CLK_TCK) isn't available in a
// pure-Go, cross-compiled init/agent.
const clkTck = 100

// Process mirrors one row of `ps aux`.
type Process struct {
	PID         int32
	PPID        int32
	User        string
	State       string
	CPUPercent  float64
	MemPercent  float64
	VSZKB       uint64
	RSSKB       uint64
	TTY         string
	StartTimeMS int64
	Command     string
}

// List returns the live process table from the host's /proc.
func List() ([]Process, error) {
	return listFrom("/proc")
}

// listFrom reads the process table rooted at a procfs directory.
func listFrom(root string) ([]Process, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	sys := readSystem(root)

	var procs []Process
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID dir
		}
		p, ok := readProcess(root, pid, sys)
		if !ok {
			continue // vanished mid-scan, or unreadable
		}
		procs = append(procs, p)
	}
	return procs, nil
}

// systemInfo holds the machine-wide values needed to derive %cpu, %mem,
// and absolute start times.
type systemInfo struct {
	uptimeSec  float64 // /proc/uptime field 1
	btimeSec   int64   // /proc/stat "btime"
	memTotalKB uint64  // /proc/meminfo "MemTotal"
}

func readSystem(root string) systemInfo {
	var s systemInfo
	if b, err := os.ReadFile(filepath.Join(root, "uptime")); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			s.uptimeSec, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "stat")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if rest, ok := strings.CutPrefix(line, "btime "); ok {
				s.btimeSec, _ = strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
				break
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "meminfo")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if rest, ok := strings.CutPrefix(line, "MemTotal:"); ok {
				s.memTotalKB = parseFirstUint(rest)
				break
			}
		}
	}
	return s
}

func readProcess(root string, pid int, sys systemInfo) (Process, bool) {
	dir := filepath.Join(root, strconv.Itoa(pid))

	statRaw, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return Process{}, false
	}
	st, ok := parseStat(string(statRaw))
	if !ok {
		return Process{}, false
	}

	p := Process{
		PID:   int32(pid),
		PPID:  st.ppid,
		State: st.state,
		TTY:   "?",
	}

	// /proc/<pid>/status enriches user + memory in convenient units.
	comm := st.comm
	if b, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			switch {
			case strings.HasPrefix(line, "Uid:"):
				p.User = resolveUser(firstField(line[len("Uid:"):]))
			case strings.HasPrefix(line, "VmSize:"):
				p.VSZKB = parseFirstUint(line[len("VmSize:"):])
			case strings.HasPrefix(line, "VmRSS:"):
				p.RSSKB = parseFirstUint(line[len("VmRSS:"):])
			case strings.HasPrefix(line, "Name:"):
				if c := strings.TrimSpace(line[len("Name:"):]); c != "" {
					comm = c
				}
			}
		}
	}

	// Full command line; kernel threads have an empty cmdline, shown as
	// [comm] exactly like ps.
	p.Command = "[" + comm + "]"
	if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil && len(b) > 0 {
		args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		p.Command = strings.Join(args, " ")
	}

	// Derived metrics.
	if sys.memTotalKB > 0 {
		p.MemPercent = 100 * float64(p.RSSKB) / float64(sys.memTotalKB)
	}
	startSec := float64(st.starttime) / clkTck
	elapsed := sys.uptimeSec - startSec
	if elapsed > 0 {
		totalSec := float64(st.utime+st.stime) / clkTck
		p.CPUPercent = 100 * totalSec / elapsed
	}
	if sys.btimeSec > 0 {
		p.StartTimeMS = int64((float64(sys.btimeSec) + startSec) * 1000)
	}

	return p, true
}

// statFields holds the /proc/<pid>/stat values we consume.
type statFields struct {
	comm      string
	state     string
	ppid      int32
	utime     uint64
	stime     uint64
	starttime uint64
}

// parseStat parses /proc/<pid>/stat. comm (field 2) is wrapped in
// parentheses and may itself contain spaces and ')', so it's extracted
// between the first '(' and the last ')'; the remaining fields are
// whitespace-separated after that.
func parseStat(s string) (statFields, bool) {
	openIdx := strings.IndexByte(s, '(')
	closeIdx := strings.LastIndexByte(s, ')')
	if openIdx < 0 || closeIdx < 0 || closeIdx < openIdx {
		return statFields{}, false
	}
	var f statFields
	f.comm = s[openIdx+1 : closeIdx]

	rest := strings.Fields(s[closeIdx+1:])
	// rest[k] == stat field (k+3): [0]=state(3) [1]=ppid(4) [11]=utime(14)
	// [12]=stime(15) [19]=starttime(22).
	if len(rest) < 20 {
		return statFields{}, false
	}
	f.state = rest[0]
	if v, err := strconv.ParseInt(rest[1], 10, 32); err == nil {
		f.ppid = int32(v)
	}
	f.utime = parseUint(rest[11])
	f.stime = parseUint(rest[12])
	f.starttime = parseUint(rest[19])
	return f, true
}

// resolveUser turns a numeric uid into a login name, falling back to
// the numeric form when no mapping exists.
func resolveUser(uid string) string {
	if uid == "" {
		return ""
	}
	if u, err := user.LookupId(uid); err == nil {
		return u.Username
	}
	return uid
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

func parseFirstUint(s string) uint64 { return parseUint(firstField(s)) }

func parseUint(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}
