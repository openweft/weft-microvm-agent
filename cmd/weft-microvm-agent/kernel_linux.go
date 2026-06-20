//go:build linux

package main

import "syscall"

// kernelRelease returns the Linux kernel release string (uname -r),
// or empty on syscall failure. Reported via the GuestPodPlane Hello
// so the host's logs show which kernel each microVM booted under —
// useful for correlating bugs to specific kernel builds.
func kernelRelease() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
