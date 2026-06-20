//go:build !linux

package main

// kernelRelease on non-Linux returns empty — the agent only ships
// to Linux microVMs ; the stub keeps non-Linux builds (CI lint on
// darwin) green.
func kernelRelease() string { return "" }
