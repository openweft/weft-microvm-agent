//go:build linux

// Package transport opens the guest↔host channel weft-init uses to
// stream pod status, container events, log chunks, and to receive
// control requests (stop, exec, restart) from weft-agent on the
// hypervisor host.
//
// The transport is AF_VSOCK on Linux KVM and on Apple VZ guests
// (VZVirtioSocketDevice on the host side). Both expose the same
// kernel-level interface to the guest, so this code is the same
// for both backends.
//
// Pure stdlib: we open AF_VSOCK via syscall.Socket and speak the
// raw socket. The weft-proto gRPC service runs over this socket;
// integration with grpc-go is done in cmd/weft-init wiring (a
// custom Dialer), not here.
package transport

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// VsockCID values reserved by the kernel.
const (
	VsockCIDAny        = 0xffffffff // -1
	VsockCIDHypervisor = 0
	VsockCIDLocal      = 1
	VsockCIDHost       = 2
)

// AF_VSOCK is socket family 40 on Linux. Not exposed in the
// stdlib's syscall constants on every Go version, hardcoded here.
const afVsock = 40

// sockaddrVM is the userspace mirror of struct sockaddr_vm
// (linux/vm_sockets.h).
type sockaddrVM struct {
	family   uint16
	reserved uint16
	port     uint32
	cid      uint32
	zero     [4]byte
}

// Dial opens an AF_VSOCK connection to (cid, port) and wraps it
// in a *net.UnixConn-like net.Conn for use with grpc.WithDialer.
//
// Typical use: Dial(VsockCIDHost, 5555) inside the guest to reach
// weft-agent on the hypervisor host.
func Dial(cid, port uint32) (net.Conn, error) {
	fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	sa := sockaddrVM{family: afVsock, port: port, cid: cid}
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_CONNECT, uintptr(fd),
		uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa),
	); errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("vsock connect (%d,%d): %w", cid, port, errno)
	}
	f := os.NewFile(uintptr(fd), fmt.Sprintf("vsock://%d:%d", cid, port))
	conn, err := net.FileConn(f)
	_ = f.Close() // FileConn dups
	if err != nil {
		return nil, fmt.Errorf("vsock filconn: %w", err)
	}
	return conn, nil
}

// DialWithRetry retries Dial up to attempts times with the given
// per-attempt delay. The host side of vsock isn't always ready the
// instant the guest finishes booting ; a few hundred ms of retry
// covers the gap without baking in arbitrary sleeps.
func DialWithRetry(cid, port uint32, attempts int, delay time.Duration) (net.Conn, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		c, err := Dial(cid, port)
		if err == nil {
			return c, nil
		}
		lastErr = err
		time.Sleep(delay)
	}
	return nil, lastErr
}

// ioctlVMSocketsGetLocalCID is IOCTL_VM_SOCKETS_GET_LOCAL_CID from
// linux/vm_sockets.h. Value is arch-dependent ; 0x7b9 holds on arm64
// / amd64 / x86 (the kernel headers use the same _IO(7, 0xb9)
// constant). Hard-coded here to avoid pulling cgo headers into a
// pure-Go init binary.
const ioctlVMSocketsGetLocalCID = 0x7b9

// LocalCID reads the calling process's AF_VSOCK guest CID from the
// kernel via ioctl on /dev/vsock. Used by weft-microvm-agent to
// announce its actual CID in the GuestPodPlane Hello frame so the
// host can populate its podCIDs registry — closes the Apple-VZ
// readback gap (the host can't query Apple's framework for the
// assigned CID, but the guest's own kernel knows it).
//
// Returns 0 on any error (missing /dev/vsock, ioctl failure) so
// non-microVM builds + older guests don't crash : the host treats
// a zero report as "not provided" and falls back to the v0.4.46
// strict-when-known check against peer.CID().
func LocalCID() uint32 {
	fd, err := syscall.Open("/dev/vsock", syscall.O_RDONLY, 0)
	if err != nil {
		return 0
	}
	defer syscall.Close(fd)
	var cid uint32
	if _, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(ioctlVMSocketsGetLocalCID),
		uintptr(unsafe.Pointer(&cid)),
	); errno != 0 {
		return 0
	}
	return cid
}
