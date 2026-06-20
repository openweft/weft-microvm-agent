//go:build linux

// Package network configures the guest's pod-level networking
// purely via AF_NETLINK syscalls — no `ip`, `ifconfig`, or busybox
// dependency in the micro-VM. Scope is intentionally small: bring
// one interface up, assign one IPv4 address, install a default
// gateway, write /etc/resolv.conf. That's what a pod needs.
//
// Netlink RTM messages are framed by hand against the kernel ABI
// (linux/rtnetlink.h, linux/if_addr.h). No third-party deps.
package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// Apply brings the pod's network up. Idempotent at the level the
// kernel itself enforces (setting an address that already exists
// returns EEXIST, which we swallow).
func Apply(n *pod.Network) error {
	if n == nil {
		return nil
	}
	iface := n.Interface
	if iface == "" {
		iface = "eth0"
	}

	idx, err := ifaceIndex(iface)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", iface, err)
	}

	if err := linkUp(idx); err != nil {
		return fmt.Errorf("link up %s: %w", iface, err)
	}

	if n.Address != "" {
		ip, ipnet, err := net.ParseCIDR(n.Address)
		if err != nil {
			return fmt.Errorf("parse address %q: %w", n.Address, err)
		}
		if err := addrAdd(idx, ip, ipnet); err != nil && err != syscall.EEXIST {
			return fmt.Errorf("addr add %s on %s: %w", n.Address, iface, err)
		}
	}

	if n.Gateway != "" {
		gw := net.ParseIP(n.Gateway)
		if gw == nil {
			return fmt.Errorf("parse gateway %q", n.Gateway)
		}
		if err := defaultRoute(idx, gw); err != nil && err != syscall.EEXIST {
			return fmt.Errorf("default route via %s: %w", n.Gateway, err)
		}
	}

	if len(n.DNS) > 0 {
		if err := writeResolvConf(n.DNS); err != nil {
			return fmt.Errorf("resolv.conf: %w", err)
		}
	}

	if n.Hostname != "" {
		if err := syscall.Sethostname([]byte(n.Hostname)); err != nil {
			return fmt.Errorf("sethostname %q: %w", n.Hostname, err)
		}
	}

	return nil
}

// --- low-level netlink ---

func openRTNL() (int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

// talk sends one request and reads frames until NLMSG_DONE or an
// NLMSG_ERROR. errno 0 in NLMSG_ERROR is an ack and means success.
func talk(req []byte) error {
	fd, err := openRTNL()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if _, err := syscall.Write(fd, req); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for {
		n, err := syscall.Read(fd, buf)
		if err != nil {
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				return nil
			case syscall.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return fmt.Errorf("short NLMSG_ERROR")
				}
				errno := int32(binary.LittleEndian.Uint32(m.Data[:4]))
				if errno == 0 {
					return nil // ack
				}
				return syscall.Errno(-errno)
			}
		}
	}
}

func ifaceIndex(name string) (int32, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return int32(ifi.Index), nil
}

// linkUp sends RTM_NEWLINK with IFF_UP flagged.
func linkUp(idx int32) error {
	type ifinfomsg struct {
		Family uint8
		_      uint8
		Type   uint16
		Index  int32
		Flags  uint32
		Change uint32
	}
	const ifaceUP = syscall.IFF_UP

	body := ifinfomsg{
		Family: syscall.AF_UNSPEC,
		Index:  idx,
		Flags:  ifaceUP,
		Change: ifaceUP,
	}
	msg := newMessage(syscall.RTM_NEWLINK, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	msg.append((*[unsafe.Sizeof(ifinfomsg{})]byte)(unsafe.Pointer(&body))[:])
	return talk(msg.bytes())
}

// addrAdd installs an IPv4 (or IPv6) address on idx.
func addrAdd(idx int32, ip net.IP, ipnet *net.IPNet) error {
	type ifaddrmsg struct {
		Family    uint8
		Prefixlen uint8
		Flags     uint8
		Scope     uint8
		Index     uint32
	}

	family := uint8(syscall.AF_INET)
	if ip.To4() == nil {
		family = syscall.AF_INET6
	}
	prefix, _ := ipnet.Mask.Size()

	body := ifaddrmsg{
		Family:    family,
		Prefixlen: uint8(prefix),
		Index:     uint32(idx),
	}
	msg := newMessage(syscall.RTM_NEWADDR, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_CREATE|syscall.NLM_F_EXCL)
	msg.append((*[unsafe.Sizeof(ifaddrmsg{})]byte)(unsafe.Pointer(&body))[:])
	// IFA_LOCAL = 2, IFA_ADDRESS = 1 — both required for IPv4.
	addr := ip
	if v4 := ip.To4(); v4 != nil {
		addr = v4
	}
	msg.appendAttr(2 /*IFA_LOCAL*/, addr)
	msg.appendAttr(1 /*IFA_ADDRESS*/, addr)
	return talk(msg.bytes())
}

// defaultRoute installs 0.0.0.0/0 via gw on idx.
func defaultRoute(idx int32, gw net.IP) error {
	type rtmsg struct {
		Family   uint8
		DstLen   uint8
		SrcLen   uint8
		Tos      uint8
		Table    uint8
		Protocol uint8
		Scope    uint8
		Type     uint8
		Flags    uint32
	}

	family := uint8(syscall.AF_INET)
	if gw.To4() == nil {
		family = syscall.AF_INET6
	}
	body := rtmsg{
		Family:   family,
		Table:    syscall.RT_TABLE_MAIN,
		Protocol: syscall.RTPROT_BOOT,
		Scope:    syscall.RT_SCOPE_UNIVERSE,
		Type:     syscall.RTN_UNICAST,
	}
	msg := newMessage(syscall.RTM_NEWROUTE, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_CREATE|syscall.NLM_F_EXCL)
	msg.append((*[unsafe.Sizeof(rtmsg{})]byte)(unsafe.Pointer(&body))[:])
	// RTA_GATEWAY = 5, RTA_OIF = 4
	g := gw
	if v4 := gw.To4(); v4 != nil {
		g = v4
	}
	msg.appendAttr(5 /*RTA_GATEWAY*/, g)
	oif := make([]byte, 4)
	binary.LittleEndian.PutUint32(oif, uint32(idx))
	msg.appendAttr(4 /*RTA_OIF*/, oif)
	return talk(msg.bytes())
}

// writeResolvConf renders /etc/resolv.conf in the init's own
// filesystem. Each container that wants this file in its rootfs
// must bind-mount it explicitly (configurable via PodSpec.Mounts).
func writeResolvConf(dns []string) error {
	if err := os.MkdirAll("/etc", 0o755); err != nil {
		return err
	}
	var buf []byte
	for _, s := range dns {
		buf = append(buf, "nameserver "...)
		buf = append(buf, s...)
		buf = append(buf, '\n')
	}
	return os.WriteFile("/etc/resolv.conf", buf, 0o644)
}

// --- netlink message builder ---

type nlmsg struct {
	buf []byte
}

func newMessage(msgType uint16, flags uint16) *nlmsg {
	m := &nlmsg{buf: make([]byte, syscall.NLMSG_HDRLEN)}
	hdr := (*syscall.NlMsghdr)(unsafe.Pointer(&m.buf[0]))
	hdr.Type = msgType
	hdr.Flags = flags
	hdr.Seq = 1
	return m
}

func (m *nlmsg) append(b []byte) {
	m.buf = append(m.buf, b...)
	m.pad()
}

func (m *nlmsg) appendAttr(typ uint16, value []byte) {
	attr := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint16(attr[0:2], uint16(4+len(value)))
	binary.LittleEndian.PutUint16(attr[2:4], typ)
	copy(attr[4:], value)
	// Pad attribute itself to 4 bytes.
	for len(attr)%4 != 0 {
		attr = append(attr, 0)
	}
	m.buf = append(m.buf, attr...)
}

func (m *nlmsg) pad() {
	for len(m.buf)%4 != 0 {
		m.buf = append(m.buf, 0)
	}
}

func (m *nlmsg) bytes() []byte {
	hdr := (*syscall.NlMsghdr)(unsafe.Pointer(&m.buf[0]))
	hdr.Len = uint32(len(m.buf))
	return m.buf
}
