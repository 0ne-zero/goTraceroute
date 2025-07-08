//go:build linux || darwin || freebsd
// +build linux darwin freebsd

// this file provides low-level socket operations for Linux, macOS, FreeBSD
package socket

import (
	"errors"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// Address families
	AF_INET  = unix.AF_INET
	AF_INET6 = unix.AF_INET6

	// Socket types
	SOCK_DGRAM = unix.SOCK_DGRAM
	SOCK_RAW   = unix.SOCK_RAW

	// Protocol numbers
	IPPROTO_IP     = unix.IPPROTO_IP
	IPPROTO_UDP    = unix.IPPROTO_UDP
	IPPROTO_TCP    = unix.IPPROTO_TCP
	IPPROTO_ICMP   = unix.IPPROTO_ICMP
	IPPROTO_ICMPV6 = unix.IPPROTO_ICMPV6
	IPPROTO_IPV6   = unix.IPPROTO_IPV6

	// Socket options
	SOL_SOCKET        = unix.SOL_SOCKET
	SO_RCVTIMEO       = unix.SO_RCVTIMEO
	IP_TTL            = unix.IP_TTL
	IPV6_UNICAST_HOPS = unix.IPV6_UNICAST_HOPS

	// Common network errors
	NET_EAGAIN      = unix.EAGAIN
	NET_EWOULDBLOCK = unix.EWOULDBLOCK
)

// unixSocket wraps a unix socket file descriptor and address family
type unixSocket struct {
	fd int // socket file descriptor
	af int // address family (AF_INET or AF_INET6)
}

// newSocket creates a new unix socket with given family, type and protocol
func newSocket(family, typ, proto int) (Socket, error) {
	fd, err := unix.Socket(family, typ, proto)
	if err != nil {
		return nil, err
	}
	return &unixSocket{fd: fd, af: family}, nil
}

// Bind binds the socket to the specified IP and port
func (s *unixSocket) Bind(ip net.IP, port int) error {
	if s.af == unix.AF_INET {
		addr, err := toSockaddrInet4(ip, port)
		if err != nil {
			return err
		}
		return unix.Bind(s.fd, addr)
	} else if s.af == unix.AF_INET6 {
		addr, err := toSockaddrInet6(ip, port)
		if err != nil {
			return err
		}
		return unix.Bind(s.fd, addr)
	}
	// panic("Invalid address family set on socket")
	return errors.New("unsupported address family")
}

// SendTo sends data to a remote address and port
func (s *unixSocket) SendTo(data []byte, flags int, addr net.IP, port int) error {
	if s.af == AF_INET {
		sockAddr, err := toSockaddrInet4(addr, port)
		if err != nil {
			return err
		}
		return unix.Sendto(s.fd, data, flags, sockAddr)
	} else {
		sockAddr, err := toSockaddrInet6(addr, port)
		if err != nil {
			return err
		}
		return unix.Sendto(s.fd, data, flags, sockAddr)
	}
}

// RecvFrom receives data from the socket returning bytes read and sender IP
func (s *unixSocket) RecvFrom(buf []byte, flags int) (int, net.IP, error) {
	n, from, err := unix.Recvfrom(s.fd, buf, flags)
	if err != nil {
		return 0, nil, err
	}

	switch sa := from.(type) {
	case *unix.SockaddrInet4:
		return n, net.IP(sa.Addr[:]), nil
	case *unix.SockaddrInet6:
		return n, net.IP(sa.Addr[:]), nil
	default:
		return 0, nil, unix.EINVAL
	}
}

// SetSockOptInt sets integer socket option
func (s *unixSocket) SetSockOptInt(level, opt, value int) error {
	return unix.SetsockoptInt(s.fd, level, opt, value)
}

// SetSockOptTimeval sets socket option using a timeval (duration)
func (s *unixSocket) SetSockOptTimeval(level, opt int, tv *time.Duration) error {
	tvUnix := unix.NsecToTimeval(tv.Nanoseconds())
	return unix.SetsockoptTimeval(s.fd, level, opt, &tvUnix)
}

// Close closes the socket file descriptor
func (s *unixSocket) Close() error {
	return unix.Close(s.fd)
}

// toSockaddrInet4 converts net.IP to unix SockaddrInet4 for IPv4
func toSockaddrInet4(ip net.IP, port int) (*unix.SockaddrInet4, error) {
	if ip = ip.To4(); ip == nil {
		return nil, errors.New("IP is not a valid IPv4")
	}
	addr := &unix.SockaddrInet4{Addr: [4]byte(ip), Port: port}
	return addr, nil
}

// toSockaddrInet6 converts net.IP to unix SockaddrInet6 for IPv6
func toSockaddrInet6(ip net.IP, port int) (*unix.SockaddrInet6, error) {
	if ip = ip.To16(); ip == nil {
		return nil, errors.New("IP is not a valid IPv6")
	}
	addr := &unix.SockaddrInet6{Addr: [16]byte(ip), Port: port}
	return addr, nil
}
