//go:build windows
// +build windows

// This file provides low-level socket operations for Windows platform
package socket

import (
	"errors"
	"net"
	"time"

	"golang.org/x/sys/windows"
)

const (
	// Address families
	AF_INET  = windows.AF_INET
	AF_INET6 = windows.AF_INET6

	// Socket types
	SOCK_DGRAM = windows.SOCK_DGRAM
	SOCK_RAW   = windows.SOCK_RAW

	// Protocol numbers
	IPPROTO_IP     = windows.IPPROTO_IP
	IPPROTO_UDP    = windows.IPPROTO_UDP
	IPPROTO_TCP    = windows.IPPROTO_TCP
	IPPROTO_ICMP   = windows.IPPROTO_ICMP
	IPPROTO_ICMPV6 = windows.IPPROTO_ICMPV6
	IPPROTO_IPV6   = windows.IPPROTO_IPV6

	// Socket options
	SOL_SOCKET        = windows.SOL_SOCKET
	SO_RCVTIMEO       = windows.SO_RCVTIMEO
	IP_TTL            = windows.IP_TTL
	IPV6_UNICAST_HOPS = windows.IPV6_UNICAST_HOPS

	// Common network errors
	NET_EAGAIN      = windows.WSAEWOULDBLOCK
	NET_EWOULDBLOCK = windows.WSAEWOULDBLOCK
)

// windowsSocket represents a socket handle and address family on Windows
type windowsSocket struct {
	handle windows.Handle // like socket file descriptor on unix
	af     int            // address family (AF_INET or AF_INET6)
}

// newSocket creates a new socket with given family, type, and protocol
func newSocket(family, typ, proto int) (Socket, error) {
	sock, err := windows.Socket(family, typ, proto)
	if err != nil {
		return nil, err
	}
	return &windowsSocket{handle: sock, af: family}, nil
}

// Bind binds the socket to the given IP and port
func (s *windowsSocket) Bind(ip net.IP, port int) error {
	if s.af == AF_INET {
		sa, err := toSockaddrInet4(ip, port)
		if err != nil {
			return err
		}
		return windows.Bind(s.handle, sa)
	} else if s.af == AF_INET6 {
		sa, err := toSockaddrInet6(ip, port)
		if err != nil {
			return err
		}
		return windows.Bind(s.handle, sa)
	}
	return errors.New("unsupported address family")
}

// SendTo sends data to the specified IP address and port
func (s *windowsSocket) SendTo(data []byte, flags int, ip net.IP, port int) error {
	if s.af == AF_INET {
		sa, err := toSockaddrInet4(ip, port)
		if err != nil {
			return err
		}
		return windows.Sendto(s.handle, data, flags, sa)
	} else if s.af == AF_INET6 {
		sa, err := toSockaddrInet6(ip, port)
		if err != nil {
			return err
		}
		return windows.Sendto(s.handle, data, flags, sa)
	}
	return errors.New("unsupported address family")
}

// RecvFrom receives data and returns number of bytes, sender IP, and error if any
func (s *windowsSocket) RecvFrom(buf []byte, flags int) (int, net.IP, error) {
	n, sa, err := windows.Recvfrom(s.handle, buf, flags)
	if err != nil {
		return 0, nil, err
	}
	switch sa := sa.(type) {
	case *windows.SockaddrInet4:
		return n, net.IP(sa.Addr[:]), nil
	case *windows.SockaddrInet6:
		return n, net.IP(sa.Addr[:]), nil
	default:
		return 0, nil, errors.New("unknown socket address type")
	}
}

// SetSockOptInt sets an integer socket option
func (s *windowsSocket) SetSockOptInt(level, opt, value int) error {
	return windows.SetsockoptInt(s.handle, level, opt, value)
}

// SetSockOptTimeval sets a socket option with a timeval duration
func (s *windowsSocket) SetSockOptTimeval(level, opt int, tv *time.Duration) error {
	tvSec := int32(tv.Seconds())
	tvUsec := int32(tv.Milliseconds()*1000 - int64(tvSec)*1_000_000)
	tvStruct := windows.Timeval{
		Sec:  tvSec,
		Usec: tvUsec,
	}

	return windows.SetsockoptTimeval(s.handle, level, opt, &tvStruct)
}

// Close closes the socket handle
func (s *windowsSocket) Close() error {
	return windows.Closesocket(s.handle)
}

// toSockaddrInet4 converts net.IP to windows SockaddrInet4 for IPv4
func toSockaddrInet4(ip net.IP, port int) (*windows.SockaddrInet4, error) {
	if ip = ip.To4(); ip == nil {
		return nil, errors.New("IP is not valid IPv4")
	}
	return &windows.SockaddrInet4{Port: port, Addr: [4]byte(ip)}, nil
}

// toSockaddrInet6 converts net.IP to windows SockaddrInet6 for IPv6
func toSockaddrInet6(ip net.IP, port int) (*windows.SockaddrInet6, error) {
	if ip = ip.To16(); ip == nil {
		return nil, errors.New("IP is not valid IPv6")
	}
	return &windows.SockaddrInet6{Port: port, Addr: [16]byte(ip)}, nil
}
