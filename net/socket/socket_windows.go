//go:build windows
// +build windows

package socket

import (
	"errors"
	"net"
	"time"

	"golang.org/x/sys/windows"
)

const (
	AF_INET  = windows.AF_INET
	AF_INET6 = windows.AF_INET6

	SOCK_DGRAM = windows.SOCK_DGRAM
	SOCK_RAW   = windows.SOCK_RAW

	IPPROTO_UDP    = windows.IPPROTO_UDP
	IPPROTO_ICMP   = 1 // windows doesn't define IPPROTO_ICMP, fallback
	IPPROTO_ICMPV6 = 58

	SOL_SOCKET        = windows.SOL_SOCKET
	SO_RCVTIMEO       = windows.SO_RCVTIMEO
	IPPROTO_IP        = windows.IPPROTO_IP
	IPPROTO_IPV6      = 41 // IPPROTO_IPV6 is 41 on Windows
	IP_TTL            = windows.IP_TTL
	IPV6_UNICAST_HOPS = 71 // IPV6_UNICAST_HOPS = 71 on Windows

)

type windowsSocket struct {
	handle windows.Handle
	family int
}

func newSocket(family, typ, proto int) (Socket, error) {
	sock, err := windows.Socket(family, typ, proto)
	if err != nil {
		return nil, err
	}
	return &windowsSocket{handle: sock, family: family}, nil
}

func (s *windowsSocket) Close() error {
	return windows.Closesocket(s.handle)
}

func (s *windowsSocket) SetSockOptTimeval(level, opt int, tv *time.Duration) error {
	tvSec := int32(tv.Seconds())
	tvUsec := int32(tv.Milliseconds()*1000 - int64(tvSec)*1_000_000)
	tvStruct := windows.Timeval{
		Sec:  tvSec,
		Usec: tvUsec,
	}

	return windows.SetsockoptTimeval(s.handle, level, opt, &tvStruct)
}

func (s *windowsSocket) SetSockOptInt(level, opt, value int) error {
	return windows.SetsockoptInt(s.handle, level, opt, value)
}

func toSockaddrInet4(ip net.IP, port int) (*windows.SockaddrInet4, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("IP is not valid IPv4")
	}
	var addr [4]byte
	copy(addr[:], ip4)
	return &windows.SockaddrInet4{Port: port, Addr: addr}, nil
}

func toSockaddrInet6(ip net.IP, port int) (*windows.SockaddrInet6, error) {
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, errors.New("IP is not valid IPv6")
	}
	var addr [16]byte
	copy(addr[:], ip16)
	return &windows.SockaddrInet6{Port: port, Addr: addr}, nil
}

func (s *windowsSocket) Bind(port int, ip net.IP) error {
	if s.family == AF_INET {
		sa, err := toSockaddrInet4(ip, port)
		if err != nil {
			return err
		}
		return windows.Bind(s.handle, sa)
	} else if s.family == AF_INET6 {
		sa, err := toSockaddrInet6(ip, port)
		if err != nil {
			return err
		}
		return windows.Bind(s.handle, sa)
	}
	return errors.New("unsupported address family")
}

func (s *windowsSocket) SendTo(data []byte, flags, port int, ip net.IP) error {
	if s.family == AF_INET {
		sa, err := toSockaddrInet4(ip, port)
		if err != nil {
			return err
		}
		return windows.Sendto(s.handle, data, flags, sa)
	} else if s.family == AF_INET6 {
		sa, err := toSockaddrInet6(ip, port)
		if err != nil {
			return err
		}
		return windows.Sendto(s.handle, data, flags, sa)
	}
	return errors.New("unsupported address family")
}

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
