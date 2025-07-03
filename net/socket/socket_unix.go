//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package socket

import (
	"errors"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

const (
	AF_INET  = unix.AF_INET
	AF_INET6 = unix.AF_INET6

	SOCK_DGRAM = unix.SOCK_DGRAM
	SOCK_RAW   = unix.SOCK_RAW

	IPPROTO_UDP    = unix.IPPROTO_UDP
	IPPROTO_ICMP   = unix.IPPROTO_ICMP
	IPPROTO_ICMPV6 = unix.IPPROTO_ICMPV6

	SOL_SOCKET        = unix.SOL_SOCKET
	SO_RCVTIMEO       = unix.SO_RCVTIMEO
	IPPROTO_IP        = unix.IPPROTO_IP
	IPPROTO_IPV6      = unix.IPPROTO_IPV6
	IP_TTL            = unix.IP_TTL
	IPV6_UNICAST_HOPS = unix.IPV6_UNICAST_HOPS
)

type unixSocket struct {
	fd int
	af int // Address Family e.g. IPv4 or IPv6
}

func newSocket(family, typ, proto int) (Socket, error) {
	fd, err := unix.Socket(family, typ, proto)
	if err != nil {
		return nil, err
	}
	return &unixSocket{fd: fd, af: family}, nil
}

func (s *unixSocket) Close() error {
	return unix.Close(s.fd)
}

func (s *unixSocket) SetSockOptTimeval(level, opt int, tv *time.Duration) error {
	tvUnix := unix.NsecToTimeval(tv.Nanoseconds())
	return unix.SetsockoptTimeval(s.fd, level, opt, &tvUnix)
}

func (s *unixSocket) SetSockOptInt(level, opt, value int) error {
	return unix.SetsockoptInt(s.fd, level, opt, value)
}

func (s *unixSocket) Bind(port int, ip net.IP) error {
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
	return errors.New("invalid address family has been set on socket")
}

func (s *unixSocket) SendTo(data []byte, flags, port int, addr net.IP) error {
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

// Converts net.IP to *unix.SockaddrInet4
func toSockaddrInet4(ip net.IP, port int) (*unix.SockaddrInet4, error) {
	if ip = ip.To4(); ip == nil {
		return nil, errors.New("Bind IP is not an IPv4")
	}
	addr := &unix.SockaddrInet4{Addr: [4]byte(ip), Port: port}
	return addr, nil
}

// Converts net.IP to *unix.SockaddrInet6
func toSockaddrInet6(ip net.IP, port int) (*unix.SockaddrInet6, error) {
	if ip = ip.To16(); ip == nil {
		return nil, errors.New("Bind IP is not an IPv6")
	}
	addr := &unix.SockaddrInet6{Addr: [16]byte(ip), Port: port}
	return addr, nil
}
