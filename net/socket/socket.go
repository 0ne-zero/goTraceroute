package socket

import (
	"net"
	"time"
)

// Socket is an abstraction over raw UDP & ICMP sockets (IPv4 & IPv6)
type Socket interface {
	Close() error
	Port() (port int, err error)
	SetSockOptTimeval(level, opt int, tv *time.Duration) error
	SetSockOptInt(level, opt, value int) error
	SendTo(data []byte, flags, port int, addr net.IP) error
	RecvFrom(buf []byte, flags int) (n int, fromAddr net.IP, err error)
	Bind(port int, addr net.IP) error
}

func NewSocket(family, typ, proto int) (Socket, error) {
	return newSocket(family, typ, proto)
}
