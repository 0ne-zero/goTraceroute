package traceroute

import (
	"errors"

	"github.com/0ne-zero/goTraceroute/pkg/core/options"
	"github.com/0ne-zero/goTraceroute/pkg/core/probe"
	"github.com/0ne-zero/goTraceroute/pkg/net/icmp"
	trace_socket "github.com/0ne-zero/goTraceroute/pkg/net/socket"
	trace_net_tcp "github.com/0ne-zero/goTraceroute/pkg/net/tcp"
	trace_net_udp "github.com/0ne-zero/goTraceroute/pkg/net/udp"
)

// setTTL sets the TTL/hop limit on the UDP socket for IPv4 or IPv6.
func setTTL(sock trace_socket.Socket, af, ttl int) error {
	switch af {
	case trace_socket.AF_INET:
		return sock.SetSockOptInt(trace_socket.IPPROTO_IP, trace_socket.IP_TTL, ttl)
	case trace_socket.AF_INET6:
		return sock.SetSockOptInt(trace_socket.IPPROTO_IPV6, trace_socket.IPV6_UNICAST_HOPS, ttl)
	default:
		// panic("invalid address family")
		return errors.New("invalid address family")
	}
}

// sendProbe sends UDP or TCP packet with incremental ttl to the destination
func sendProbe(sock trace_socket.Socket, probe probe.ProbeRequest) error {
	if err := setTTL(sock, probe.AF, probe.TTL); err != nil {
		return err
	}
	switch probe.Options.ProbeProtocol() {
	case options.PROTOCOL_UDP:
		udpPacket, err := trace_net_udp.CraftUDPDatagram(&probe)
		if err != nil {
			return err
		}
		return sock.SendTo(udpPacket, 0, probe.DestAddr, probe.Options.UDPDestPort())
	case options.PROTOCOL_TCP:
		// Crafting TCP SYN manually and send it
		tcpSynPacket, err := trace_net_tcp.CraftTCPSynPacket(&probe)
		if err != nil {
			return err
		}
		return sock.SendTo(tcpSynPacket, 0, probe.DestAddr, probe.Options.TCPDestPort())
	default:
		// panic("unknown probe protocol")
		return errors.New("unknown probe protocol")
	}
}

// getSocketConfig chooses socket type and protocol for socket based on options given to the library
func getOutboundSocketConfig(opts *options.Options) (int, int) {
	switch opts.ProbeProtocol() {
	case options.PROTOCOL_UDP:
		return trace_socket.SOCK_RAW, trace_socket.IPPROTO_UDP
	case options.PROTOCOL_TCP:
		return trace_socket.SOCK_RAW, trace_socket.IPPROTO_TCP
	default:
		panic("How did you set Probe Protocol to something other than TCP and UDP ?!")
	}
}

// Returns outbound socket for sending UDP probe packets and inbound socket for receiving ICMP reply packets
func setupSockets(opts *options.Options, af int) (trace_socket.Socket, trace_socket.Socket, error) {
	socketType, socketProto := getOutboundSocketConfig(opts)
	outboundSocket, err := trace_socket.NewSocket(af, socketType, socketProto)
	if err != nil {
		return nil, nil, err
	}

	// Create raw ICMP socket to receive ICMP Time Exceeded / Destination Unreachable packets when using UDP protocol to probe
	inboundICMPSocket, err := icmp.CreateICMPSocket(opts, af)
	return outboundSocket, inboundICMPSocket, err
}
