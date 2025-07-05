package traceroute

import (
	"context"
	"errors"
	"net"
	"time"

	trace_net "github.com/0ne-zero/traceroute/net"
	trace_socket "github.com/0ne-zero/traceroute/net/socket"
)

// Traceroute performs a traceroute to the destination using the given options.
// This is the default entry point without cancellation.
func Traceroute(dest string, options *tracerouteOptions, chans ...chan TracerouteHop) (TracerouteResult, error) {
	return TracerouteContext(context.Background(), dest, options, chans...)
}

// TracerouteContext performs a traceroute that can be cancelled via context.
// It works by sending UDP packets with increasing TTL/hop limit and listening for ICMP Time Exceeded or Destination Unreachable replies.
func TracerouteContext(ctx context.Context, dest string, options *tracerouteOptions, chans ...chan TracerouteHop) (TracerouteResult, error) {
	var result TracerouteResult
	result.Hops = []TracerouteHop{}

	// Resolve destination hostname to IP (IPv4 or IPv6 depending on preference)
	destAddr, err := trace_net.ResolveHostnameToIP(dest, options.PreferAddressFamily())
	if err != nil {
		return result, err
	}
	result.DestinationAddress = destAddr

	// Choose address family and ICMP protocol based on destination IP
	af, icmpProto := getSocketConfig(destAddr)

	// Create outbound UDP socket for sending probe packets
	sendSocket, err := trace_socket.NewSocket(af, trace_socket.SOCK_DGRAM, trace_socket.IPPROTO_UDP)
	if err != nil {
		return result, err
	}
	defer sendSocket.Close()

	// Bind send socket to wildcard IP and fixed source port (used to match replies)
	bindIP := trace_net.GetLocalWildcardIP(af)
	if err := sendSocket.Bind(options.SrcPort(), bindIP); err != nil {
		return result, err
	}

	// Create raw ICMP socket to receive ICMP Time Exceeded / Destination Unreachable packets
	recvSocket, err := trace_socket.NewSocket(af, trace_socket.SOCK_RAW, icmpProto)
	if err != nil {
		return result, err
	}
	defer recvSocket.Close()

	// Set receive timeout on the raw socket
	timeout := time.Duration(options.TimeoutMs()) * time.Millisecond
	recvSocket.SetSockOptTimeval(trace_socket.SOL_SOCKET, trace_socket.SO_RCVTIMEO, &timeout)

	ttl := options.FirstHop()
	retriesLeft := options.MaxRetries()

	for ttl <= options.MaxHops() {
		// Exit early if context is cancelled
		select {
		case <-ctx.Done():
			closeNotify(chans)
			return result, ctx.Err()
		default:
		}

		// Set TTL / hop limit for the next probe
		if err := setTTL(sendSocket, af, ttl); err != nil {
			return result, err
		}

		start := time.Now()

		// Send empty UDP packet to destination at specified port
		// The goal is to trigger ICMP Time Exceeded replies from routers
		if err := sendSocket.SendTo([]byte{0x0}, 0, options.DestPort(), destAddr); err != nil {
			return result, err
		}

		// Receive raw ICMP reply: contains outer IP header + ICMP header + quoted original IP + UDP headers
		replyData, from, err := receiveProbe(recvSocket)
		elapsed := time.Since(start)
		if err != nil {
			// Retry this hop if retries left, otherwise record as timeout
			if retriesLeft > 0 {
				retriesLeft--
				continue
			}
			hop := newTracerouteHop(false, from, len(replyData), elapsed, ttl)
			notify(hop, chans)
			result.Hops = append(result.Hops, hop)

			// Continue probing with higher ttl
			ttl++
			retriesLeft = options.MaxRetries()
			continue
		}

		// Parse quoted UDP header in ICMP payload to check if the ICMP reply is for our probe
		srcPort, dstPort, err := trace_net.ParseQuotedUDPHeader(replyData, af)
		if err != nil || srcPort != options.SrcPort() || dstPort != options.DestPort() {
			continue
		}

		// Valid response: add hop to results
		hop := newTracerouteHop(true, from, len(replyData), elapsed, ttl)
		notify(hop, chans)
		result.Hops = append(result.Hops, hop)

		// Stop if we reached the destination
		if from.Equal(destAddr) {
			closeNotify(chans)
			return result, nil
		}

		ttl++
		retriesLeft = options.MaxRetries()
	}

	closeNotify(chans)
	return result, nil
}

// setTTL sets the TTL/hop limit on the UDP socket for IPv4 or IPv6.
func setTTL(sock trace_socket.Socket, af, ttl int) error {
	switch af {
	case trace_socket.AF_INET:
		return sock.SetSockOptInt(trace_socket.IPPROTO_IP, trace_socket.IP_TTL, ttl)
	case trace_socket.AF_INET6:
		return sock.SetSockOptInt(trace_socket.IPPROTO_IPV6, trace_socket.IPV6_UNICAST_HOPS, ttl)
	default:
		return errors.New("invalid address family")
	}
}

// receiveProbe reads raw ICMP reply data and reports sender IP.
func receiveProbe(sock trace_socket.Socket) ([]byte, net.IP, error) {
	buf := make([]byte, 512) // enough for IP+ICMP+quoted original packet
	n, from, err := sock.RecvFrom(buf, 0)
	return buf[:n], from, err
}

// getSocketConfig chooses address family and ICMP protocol based on destination IP.
func getSocketConfig(dest net.IP) (af, icmpProto int) {
	if trace_net.GetIPFamily(dest) == trace_socket.AF_INET6 {
		return trace_socket.AF_INET6, trace_socket.IPPROTO_ICMPV6
	}
	return trace_socket.AF_INET, trace_socket.IPPROTO_ICMP
}
