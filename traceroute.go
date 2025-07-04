package traceroute

import (
	"context"
	"errors"
	"time"

	"net"

	trace_net "github.com/0ne-zero/traceroute/net"
	trace_socket "github.com/0ne-zero/traceroute/net/socket"
)

// Traceroute performs a traceroute to the destination using the given options and optional channels.
func Traceroute(dest string, options *tracerouteOptions, chans ...chan TracerouteHop) (TracerouteResult, error) {
	return TracerouteContext(context.Background(), dest, options, chans...)
}

// TracerouteContext performs a traceroute to the destination using the given options and optional channels.
// It stops early if the context is canceled.
func TracerouteContext(ctx context.Context, dest string, options *tracerouteOptions, chans ...chan TracerouteHop) (TracerouteResult, error) {
	var result TracerouteResult
	result.Hops = []TracerouteHop{}

	destAddr, err := trace_net.ResolveHostnameToIP(dest, options.PreferAddressFamily())
	if err != nil {
		return result, err
	}
	result.DestinationAddress = destAddr

	// Setup socket configs based on destination IP version
	addressFamily := trace_socket.AF_INET
	icmpProto := trace_socket.IPPROTO_ICMP
	destIPFamily := trace_net.GetIPFamily(destAddr)
	if destIPFamily == trace_socket.AF_INET6 {
		addressFamily = trace_socket.AF_INET6
		icmpProto = trace_socket.IPPROTO_ICMPV6
	}

	// Create outbound socket
	sendSocket, err := trace_socket.NewSocket(addressFamily, trace_socket.SOCK_DGRAM, trace_socket.IPPROTO_UDP)
	if err != nil {
		return result, err
	}
	defer sendSocket.Close()

	// Create inbound socket
	recvSocket, err := trace_socket.NewSocket(addressFamily, trace_socket.SOCK_RAW, icmpProto)
	if err != nil {
		return result, err
	}
	defer recvSocket.Close()

	// Set timeout for inbound socket
	timeout := time.Duration(options.TimeoutMs()) * time.Millisecond
	recvSocket.SetSockOptTimeval(trace_socket.SOL_SOCKET, trace_socket.SO_RCVTIMEO, &timeout)

	ttl := options.FirstHop()
	retriesLeft := options.MaxRetries()

	for {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			closeNotify(chans)
			return result, ctx.Err()
		default:

		}

		if ttl > options.MaxHops() {
			closeNotify(chans)
			return result, nil
		}

		// Send UDP probe with current TTL
		start := time.Now()
		err := sendProbe(sendSocket, addressFamily, ttl, options.Port(), destAddr)
		if err != nil {
			return result, err
		}

		// Receive ICMP reply
		n, from, err := receiveProbe(recvSocket, options.PacketSize())
		elapsed := time.Since(start)

		if err != nil {
			// Retry if retries left, otherwise report timeout hop
			if retriesLeft > 0 {
				retriesLeft--
				continue
			}

			hop := newTracerouteHop(false, from, n, elapsed, ttl)
			notify(hop, chans)
			result.Hops = append(result.Hops, hop)

			// Reset retries and increase TTL
			retriesLeft = options.MaxRetries()
			ttl++
			continue
		}

		// Successful hop
		hop := newTracerouteHop(true, from, n, elapsed, ttl)
		notify(hop, chans)
		result.Hops = append(result.Hops, hop)

		// If reached destination, stop traceroute
		if from.Equal(destAddr) {
			closeNotify(chans)
			return result, nil
		}

		// Reset retries and increase TTL
		retriesLeft = options.MaxRetries()
		ttl++
	}
}

func sendProbe(sock trace_socket.Socket, af, ttl, port int, dest net.IP) error {
	switch af {
	case trace_socket.AF_INET:
		if err := sock.SetSockOptInt(trace_socket.IPPROTO_IP, trace_socket.IP_TTL, ttl); err != nil {
			return err
		}
	case trace_socket.AF_INET6:
		if err := sock.SetSockOptInt(trace_socket.IPPROTO_IPV6, trace_socket.IPV6_UNICAST_HOPS, ttl); err != nil {
			return err
		}
	default:
		return errors.New("invalid address family")
	}
	return sock.SendTo([]byte{0x0}, 0, port, dest)
}

func receiveProbe(sock trace_socket.Socket, packetSize int) (int, net.IP, error) {
	buf := make([]byte, packetSize)
	n, from, err := sock.RecvFrom(buf, 0)
	return n, from, err
}
