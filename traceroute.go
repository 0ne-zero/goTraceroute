package traceroute

import (
	"time"

	"net"

	trace_net "github.com/aeden/traceroute/net"
	trace_socket "github.com/aeden/traceroute/net/socket"
)

// Traceroute performs a traceroute to the destination using the given options and optional channels.
func Traceroute(dest string, options *tracerouteOptions, chans ...chan TracerouteHop) (TracerouteResult, error) {
	var result TracerouteResult
	result.Hops = []TracerouteHop{}

	destAddr, err := trace_net.ResolveHostnameToIP(dest)
	if err != nil {
		return result, err
	}
	result.DestinationAddress = destAddr

	// Setup sockets configs based on destination IP version
	addressFamily := trace_socket.AF_INET
	icmpProto := trace_socket.IPPROTO_ICMP
	// Get destination IP family (e.g. IPv4/IPv6)
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

	// Get local IP address and bind inbound socket to it
	localAddr, err := trace_net.LocalNonLoopbackIP(destIPFamily)
	if err != nil {
		return result, err
	}
	if err := recvSocket.Bind(options.Port(), localAddr); err != nil {
		return result, err
	}

	ttl := options.FirstHop()
	retryCounter := 0

	for {
		// Stop traceroute and return the result if ttl exceeded maximum allowed hops
		if ttl > options.MaxHops() {
			closeNotify(chans)
			return result, nil
		}

		// Send UDP packet with specified Time-To-Live to probe
		start := time.Now()
		if err := sendProbe(sendSocket, ttl, options.Port(), destAddr); err != nil {
			return result, err
		}

		// Receive ICMP response
		n, from, err := receiveProbe(recvSocket, options.PacketSize())
		elapsed := time.Since(start)

		if err != nil {
			// Continue to the next ttl if the maximum retry has been done
			if retryCounter == options.MaxRetries() {
				hop := createHop(false, from, n, elapsed, ttl)
				notify(hop, chans)
				result.Hops = append(result.Hops, hop)

				// Reset retry counter
				retryCounter = 0
				// Increase ttl
				ttl += 1

				// Continue the traceroute
			}
			// Retry the traceroute with the same TTL
			retryCounter += 1
		} else {
			hop := createHop(true, from, n, elapsed, ttl)
			notify(hop, chans)
			result.Hops = append(result.Hops, hop)

			// Stop traceroute and return the result if the response was from the destination itself (we reached the end)
			if from.Equal(destAddr) {
				closeNotify(chans)
				return result, nil
			}

			// Reset retry counter
			retryCounter = 0
			// Increase ttl
			ttl += 1

			// Continue the traceroute
		}
	}
}

func sendProbe(sock trace_socket.Socket, ttl, port int, dest net.IP) error {
	if err := sock.SetSockOptInt(trace_socket.IPPROTO_IP, trace_socket.IP_TTL, ttl); err != nil {
		return err
	}
	return sock.SendTo([]byte{0x0}, 0, port, dest)
}

func receiveProbe(sock trace_socket.Socket, packetSize int) (int, net.IP, error) {
	buf := make([]byte, packetSize)
	n, from, err := sock.RecvFrom(buf, 0)
	return n, from, err
}

func createHop(success bool, addr net.IP, n int, elapsed time.Duration, ttl int) TracerouteHop {
	hop := TracerouteHop{
		Success:     success,
		Address:     addr,
		Bytes:       n,
		ElapsedTime: elapsed,
		TTL:         ttl,
	}
	if success {
		hop.Host = trace_net.ReverseLookup(hop.AddressString(), time.Duration(DefaultTimeoutMs)*time.Millisecond)
	}
	return hop
}
