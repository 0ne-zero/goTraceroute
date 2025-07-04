package traceroute

import (
	"errors"
	"time"

	"net"

	trace_net "github.com/0ne-zero/traceroute/net"
	trace_socket "github.com/0ne-zero/traceroute/net/socket"
)

// Traceroute performs a traceroute to the destination using the given options and optional channels.
func Traceroute(dest string, options *tracerouteOptions, chans ...chan TracerouteHop) (TracerouteResult, error) {
	var result TracerouteResult
	result.Hops = []TracerouteHop{}

	destAddr, err := trace_net.ResolveHostnameToIP(dest, options.PreferAddressFamily())
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

	// We don't explicitly bind the raw ICMP/ICMPv6 receive socket to a local address.
	// By default, the kernel will deliver incoming ICMP Time Exceeded replies to our raw socket,
	// regardless of which local IP they arrive on or which interface they come through.
	//
	// This is because the OS routes outgoing probe packets (UDP with incremented TTL/Hop Limit)
	// and keeps track of the source IP. Routers on the path send ICMP replies back to that source IP.
	// Since our raw socket is open and unbound, the kernel delivers those replies to us automatically.
	//
	// Binding the raw socket to a specific local IP or port is usually unnecessary.
	// So instead of binding to "0.0.0.0" or "::", we just let the raw socket listen for all incoming ICMP packets.

	// If we wanted to bind to winldcard or any specific IP, the code would be:
	//     localAddr := net.ParseIP("0.0.0.0")
	//     if addressFamily == trace_socket.AF_INET6 {
	// 	       localAddr = net.ParseIP("::")
	//     }

	//     if err := recvSocket.Bind(options.Port(), localAddr); err != nil {
	// 	       return result, err
	//     }

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
		if err := sendProbe(sendSocket, addressFamily, ttl, options.Port(), destAddr); err != nil {
			return result, err
		}

		// Receive ICMP response
		n, from, err := receiveProbe(recvSocket, options.PacketSize())
		elapsed := time.Since(start)

		if err != nil {
			// Continue to the next ttl if the maximum retry has been done
			if retryCounter == options.MaxRetries() {
				hop := newTracerouteHop(false, from, n, elapsed, ttl)
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
			hop := newTracerouteHop(true, from, n, elapsed, ttl)
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

func sendProbe(sock trace_socket.Socket, af, ttl, port int, dest net.IP) error {
	if af == trace_socket.AF_INET {
		if err := sock.SetSockOptInt(trace_socket.IPPROTO_IP, trace_socket.IP_TTL, ttl); err != nil {
			return err
		}
	} else if af == trace_socket.AF_INET6 {
		if err := sock.SetSockOptInt(trace_socket.IPPROTO_IPV6, trace_socket.IPV6_UNICAST_HOPS, ttl); err != nil {
			return err
		}
	} else {
		return errors.New("invalid address family")
	}
	return sock.SendTo([]byte{0x0}, 0, port, dest)
}

func receiveProbe(sock trace_socket.Socket, packetSize int) (int, net.IP, error) {
	buf := make([]byte, packetSize)
	n, from, err := sock.RecvFrom(buf, 0)
	return n, from, err
}
