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

	localAddr, err := trace_net.LocalNonLoopbackIP()
	if err != nil {
		return result, err
	}

	sendSocket, err := trace_socket.NewSocket(trace_socket.AF_INET, trace_socket.SOCK_DGRAM, trace_socket.IPPROTO_UDP)
	if err != nil {
		return result, err
	}
	defer sendSocket.Close()

	recvSocket, err := trace_socket.NewSocket(trace_socket.AF_INET, trace_socket.SOCK_RAW, trace_socket.IPPROTO_ICMP)
	if err != nil {
		return result, err
	}
	defer recvSocket.Close()

	timeout := time.Duration(options.TimeoutMs()) * time.Millisecond
	recvSocket.SetSockOptTimeval(trace_socket.SOL_SOCKET, trace_socket.SO_RCVTIMEO, &timeout)

	if err := recvSocket.Bind(options.Port(), localAddr); err != nil {
		return result, err
	}

	ttl := options.FirstHop()
	retry := 0

	for {
		start := time.Now()

		if err := sendProbe(sendSocket, ttl, options.Port(), destAddr); err != nil {
			return result, err
		}

		n, from, err := receiveProbe(recvSocket, options.PacketSize())
		elapsed := time.Since(start)

		if err == nil {
			hop := createHop(true, from, n, elapsed, ttl)
			notify(hop, chans)
			result.Hops = append(result.Hops, hop)

			ttl++
			retry = 0

			if ttl > options.MaxHops() || from.Equal(destAddr) {
				closeNotify(chans)
				return result, nil
			}
		} else {
			retry++
			if retry > options.Retries() {
				notify(TracerouteHop{Success: false, TTL: ttl}, chans)
				ttl++
				retry = 0
			}
			if ttl > options.MaxHops() {
				closeNotify(chans)
				return result, nil
			}
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
