package icmp

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/0ne-zero/goTraceroute/pkg/core/hop"
	"github.com/0ne-zero/goTraceroute/pkg/core/options"
	"github.com/0ne-zero/goTraceroute/pkg/core/probe"
	trace_net "github.com/0ne-zero/goTraceroute/pkg/net"
	trace_socket "github.com/0ne-zero/goTraceroute/pkg/net/socket"
)

const (
	icmpHeaderLength = 8
	// ICMP capture read timeout; lets us check ctx.Done every N ms in HandleProbeICMPResponse
	icmpCaptureReadTimeoutMs = 50
	icmpReadPacketSize       = 512
)

// HandleProbeICMPResponse listens for ICMP replies filtered by quoted transport ports matching the probe
// Notifies readiness by sending a signal on readyChan and sends the result on resChan
func HandleProbeICMPResponse(ctx context.Context, sock trace_socket.Socket, probeReq *probe.ProbeRequest, readyChan chan<- struct{}, resChan chan<- probe.ProbeResponse) {
	res := probe.ProbeResponse{
		TracerouteHop: hop.NewTracerouteHop(false, nil, 0, 0, probeReq.TTL),
	}

	defer func() {
		resChan <- res
		close(resChan)
	}()

	buf := make([]byte, 512) // Enough for IP + ICMP + quoted original IP + transport header

	readyChan <- struct{}{}

	for {
		select {
		case <-ctx.Done():
			res.Err = ctx.Err()
			return
		default:
			n, from, err := sock.RecvFrom(buf, 0)
			res.ElapsedTime = time.Since(probeReq.StartTime)
			if err != nil {
				// Ignore unimportant errors and try again
				if errors.Is(err, trace_socket.NET_EAGAIN) || errors.Is(err, trace_socket.NET_EWOULDBLOCK) {
					continue
				}
				res.Err = err
				return
			}
			replyData := buf[:n]
			// Extract quoted ports from ICMP payload
			srcPort, destPort, err := extractICMPQuotedTransportPorts(replyData, probeReq.AF)
			if err != nil {
				continue
			}

			var expectedDestPort int
			if probeReq.Options.ProbeProtocol() == options.PROTOCOL_UDP {
				expectedDestPort = probeReq.Options.UDPDestPort()
			} else {
				expectedDestPort = probeReq.Options.TCPDestPort()
			}

			if srcPort != probeReq.SrcPort || destPort != expectedDestPort {
				continue // unrelated ICMP, wait for next
			}

			res.Success = true
			res.Address = from
			res.ReceivedBytesLen = n
			if from.Equal(probeReq.DestAddr) {
				res.ReachedDest = true
			}
			return
		}
	}
}

// extractICMPQuotedTransportPorts extracts source and destination ports from the transport header(TCP or UDP) of ICMP reply request i.e. IP + ICMP Header + ICMP Payload (Quoted IP + UDP Headers)
func extractICMPQuotedTransportPorts(packet []byte, af int) (int, int, error) {
	// Skip the outer IP packet (the actual packet caused routing from destination to us)
	packet, err := trace_net.SkipIPHeader(packet, af)
	if err != nil {
		return 0, 0, err
	}

	// Skip the ICMP header
	packet = skipICMPHeader(packet)
	// Skip the ICMP quoted IP packet
	packet, err = trace_net.SkipIPHeader(packet, af)
	if err != nil {
		return 0, 0, err
	}

	// Extract UDP src.port & dst.port
	udpHeader := packet
	srcPort := int(binary.BigEndian.Uint16(udpHeader[0:2]))
	dstPort := int(binary.BigEndian.Uint16(udpHeader[2:4]))

	return srcPort, dstPort, nil
}

func getICMPProtoByAddressFamily(af int) int {
	if af == trace_socket.AF_INET {
		return trace_socket.IPPROTO_ICMP
	}
	return trace_socket.IPPROTO_ICMPV6
}

// CreateICMPSocket creates a raw ICMP socket with a receive timeout for given IP family
func CreateICMPSocket(opts *options.Options, af int) (trace_socket.Socket, error) {
	icmpProto := getICMPProtoByAddressFamily(af)
	inboundSocket, err := trace_socket.NewSocket(af, trace_socket.SOCK_RAW, icmpProto)
	if err != nil {
		return nil, err
	}

	// Set receive timeout on the raw socket
	timeout := icmpCaptureReadTimeoutMs * time.Millisecond
	err = inboundSocket.SetSockOptTimeval(trace_socket.SOL_SOCKET, trace_socket.SO_RCVTIMEO, &timeout)
	return inboundSocket, err
}

// skipICMPHeader returns the slice of data after the ICMP header in the packet.
func skipICMPHeader(packet []byte) []byte {
	return packet[icmpHeaderLength:]
}
