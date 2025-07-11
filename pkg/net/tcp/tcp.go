package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/0ne-zero/goTraceroute/pkg/core/hop"
	"github.com/0ne-zero/goTraceroute/pkg/core/probe"
	trace_net "github.com/0ne-zero/goTraceroute/pkg/net"
	trace_socket "github.com/0ne-zero/goTraceroute/pkg/net/socket"
	tcp_capture "github.com/0ne-zero/goTraceroute/pkg/net/tcp/capture"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// tcpFlags holds TCP flag states relevant for probe responses
type tcpFlags struct {
	rst bool
	syn bool
	ack bool
}

// parsedTCPPacket represents key info parsed from a captured TCP packet
type parsedTCPPacket struct {
	srcIP    net.IP
	srcPort  int
	destPort int
	flags    tcpFlags
}

// HandleProbeTCPResponse listens for TCP packets matching the probe
// filtering by source/dest ports and flags (SYN/ACK or RST)
// Notifies readiness by sending a signal on readyChan and sends the result on resChan
func HandleProbeTCPResponse(ctx context.Context, captureHandle *pcap.Handle, probeReq *probe.ProbeRequest, readyChan chan<- struct{}, resChan chan<- probe.ProbeResponse) {
	res := probe.ProbeResponse{
		TracerouteHop: hop.NewTracerouteHop(false, nil, 0, 0, probeReq.TTL),
	}
	defer func() {
		resChan <- res
		close(resChan)
	}()

	// Filter incoming TCP packets
	if err := tcp_capture.SetTCPCaptureFilter(captureHandle, probeReq); err != nil {
		res.Err = err
		return
	}

	// Signal monitoring is ready
	readyChan <- struct{}{}

	for {
		select {
		case <-ctx.Done():
			res.Err = ctx.Err()
			return

		default:
			// Read a TCP packet according to the filter
			packetData, _, err := captureHandle.ReadPacketData()
			res.ElapsedTime = time.Since(probeReq.StartTime)
			if err != nil {
				// Ignore unimportant errors and try again
				if errors.Is(err, pcap.NextErrorTimeoutExpired) {
					continue
				}
				res.Err = err
				return
			}

			// Parse the incoming TCP packet
			parsedPacket, err := parseTCPPacket(packetData, probeReq)
			fmt.Printf("Got packet src=%v srcPort=%v dstPort=%v flags=%+v\n",
				parsedPacket.srcIP, parsedPacket.srcPort, parsedPacket.destPort, parsedPacket.flags)

			if err != nil {
				continue
			}
			// Validate ports to see if it matches with our probe request
			if parsedPacket.destPort != probeReq.SrcPort || parsedPacket.srcPort != probeReq.Options.TCPDestPort() {
				continue
			}

			// It's our packet, it should has either SYN/ACK or RST
			if parsedPacket.flags.rst || (parsedPacket.flags.syn && parsedPacket.flags.ack) {
				res.Success = true
				res.ReachedDest = true
				res.Address = parsedPacket.srcIP
				return

			}
			// else: keep waiting
		}
	}
}

// parseTCPPacket extracts source/destination IP and ports, plus flags, from raw packet data.
func parseTCPPacket(data []byte, probe *probe.ProbeRequest) (*parsedTCPPacket, error) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	ipLayer := tcp_capture.GetIPLayer(packet, probe.AF)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
		return nil, errors.New("missing IP or TCP layer")
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	var srcIP net.IP
	if probe.AF == trace_socket.AF_INET {
		srcIP = ipLayer.(*layers.IPv4).SrcIP
	} else {
		srcIP = ipLayer.(*layers.IPv6).SrcIP
	}

	parsed := &parsedTCPPacket{
		srcIP:    srcIP,
		srcPort:  int(tcp.SrcPort),
		destPort: int(tcp.DstPort),
		flags:    tcpFlags{rst: tcp.RST, syn: tcp.SYN, ack: tcp.ACK},
	}

	return parsed, nil
}

// CraftTCPSynPacket builds a raw TCP SYN packet for the given probe request,
// setting correct ports, sequence number, and IP layer checksum.
func CraftTCPSynPacket(probe *probe.ProbeRequest) ([]byte, error) {
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(probe.SrcPort),
		DstPort: layers.TCPPort(probe.Options.TCPDestPort()),
		Seq:     trace_net.RandomSeq(),
		SYN:     true,
		Window:  14600,
	}

	// Must call SetNetworkLayerForChecksum with IPv4 or IPv6 layer for checksum
	ip := &layers.IPv4{
		SrcIP: probe.SrcAddr,
		DstIP: probe.DestAddr,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := tcp.SerializeTo(buf, serializeOpts); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
