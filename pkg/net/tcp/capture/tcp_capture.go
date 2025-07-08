package tcp_capture

import (
	"fmt"
	"net"
	"time"

	"github.com/0ne-zero/traceroute/pkg/core/options"
	"github.com/0ne-zero/traceroute/pkg/core/probe"
	trace_net "github.com/0ne-zero/traceroute/pkg/net"
	trace_socket "github.com/0ne-zero/traceroute/pkg/net/socket"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TCP capture handle read timeout; lets us check ctx.Done() every N ms in HandleProbeTCPResponse
const tcpCaptureReadTimeoutMs = 50

// GetIPLayer returns the IP layer of the packet based on address family IPv4 or IPv6
func GetIPLayer(packet gopacket.Packet, af int) gopacket.Layer {
	if af == trace_socket.AF_INET {
		return packet.Layer(layers.LayerTypeIPv4)
	}
	return packet.Layer(layers.LayerTypeIPv6)
}

// SetTCPCaptureFilter applies a BPF filter on the pcap handle to capture only TCP packets matching probe destination IP and ports
func SetTCPCaptureFilter(handle *pcap.Handle, probe *probe.ProbeRequest) error {
	filter := fmt.Sprintf("tcp and src host %s and src port %d and dst port %d",
		probe.DestAddr.String(), probe.Options.TCPDestPort(), probe.SrcPort)
	return handle.SetBPFFilter(filter)
}

// OpenCaptureHandleByIP opens a live pcap capture handle on the network interface associated with the given source IP address
// uses tcpCaptureReadTimeoutMs read timeout and promiscuous mode to capture all packets on the interface
func OpenCaptureHandleByIP(options *options.Options, srcIP net.IP) (*pcap.Handle, error) {
	const snapshotLen = 65536
	const promiscuous = true
	var timeout = tcpCaptureReadTimeoutMs * time.Millisecond
	iface, err := trace_net.GetInterfaceByIP(srcIP)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface by IP: %w", err)
	}

	handle, err := pcap.OpenLive(iface.Name, snapshotLen, promiscuous, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}
	return handle, nil
}
