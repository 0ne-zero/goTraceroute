package udp

import (
	"github.com/0ne-zero/traceroute/pkg/core/probe"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CraftUDPDatagram builds a UDP datagram with correct ports and checksum
func CraftUDPDatagram(probe *probe.ProbeRequest) ([]byte, error) {
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(probe.SrcPort),
		DstPort: layers.UDPPort(probe.Options.UDPDestPort()),
	}

	// Must call SetNetworkLayerForChecksum
	ip := &layers.IPv4{SrcIP: probe.SrcAddr, DstIP: probe.DestAddr}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	if err := udp.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
