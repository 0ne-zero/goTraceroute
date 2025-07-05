package net

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/0ne-zero/traceroute/net/socket"
)

const icmpHeaderLength = 8

// ResolveHostnameToIP resolves a hostname to an IP address,
// preferring the specified address family (e.g., IPv4Family or IPv6Family).
func ResolveHostnameToIP(dest string, preferAddressFamily int) (net.IP, error) {
	addrs, err := net.LookupHost(dest)
	if err != nil {
		return nil, err
	}

	var fallbackIPs []net.IP
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if GetIPFamily(ip) == preferAddressFamily {
			return ip, nil
		}
		fallbackIPs = append(fallbackIPs, ip)
	}

	if len(fallbackIPs) > 0 {
		return fallbackIPs[0], nil
	}

	return nil, fmt.Errorf("no valid IP address found for host %s", dest)
}

// Resolves IP address to hostname
func ReverseLookup(addr string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, addr)
	if err == nil && len(names) > 0 {
		return names[0]
	}
	return ""
}

func GetIPFamily(ip net.IP) int {
	if ip == nil {
		return -1
	}
	if ip.To4() != nil {
		return socket.AF_INET
	}
	if ip.To16() != nil {
		return socket.AF_INET6
	}
	return -1
}

// SkipIPHeader returns the slice of data after the IP header in the packet.
// It uses the address family to determine the IP header length.
// For IPv4, header length is variable and specified in the first byte.
// For IPv6, header length is fixed to 40 bytes.
func SkipIPHeader(packet []byte, af int) ([]byte, error) {
	if len(packet) == 0 {
		return nil, errors.New("empty packet")
	}

	switch af {
	case socket.AF_INET:
		if len(packet) < 20 {
			return nil, errors.New("packet too short for IPv4 header")
		}
		// IPv4 header length in 32-bit words (4 bytes)
		hdrLen := int(packet[0]&0x0F) * 4
		if hdrLen < 20 || hdrLen > len(packet) {
			return nil, errors.New("invalid IPv4 header length")
		}
		return packet[hdrLen:], nil

	case socket.AF_INET6:
		const ipv6HeaderLen = 40
		if len(packet) < ipv6HeaderLen {
			return nil, errors.New("packet too short for IPv6 header")
		}
		return packet[ipv6HeaderLen:], nil

	default:
		return nil, errors.New("unknown address family")
	}
}

// SkipICMPHeader returns the slice of data after the ICMP header in the packet.
func SkipICMPHeader(packet []byte) []byte {
	return packet[icmpHeaderLength:]
}

// ParseQuotedUDPHeader extracts UDP source and destination ports from ICMP reply request i.e. IP + ICMP Header + ICMP Payload (Quoted IP + UDP Headers)
func ParseQuotedUDPHeader(packet []byte, af int) (int, int, error) {
	// Skip the outer IP packet (the actual packet caused routing from destination to us)
	packet, err := SkipIPHeader(packet, af)
	if err != nil {
		return 0, 0, err
	}

	// Skip the ICMP header
	packet = SkipICMPHeader(packet)
	// Skip the ICMP quoted IP packet
	packet, err = SkipIPHeader(packet, af)
	if err != nil {
		return 0, 0, err
	}

	// Extract UDP src.port & dst.port
	udpHeader := packet
	srcPort := int(binary.BigEndian.Uint16(udpHeader[0:2]))
	dstPort := int(binary.BigEndian.Uint16(udpHeader[2:4]))

	return srcPort, dstPort, nil
}

func GetLocalWildcardIP(family int) net.IP {
	if family == socket.AF_INET6 {
		return net.ParseIP("::")
	}
	return net.ParseIP("0.0.0.0")
}

// Returns the first non-loopback IP address (IPv4 or IPv6).
// NEVER USED
// func LocalNonLoopbackIP(family int) (net.IP, error) {
// 	addrs, err := net.InterfaceAddrs()
// 	if err != nil {
// 		return nil, err
// 	}

// 	for _, a := range addrs {
// 		ipnet, ok := a.(*net.IPNet)
// 		if !ok {
// 			continue
// 		}
// 		if ipnet.IP.IsLoopback() || (ipnet.IP.To16() != nil && ipnet.IP.IsLinkLocalUnicast()) {
// 			continue
// 		}

// 		if GetIPFamily(ipnet.IP) == family {
// 			return ipnet.IP, nil
// 		}
// 	}

// 	return nil, errors.New("no non-loopback IP address found with given family")
// }
