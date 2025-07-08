package net

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	trace_socket "github.com/0ne-zero/traceroute/pkg/net/socket"
)

// ResolveHostnameToIP resolves hostname to preferred IP family (IPv4 or IPv6)
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

// ReverseLookup does reverse DNS lookup with timeout
func ReverseLookup(addr string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, addr)
	if err == nil && len(names) > 0 {
		return names[0]
	}
	return ""
}

// GetIPFamily returns AF_INET (IPv4), AF_INET6 (IPv6), or -1.
func GetIPFamily(ip net.IP) int {
	if ip == nil {
		return -1
	}
	if ip.To4() != nil {
		return trace_socket.AF_INET
	}
	if ip.To16() != nil {
		return trace_socket.AF_INET6
	}
	return -1
}

// SkipIPHeader returns the slice of data after the IP header in the packet
// It uses the address family to determine the IP header length
func SkipIPHeader(packet []byte, af int) ([]byte, error) {
	if len(packet) == 0 {
		return nil, errors.New("empty packet")
	}

	switch af {
	case trace_socket.AF_INET:
		if len(packet) < 20 {
			return nil, errors.New("packet too short for IPv4 header")
		}
		// IPv4 header length is variable and specified in the first byte
		// IPv4 header length in 32-bit words (4 bytes)
		hdrLen := int(packet[0]&0x0F) * 4
		if hdrLen < 20 || hdrLen > len(packet) {
			return nil, errors.New("invalid IPv4 header length")
		}
		return packet[hdrLen:], nil

	case trace_socket.AF_INET6:
		// IPv6 header length is fixed to 40 bytes
		const ipv6HeaderLen = 40
		if len(packet) < ipv6HeaderLen {
			return nil, errors.New("packet too short for IPv6 header")
		}
		return packet[ipv6HeaderLen:], nil

	default:
		return nil, errors.New("unknown address family")
	}
}

// GetLocalWildcardIP returns wildcard IP for family
func GetLocalWildcardIP(family int) net.IP {
	if family == trace_socket.AF_INET6 {
		return net.ParseIP("::")
	}
	return net.ParseIP("0.0.0.0")
}

// GetOutboundAddr returns local IP used to reach dest IP
func GetOutboundAddr(destIP net.IP) (net.IP, error) {
	var network string

	switch GetIPFamily(destIP) {
	case trace_socket.AF_INET:
		network = "udp4"
	case trace_socket.AF_INET6:
		network = "udp6"
	default:
		return nil, fmt.Errorf("invalid destination IP: %v", destIP)
	}

	conn, err := net.Dial(network, net.JoinHostPort(destIP.String(), "0"))
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("failed to cast LocalAddr to *net.UDPAddr")
	}

	return localAddr.IP, nil
}

// GetInterfaceByIP returns interface for given local IP
func GetInterfaceByIP(localIP net.IP) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		// Skip down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip.Equal(localIP) {
				return &iface, nil
			}
		}
	}

	return nil, errors.New("interface not found for IP: " + localIP.String())
}

// PickRandomPort returns a random ephemeral port
func PickRandomPort() (int, error) {
	const minPort = 32768
	const maxPort = 61000
	var b [2]byte

	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}

	// Convert 2 bytes to uint16
	val := binary.BigEndian.Uint16(b[:])

	// Map val into [minPort, maxPort)
	port := int(val)%(maxPort-minPort) + minPort
	return port, nil
}

// RandomSeq returns a random uint32 sequence number
func RandomSeq() uint32 {
	var b [4]byte
	_, err := rand.Read(b[:])
	if err != nil {
		// fallback to timestamp or constant if crypto/rand fails
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}

// Returns the first non-loopback IP address (IPv4 or IPv6)
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
