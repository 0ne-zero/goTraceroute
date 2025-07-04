package net

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/0ne-zero/traceroute/net/socket"
)

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
