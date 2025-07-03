package net

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/aeden/traceroute/net/socket"
)

// Return the first non-loopback IP address (IPv4 or IPv6).
func LocalNonLoopbackIP(family int) (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}

		if GetIPFamily(ipnet.IP) == family {
			return ipnet.IP, nil
		}
	}

	return nil, errors.New("no non-loopback IP address found with given family")
}

// Resolves hostname to IP
func ResolveHostnameToIP(dest string) (net.IP, error) {
	addrs, err := net.LookupHost(dest)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ipAddr, err := net.ResolveIPAddr("ip", addr)
		if err != nil {
			continue
		}
		// Return the first valid IP (IPv4 or IPv6)
		if ipAddr.IP != nil {
			return ipAddr.IP, nil
		}
	}
	return nil, errors.New("no valid IP address found for host")
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
