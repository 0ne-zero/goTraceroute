package net

import (
	"context"
	"errors"
	"net"
	"time"
)

// Return the first non-loopback IP address (IPv4 or IPv6).
func LocalNonLoopbackIP() (ip net.IP, err error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}

		ip := ipnet.IP

		// Return first IPv4 or IPv6 address
		return ip, nil
	}

	return nil, errors.New("no non-loopback IP address found")
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
