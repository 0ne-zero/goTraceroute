package traceroute

import (
	"errors"
	"net"
)

// Converts a net.IP (IPv4) to [4]byte
func NetIPToFourByte(ip net.IP) ([4]byte, error) {
	res := [4]byte{}
	ip = ip.To4()
	if ip == nil {
		return res, errors.New("invalid IPv4 address")
	}
	return res, nil
}

// Converts a [4]byte to net.IP
func FourByteToNetIP(bytes [4]byte) (net.IP, error) {
	res := net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
	if res == nil {
		return nil, errors.New("failed to create net.IP")
	}
	return res, nil
}
