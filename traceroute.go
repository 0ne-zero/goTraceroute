// Package traceroute provides functions for executing a tracroute to a remote
// host.
package traceroute

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/aeden/traceroute/socket"
)

const DEFAULT_PORT = 33434
const DEFAULT_MAX_HOPS = 64
const DEFAULT_FIRST_HOP = 1
const DEFAULT_TIMEOUT_MS = 500
const DEFAULT_RETRIES = 3
const DEFAULT_PACKET_SIZE = 52

// Return the first non-loopback IP address (IPv4 or IPv6).
func socketAddr() (ip net.IP, err error) {
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

// Given a host name convert it to a 4 byte IP address.
func destAddr(dest string) (net.IP, error) {
	addrs, err := net.LookupHost(dest)
	if err != nil {
		return nil, err
	}
	addr := addrs[0]

	ipAddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		return nil, err
	}
	return ipAddr.IP.To4(), nil
}

// TracrouteOptions type
type TracerouteOptions struct {
	port       int
	maxHops    int
	firstHop   int
	timeoutMs  int
	retries    int
	packetSize int
}

func (options *TracerouteOptions) Port() int {
	if options.port == 0 {
		options.port = DEFAULT_PORT
	}
	return options.port
}

func (options *TracerouteOptions) SetPort(port int) {
	options.port = port
}

func (options *TracerouteOptions) MaxHops() int {
	if options.maxHops == 0 {
		options.maxHops = DEFAULT_MAX_HOPS
	}
	return options.maxHops
}

func (options *TracerouteOptions) SetMaxHops(maxHops int) {
	options.maxHops = maxHops
}

func (options *TracerouteOptions) FirstHop() int {
	if options.firstHop == 0 {
		options.firstHop = DEFAULT_FIRST_HOP
	}
	return options.firstHop
}

func (options *TracerouteOptions) SetFirstHop(firstHop int) {
	options.firstHop = firstHop
}

func (options *TracerouteOptions) TimeoutMs() int {
	if options.timeoutMs == 0 {
		options.timeoutMs = DEFAULT_TIMEOUT_MS
	}
	return options.timeoutMs
}

func (options *TracerouteOptions) SetTimeoutMs(timeoutMs int) {
	options.timeoutMs = timeoutMs
}

func (options *TracerouteOptions) Retries() int {
	if options.retries == 0 {
		options.retries = DEFAULT_RETRIES
	}
	return options.retries
}

func (options *TracerouteOptions) SetRetries(retries int) {
	options.retries = retries
}

func (options *TracerouteOptions) PacketSize() int {
	if options.packetSize == 0 {
		options.packetSize = DEFAULT_PACKET_SIZE
	}
	return options.packetSize
}

func (options *TracerouteOptions) SetPacketSize(packetSize int) {
	options.packetSize = packetSize
}

// TracerouteHop type
type TracerouteHop struct {
	Success     bool
	Address     net.IP        // IP Address of the node on the network
	Host        string        // Domain name of the node on the netwrok
	N           int           // Received bytes (It's redundant actually in here, don't need it)
	ElapsedTime time.Duration // Round-Time-Trip
	TTL         int           // Time-To-Live of the node on the network (answers how far the node is)
}

func (hop *TracerouteHop) AddressString() string {
	if hop.Address == nil {
		return ""
	}
	return hop.Address.String()
}

func (hop *TracerouteHop) HostOrAddressString() string {
	if hop.Host != "" {
		return hop.Host
	} else {
		return hop.AddressString()
	}
}

// TracerouteResult type
type TracerouteResult struct {
	DestinationAddress net.IP
	Hops               []TracerouteHop
}

func notify(hop TracerouteHop, channels []chan TracerouteHop) {
	for _, c := range channels {
		c <- hop
	}
}

func closeNotify(channels []chan TracerouteHop) {
	for _, c := range channels {
		close(c)
	}
}

// Traceroute uses the given dest (hostname) and options to execute a traceroute
// from your machine to the remote host.
//
// Outbound packets are UDP packets and inbound packets are ICMP.
//
// Returns a TracerouteResult which contains an array of hops. Each hop includes
// the elapsed time and its IP address.
func Traceroute(dest string, options *TracerouteOptions, c ...chan TracerouteHop) (result TracerouteResult, err error) {
	result.Hops = []TracerouteHop{}
	destAddr, err := destAddr(dest)
	result.DestinationAddress = destAddr
	socketAddr, err := socketAddr()
	if err != nil {
		return
	}

	// Set up the socket to send packets out.
	sendSocket, err := socket.NewSocket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	if err != nil {
		return result, err
	}
	defer sendSocket.Close()
	// Set up the socket to receive inbound packets
	recvSocket, err := socket.NewSocket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return result, err
	}
	defer recvSocket.Close()

	// This sets the timeout to wait for a response from the remote host
	timeout := time.Duration(options.TimeoutMs()) * time.Millisecond
	recvSocket.SetSockOptTimeval(socket.SOL_SOCKET, socket.SO_RCVTIMEO, &timeout)

	// Bind to the local socket to listen for ICMP packets
	recvSocket.Bind(options.Port(), socketAddr)

	ttl := options.FirstHop()
	retry := 0
	for {
		// log.Println("TTL: ", ttl)
		start := time.Now()

		// This sets the current hop TTL
		sendSocket.SetSockOptInt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

		// Send a single null byte UDP packet
		sendSocket.SendTo([]byte{0x0}, 0, options.Port(), destAddr)

		var p = make([]byte, options.PacketSize())
		n, from, err := recvSocket.RecvFrom(p, 0)
		elapsed := time.Since(start)
		if err == nil {
			hop := TracerouteHop{Success: true, Address: from, N: n, ElapsedTime: elapsed, TTL: ttl}

			// Do reverse lookup
			hop.Host = reverseLookup(hop.AddressString(), time.Duration(DEFAULT_TIMEOUT_MS))

			notify(hop, c)

			result.Hops = append(result.Hops, hop)

			ttl += 1
			retry = 0

			if ttl > options.MaxHops() || from.Equal(destAddr) {
				closeNotify(c)
				return result, nil
			}
		} else {
			retry += 1
			if retry > options.Retries() {
				notify(TracerouteHop{Success: false, TTL: ttl}, c)
				ttl += 1
				retry = 0
			}

			if ttl > options.MaxHops() {
				closeNotify(c)
				return result, nil
			}
		}

	}
}

func reverseLookup(addr string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, addr)
	if err == nil && len(names) > 0 {
		return names[0]
	}
	return ""
}
