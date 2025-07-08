package options

import (
	trace_socket "github.com/0ne-zero/traceroute/pkg/net/socket"
)

type Protocol int

const (
	PROTOCOL_TCP Protocol = 1 // TCP socket type in OS
	PROTOCOL_UDP Protocol = 2 // UDP socket type in OS
)

const (
	DefaultUDPSrcPort              = 33777
	DefaultUDPDestPort             = 33434
	DefaultTCPDestPort             = 443
	DefaultMaxHops                 = 64
	DefaultFirstHop                = 1
	DefaultTimeoutMs               = 3000
	DefaultDelayMs                 = 200
	DefaultRetries                 = 2 // Except the first one
	DefaultPreferAddressFamily     = trace_socket.AF_INET
	DefaultProbeProtocol           = PROTOCOL_UDP
	DefaultMaxConsecutiveNoReplies = 0 // Disabled by default
)

// Options holds configuration for a traceroute operation
type Options struct {
	udpSrcPort              int
	udpDestPort             int
	tcpDestPort             int
	maxHops                 int
	firstHop                int
	timeoutMs               int
	delayMs                 int
	maxRetries              int
	preferAddressFamily     int
	probeProtocol           Protocol
	maxConsecutiveNoReplies int
}

// NewTracerouteOptions returns Options initialized with default values
func NewTracerouteOptions() *Options {
	return &Options{
		udpSrcPort:              DefaultUDPSrcPort,
		udpDestPort:             DefaultUDPDestPort,
		tcpDestPort:             DefaultTCPDestPort,
		maxHops:                 DefaultMaxHops,
		firstHop:                DefaultFirstHop,
		timeoutMs:               DefaultTimeoutMs,
		delayMs:                 DefaultDelayMs,
		maxRetries:              DefaultRetries,
		preferAddressFamily:     DefaultPreferAddressFamily,
		probeProtocol:           DefaultProbeProtocol,
		maxConsecutiveNoReplies: DefaultMaxConsecutiveNoReplies,
	}
}

// Getters

// UDPSrcPort returns the UDP source port for probes
func (o *Options) UDPSrcPort() int { return o.udpSrcPort }

// UDPDestPort returns the UDP destination port for probes
func (o *Options) UDPDestPort() int { return o.udpDestPort }

// TCPDestPort returns the TCP destination port for probes
func (o *Options) TCPDestPort() int { return o.tcpDestPort }

// MaxHops returns the maximum TTL (max hops) for traceroute
func (o *Options) MaxHops() int { return o.maxHops }

// FirstHop returns the first TTL to start probing from
func (o *Options) FirstHop() int { return o.firstHop }

// TimeoutMs returns the timeout per probe in milliseconds
func (o *Options) TimeoutMs() int { return o.timeoutMs }

// DelayMs returns the delay between sending probes in milliseconds
func (o *Options) DelayMs() int { return o.delayMs }

// MaxRetries returns the number of retries per hop (except the first one)
func (o *Options) MaxRetries() int { return o.maxRetries }

// PreferAddressFamily returns the preferred IP address family (IPv4 or IPv6)
func (o *Options) PreferAddressFamily() int { return o.preferAddressFamily }

// ProbeProtocol returns the protocol used for probing (UDP or TCP)
func (o *Options) ProbeProtocol() Protocol { return o.probeProtocol }

// Returns 0 or negative if early stopping is disabled
// Read SetMaxConsecutiveNoReplies's documentation for more detail about it
func (o *Options) MaxConsecutiveNoReplies() int {
	return o.maxConsecutiveNoReplies
}

// Setters

// SetUDPSrcPort sets the UDP source port for probes
func (o *Options) SetUDPSrcPort(port int) { o.udpSrcPort = port }

// SetUDPDestPort sets the UDP destination port for probes
func (o *Options) SetUDPDestPort(port int) { o.udpDestPort = port }

// SetTCPDestPort sets the TCP destination port for probes
func (o *Options) SetTCPDestPort(port int) { o.tcpDestPort = port }

// SetMaxHops sets the maximum TTL (max hops) for traceroute
func (o *Options) SetMaxHops(maxHops int) { o.maxHops = maxHops }

// SetFirstHop sets the first TTL to start probing from
func (o *Options) SetFirstHop(firstHop int) { o.firstHop = firstHop }

// SetTimeoutMs sets the timeout per probe in milliseconds
func (o *Options) SetTimeoutMs(timeoutMs int) { o.timeoutMs = timeoutMs }

// SetDelayMs sets the delay between sending probes in milliseconds
func (o *Options) SetDelayMs(delayMs int) { o.delayMs = delayMs }

// SetRetries sets the number of retries per hop (except the first one)
func (o *Options) SetRetries(retries int) { o.maxRetries = retries }

// SetPreferAddressFamily sets the preferred IP address family (IPv4 or IPv6)
func (o *Options) SetPreferAddressFamily(af int) { o.preferAddressFamily = af }

// SetProbeProtocol sets the protocol used for probing (UDP or TCP)
func (o *Options) SetProbeProtocol(protocol Protocol) { o.probeProtocol = protocol }

// SetMaxConsecutiveNoReplies sets how many consecutive TTL probes without any response
// (ICMP, TCP SYN/ACK, or RST) will cause traceroute to stop early before reaching max TTL
// Use a positive number to enable early stopping for efficiency when destination or intermediate hops are silent
// Set to 0 or a negative number to disable early stopping and always probe up to max TTL
// A TTL counts toward this when no host responds after all retries; the counter resets when a response is received
func (o *Options) SetMaxConsecutiveNoReplies(maxConsecutive int) {
	o.maxConsecutiveNoReplies = maxConsecutive
}
