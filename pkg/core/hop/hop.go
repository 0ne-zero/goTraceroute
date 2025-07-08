package hop

import (
	"net"
	"time"

	"github.com/0ne-zero/traceroute/pkg/core/options"
	trace_net "github.com/0ne-zero/traceroute/pkg/net"
)

// TracerouteHop represents a single hop in a traceroute operation.
type TracerouteHop struct {
	Success          bool          // Whether the probe succeeded
	Address          net.IP        // IP address of the node
	Host             string        // Resolved hostname of the node (if available)
	ReceivedBytesLen int           // Number of bytes received (optional)
	ElapsedTime      time.Duration // Round-trip time for the probe
	TTL              int           // Time-To-Live value for this hop
}

func NewTracerouteHop(success bool, addr net.IP, bytes int, elapsed time.Duration, ttl int) TracerouteHop {
	hop := TracerouteHop{
		Success:          success,
		Address:          addr,
		ReceivedBytesLen: bytes,
		ElapsedTime:      elapsed,
		TTL:              ttl,
	}
	if success {
		hop.Host = trace_net.ReverseLookup(hop.AddressString(), time.Duration(options.DefaultTimeoutMs)*time.Millisecond)
	}
	return hop
}

// AddressString returns the string representation of the IP address or empty string if nil.
func (hop *TracerouteHop) AddressString() string {
	if hop.Address == nil {
		return ""
	}
	return hop.Address.String()
}

// HostOrAddressString returns the hostname if available, otherwise the IP address string.
func (hop *TracerouteHop) HostOrAddressString() string {
	if hop.Host != "" {
		return hop.Host
	}
	return hop.AddressString()
}
