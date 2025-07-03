package traceroute

import (
	"net"
	"time"
)

// TracerouteHop represents a single hop in a traceroute operation.
type TracerouteHop struct {
	Success     bool          // Whether the probe succeeded
	Address     net.IP        // IP address of the node
	Host        string        // Resolved hostname of the node (if available)
	Bytes       int           // Number of bytes received (optional)
	ElapsedTime time.Duration // Round-trip time for the probe
	TTL         int           // Time-To-Live value for this hop
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
