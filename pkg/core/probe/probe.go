package probe

import (
	"net"
	"time"

	"github.com/0ne-zero/traceroute/pkg/core/hop"
	"github.com/0ne-zero/traceroute/pkg/core/options"
)

// ProbeRequest holds parameters for sending a probe packet
// Could be UDP or TCP based on options
type ProbeRequest struct {
	SrcAddr   net.IP // Only need it when using TCP to calculating TCP header checksum
	SrcPort   int
	DestAddr  net.IP
	AF        int
	TTL       int
	Options   *options.Options
	StartTime time.Time
}

// ProbeResponse contains the result of a probe including hop info, destination reached flag, and any error
type ProbeResponse struct {
	hop.TracerouteHop
	ReachedDest bool
	Err         error
}
