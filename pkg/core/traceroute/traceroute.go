package traceroute

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/0ne-zero/traceroute/pkg/core/hop"
	"github.com/0ne-zero/traceroute/pkg/core/options"
	"github.com/0ne-zero/traceroute/pkg/core/probe"
	trace_net "github.com/0ne-zero/traceroute/pkg/net"
	"github.com/0ne-zero/traceroute/pkg/net/icmp"
	trace_socket "github.com/0ne-zero/traceroute/pkg/net/socket"
	"github.com/0ne-zero/traceroute/pkg/net/tcp"
	tcp_capture "github.com/0ne-zero/traceroute/pkg/net/tcp/capture"
	"github.com/google/gopacket/pcap"
)

var (
	ErrMaxConsecutiveNoRepliesExceeded = errors.New("stopped early: exceeded max consecutive no-reply")
)

// TracerouteResult holds the final destination address and all hops collected during the traceroute
type TracerouteResult struct {
	DestinationAddr net.IP
	Hops            []hop.TracerouteHop
}

// TracerouteContext performs a cancellable traceroute with given context and options.
// It sends probes with increasing TTL, listens for ICMP (and optionally TCP) replies, retries as needed,
// and reports each hop through provided channels until destination or max hops reached.
// To avoid blocking forever, ensure you read from the result channel in a separate goroutine
// or use a buffered channel sized to hold up to the maximum number of hops
func Traceroute(dest string, options *options.Options, chans ...chan hop.TracerouteHop) error {
	return TracerouteContext(context.Background(), dest, options, chans...)
}

// TracerouteContext performs a cancellable traceroute with given context and options.
// It sends probes with increasing TTL, listens for ICMP (and optionally TCP) replies, retries as needed,
// and reports each hop through provided channels until destination or max hops reached.
// To avoid blocking forever, ensure you read from the result channel in a separate goroutine
// or use a buffered channel sized to hold up to the maximum number of hops
func TracerouteContext(ctx context.Context, dest string, opts *options.Options, chans ...chan hop.TracerouteHop) error {
	// Resolve destination hostname to IP
	destAddr, err := trace_net.ResolveHostnameToIP(dest, opts.PreferAddressFamily())
	if err != nil {
		return err
	}
	af := trace_net.GetIPFamily(destAddr)

	// Create outbound + inbound sockets
	outboundSocket, inboundICMPSocket, err := setupSockets(opts, af)
	if err != nil {
		return err
	}
	defer outboundSocket.Close()
	defer inboundICMPSocket.Close()

	outboundIP, err := trace_net.GetOutboundAddr(destAddr)
	if err != nil {
		return err
	}

	// Get network capture handle if needed, used to catch TCP responses
	var captureHandle *pcap.Handle
	if opts.ProbeProtocol() == options.PROTOCOL_TCP {

		captureHandle, err = tcp_capture.OpenCaptureHandleByIP(opts, outboundIP)
		if err != nil {
			return err
		}
		defer captureHandle.Close()
	}

	consecutiveCounter := 0 // Unused if Options.MaxConsecutiveNoReplies() is <= 0
	retriesLeft := opts.MaxRetries()
	ttl := opts.FirstHop()
	starting := true

	for ttl <= opts.MaxHops() {
		// Check if parent context cancelled
		select {
		case <-ctx.Done():
			closeNotifyChans(chans)
			return ctx.Err()
		default:
		}

		// Craft UDP or TCP probeReq request based on protocol
		probeReq, err := craftProbeRequest(opts, outboundIP, destAddr, af, ttl)
		if err != nil {
			return err
		}

		// Create child context for this probe iteration
		// Ensures only one monitoring is on and waiting the current probe's response
		iterCtx, iterCtxCancel := context.WithTimeout(ctx, time.Duration(opts.TimeoutMs())*time.Millisecond)

		// Start listening for ICMP and/or TCP responses
		icmpResChan, tcpResChan := startMonitoringResponse(iterCtx, inboundICMPSocket, captureHandle, probeReq, opts)

		// Skip delay for the first packet
		if !starting {
			time.Sleep(time.Duration(opts.DelayMs()) * time.Millisecond)
		} else {
			starting = false
		}

		// Send probe packet
		if err := sendProbe(outboundSocket, probeReq); err != nil {
			closeNotifyChans(chans)
			iterCtxCancel()
			return err
		}

		// Wait for response (ICMP reply or TCP (SYN/ACK/ or RST)) or context error(timeout/cancellation)
		select {
		case icmpRes := <-icmpResChan:
			if icmpRes.Err == nil && icmpRes.Success {
				notify(icmpRes.TracerouteHop, chans)
				if icmpRes.ReachedDest {
					closeNotifyChans(chans)
					iterCtxCancel()
					return nil
				}
				ttl++
				retriesLeft = opts.MaxRetries()
				consecutiveCounter = 0
				iterCtxCancel()
				continue
			}
		case tcpRes := <-tcpResChan:
			if tcpRes.Err == nil && tcpRes.Success {
				// We assume that if there was a TCP response it's from the destination, other hosts would answer with ICMP reply
				if tcpRes.ReachedDest {
					notify(tcpRes.TracerouteHop, chans)
					if tcpRes.ReachedDest {
						closeNotifyChans(chans)
						iterCtxCancel()
						return nil
					}
				}
				// TODO: It's possible to the middle hosts return TCP response (ReachedDest = false), handle it
			}
		case <-ctx.Done():
			closeNotifyChans(chans)
			iterCtxCancel() // Don't need this, but compiler complains
			return ctx.Err()
		}

		// Possible situations *after* select:
		// - retriesLeft > 0: retry same TTL because of transient error.
		// - no response after retries: record timeout and increase TTL.

		// If retries left, retry same TTL
		if retriesLeft > 0 {
			retriesLeft--
			iterCtxCancel()
			continue
		}

		// No response for this TTL at all, record as timeout for this TTL
		timeoutHop := hop.NewTracerouteHop(false, nil, 0, time.Since(probeReq.StartTime), probeReq.TTL)
		notify(timeoutHop, chans)

		// Increase consecutive counter if the feature is enabled and check it every time
		if opts.MaxConsecutiveNoReplies() > 0 {
			consecutiveCounter++
			if consecutiveCounter == opts.MaxConsecutiveNoReplies() {
				closeNotifyChans(chans)
				iterCtxCancel()
				return ErrMaxConsecutiveNoRepliesExceeded
			}
		}

		// Increase TTL to send next probe
		ttl++
		retriesLeft = opts.MaxRetries()
		iterCtxCancel()
	}

	closeNotifyChans(chans)
	return nil
}

// startMonitoringResponse starts ICMP (and optionally TCP) monitoring goroutines
// for the given probe, and returns their response channels.
func startMonitoringResponse(iterCtx context.Context, inboundICMPSocket trace_socket.Socket, captureHandle *pcap.Handle, probeReq probe.ProbeRequest, opts *options.Options) (chan probe.ProbeResponse, chan probe.ProbeResponse) {
	icmpResChan := make(chan probe.ProbeResponse, 1)
	icmpReady := make(chan struct{})
	go icmp.HandleProbeICMPResponse(iterCtx, inboundICMPSocket, &probeReq, icmpReady, icmpResChan)
	// Wait until ICMP monitoring starts
	<-icmpReady

	var tcpResChan chan probe.ProbeResponse
	if opts.ProbeProtocol() == options.PROTOCOL_TCP {
		tcpResChan = make(chan probe.ProbeResponse, 1)
		tcpReady := make(chan struct{})
		go tcp.HandleProbeTCPResponse(iterCtx, captureHandle, &probeReq, tcpReady, tcpResChan)
		// Wait until TCP monitoring starts
		<-tcpReady
	}
	return icmpResChan, tcpResChan
}

// craftProbeRequest builds a probe request for the given TTL and protocol,
func craftProbeRequest(opts *options.Options, outboundIP, destAddr net.IP, af int, ttl int) (probe.ProbeRequest, error) {
	probe := probe.ProbeRequest{
		SrcAddr:   outboundIP,
		DestAddr:  destAddr,
		AF:        af,
		TTL:       ttl,
		Options:   opts,
		StartTime: time.Now(),
	}

	// Pick a random port so can dertimne the right response for each ttl
	port, err := trace_net.PickRandomPort()
	if err != nil {
		return probe, err
	}
	probe.SrcPort = port

	return probe, nil
}

// notify sends the traceroute hop result to all subscribed channels.
func notify(hop hop.TracerouteHop, channels []chan hop.TracerouteHop) {
	for _, c := range channels {
		c <- hop
	}
}

// closeNotifyChans closes all traceroute hop channels to signal completion.
func closeNotifyChans(channels []chan hop.TracerouteHop) {
	for _, c := range channels {
		close(c)
	}
}
