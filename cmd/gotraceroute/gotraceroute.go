package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/0ne-zero/traceroute/cmd/gotraceroute/flag"
	"github.com/0ne-zero/traceroute/pkg/core/hop"
	"github.com/0ne-zero/traceroute/pkg/core/options"
	"github.com/0ne-zero/traceroute/pkg/core/traceroute"
	trace_socket "github.com/0ne-zero/traceroute/pkg/net/socket"
)

func main() {
	flags, err := flag.ParseFlags()
	if err != nil {
		if errors.Is(err, flag.ErrMissingHost) {
			flag.PrintUsage()
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	// Resolve host
	ipAddr, err := net.ResolveIPAddr("ip", flags.Host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to resolve host %s: %v\n", flags.Host, err)
		os.Exit(1)
	}

	// Setup options
	opts := options.NewTracerouteOptions()
	switch flags.Protocol {
	case "udp":
		opts.SetProbeProtocol(options.PROTOCOL_UDP)
	case "tcp":
		opts.SetProbeProtocol(options.PROTOCOL_TCP)
	default:
		fmt.Fprintf(os.Stderr, "invalid protocol: must be either \"udp\" or \"tcp\"")
		os.Exit(1)
	}
	if flags.MaxConsecutiveNoReplies > 0 {
		opts.SetMaxConsecutiveNoReplies(flags.MaxConsecutiveNoReplies)
	}
	opts.SetUDPDestPort(flags.DestPort)
	opts.SetFirstHop(flags.FirstHop)
	opts.SetMaxHops(flags.MaxHops)
	opts.SetRetries(flags.Retries)
	opts.SetTimeoutMs(flags.TimeoutMs)
	opts.SetDelayMs(flags.DelayMs)

	switch flags.PreferAddressFamily {
	case 4:
		opts.SetPreferAddressFamily(trace_socket.AF_INET)
	case 6:
		opts.SetPreferAddressFamily(trace_socket.AF_INET6)
	default:
		opts.SetPreferAddressFamily(trace_socket.AF_INET)
	}

	fmt.Printf("traceroute to %s (%s), %d start ttl, %d hops max\n", flags.Host, ipAddr.String(), opts.FirstHop(), opts.MaxHops())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Setup Ctrl+C handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupted. Stopping traceroute...")
		cancel()
	}()

	// Start traceroute
	hopChan := make(chan hop.TracerouteHop)
	errChan := make(chan error)

	go func() {
		err = traceroute.TracerouteContext(ctx, flags.Host, opts, hopChan)
		if err != nil {
			errChan <- err
		}

	}()

	for {
		select {
		case hop, ok := <-hopChan:
			if !ok {
				return
			}
			printHop(hop)
		case err := <-errChan:
			if errors.Is(err, traceroute.ErrMaxConsecutiveNoRepliesExceeded) {
				fmt.Fprintf(os.Stderr, "Traceroute stopped early: too many consecutive unanswered hops\n")
			} else {
				fmt.Fprintf(os.Stderr, "Traceroute error: %v\n", err)
			}
			os.Exit(1)
		}
	}
}

func printHop(hop hop.TracerouteHop) {
	addr := net.IP(hop.Address).String()
	display := addr
	if hop.Host != "" {
		display = hop.Host
	}

	if hop.Success {
		fmt.Printf("%-3d %-32s (%s)  %10.2f ms\n",
			hop.TTL, display, addr, float64(hop.ElapsedTime.Microseconds())/1000.0)
	} else {
		fmt.Printf("%-3d *\n", hop.TTL)
	}
}
