package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/0ne-zero/traceroute"
	"github.com/0ne-zero/traceroute/cmd/flag"
	trace_socket "github.com/0ne-zero/traceroute/net/socket"
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
	opts := traceroute.NewTracerouteOptions()
	opts.SetMaxHops(flags.MaxHops)
	opts.SetFirstHop(flags.FirstHop)
	opts.SetRetries(flags.Retries)
	opts.SetTimeoutMs(flags.TimeoutMs)
	opts.SetPacketSize(flags.PacketSize)

	switch flags.PreferAddressFamily {
	case 4:
		opts.SetPreferAddressFamily(trace_socket.AF_INET)
	case 6:
		opts.SetPreferAddressFamily(trace_socket.AF_INET6)
	default:
		opts.SetPreferAddressFamily(trace_socket.AF_INET)
	}

	fmt.Printf("traceroute to %s (%s), %d hops max, %d byte packets\n",
		flags.Host, ipAddr.String(), opts.MaxHops(), opts.PacketSize())

	// Setup Ctrl+C handling
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupted. Stopping traceroute...")
		//cancel()
	}()

	// Start traceroute
	hopChan := make(chan traceroute.TracerouteHop)
	go func() {
		for hop := range hopChan {
			printHop(hop)
		}
	}()

	_, err = traceroute.Traceroute(flags.Host, opts, hopChan)
	//_, err = traceroute.TracerouteContext(ctx, flags.Host, opts, hopChan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Traceroute error: %v\n", err)
		os.Exit(1)
	}
}

func printHop(hop traceroute.TracerouteHop) {
	addr := net.IP(hop.Address).String()
	display := addr
	if hop.Host != "" {
		display = hop.Host
	}

	if hop.Success {
		fmt.Printf("%-3d %-30s (%-15s)  %6.2f ms\n",
			hop.TTL, display, addr, float64(hop.ElapsedTime.Microseconds())/1000.0)
	} else {
		fmt.Printf("%-3d *\n", hop.TTL)
	}
}
