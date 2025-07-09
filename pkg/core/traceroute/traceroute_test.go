package traceroute_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/0ne-zero/traceroute/pkg/core/hop"
	"github.com/0ne-zero/traceroute/pkg/core/options"
	"github.com/0ne-zero/traceroute/pkg/core/traceroute"
)

func printHop(hop hop.TracerouteHop) {
	if hop.Address == nil && hop.Host == "" {
		fmt.Printf("%-3d * (*)  %v ms\n", hop.TTL, float64(hop.ElapsedTime.Microseconds())/1000.0)
	} else {
		fmt.Printf("%-3d %v (%v)  %10.2f ms\n", hop.TTL, hop.HostOrAddressString(), hop.AddressString(), float64(hop.ElapsedTime.Microseconds())/1000.0)
	}
}

func TestTracerouteIPv4(t *testing.T) {
	fmt.Println("Testing synchronous traceroute IPv4:")
	opts := options.NewTracerouteOptions()
	resChan := make(chan hop.TracerouteHop, opts.MaxHops())

	err := traceroute.Traceroute("google.com", opts, resChan)
	if err != nil {
		t.Fatalf("TestTraceroute failed due to an error: %v", err)
	}

	for hop := range resChan {
		printHop(hop)
	}
}

func TestTraceouteChannelIPv4(t *testing.T) {
	fmt.Println("\nTesting asynchronous traceroute IPv4:")

	resChan := make(chan hop.TracerouteHop)
	errChan := make(chan error)

	go func() {
		opts := options.NewTracerouteOptions()
		err := traceroute.Traceroute("google.com", opts, resChan)
		if err != nil {
			errChan <- fmt.Errorf("TestTraceroute failed due to an error: %v", err)
		}
	}()

	for {
		select {
		case hop, ok := <-resChan:
			if !ok {
				return
			}
			printHop(hop)
		case err := <-errChan:
			t.Fatal(err)
		}
	}
}

func TestTCPTracerouteIPv4(t *testing.T) {
	fmt.Println("Testing synchronous TCP traceroute IPv4:")

	opts := options.NewTracerouteOptions()
	opts.SetProbeProtocol(options.PROTOCOL_TCP)
	resChan := make(chan hop.TracerouteHop, opts.MaxHops())

	err := traceroute.Traceroute("google.com", opts, resChan)
	if err != nil {
		t.Fatalf("TestTraceroute failed due to an error: %v", err)
	}

	for hop := range resChan {
		printHop(hop)
	}
}
func TestTCPTraceouteChannelIPv4(t *testing.T) {
	fmt.Println("\nTesting asynchronous traceroute IPv4:")

	resChan := make(chan hop.TracerouteHop)
	errChan := make(chan error)

	go func() {
		opts := options.NewTracerouteOptions()
		opts.SetProbeProtocol(options.PROTOCOL_TCP)
		err := traceroute.Traceroute("google.com", opts, resChan)
		if err != nil {
			errChan <- fmt.Errorf("TestTraceroute failed due to an error: %v", err)
		}
	}()

	for {
		select {
		case hop, ok := <-resChan:
			if !ok {
				return
			}
			printHop(hop)
		case err := <-errChan:
			t.Fatal(err)
		}
	}
}

func TestTracerouteIPv6(t *testing.T) {
	fmt.Println("Testing synchronous traceroute IPv6:")

	opts := options.NewTracerouteOptions()
	resChan := make(chan hop.TracerouteHop, opts.MaxHops())

	err := traceroute.Traceroute("2001:4860:4860::8888", opts, resChan)
	if err != nil {
		t.Fatalf("TestTraceroute failed due to an error: %v", err)
	}

	for hop := range resChan {
		printHop(hop)
	}

}
func TestTraceouteChannelIPv6(t *testing.T) {
	fmt.Println("\nTesting asynchronous traceroute IPv6:")

	resChan := make(chan hop.TracerouteHop)
	errChan := make(chan error)

	go func() {
		options := options.NewTracerouteOptions()
		err := traceroute.Traceroute("2001:4860:4860::8888", options, resChan)
		if err != nil {
			errChan <- fmt.Errorf("TestTraceroute failed due to an error: %v", err)
		}
	}()

	for {
		select {
		case hop, ok := <-resChan:
			if !ok {
				return
			}
			printHop(hop)
		case err := <-errChan:
			t.Fatal(err)
		}
	}
}

func TestTCPTracerouteIPv6(t *testing.T) {
	fmt.Println("Testing synchronous traceroute IPv6:")

	opts := options.NewTracerouteOptions()
	opts.SetProbeProtocol(options.PROTOCOL_TCP)
	resChan := make(chan hop.TracerouteHop, opts.MaxHops())

	err := traceroute.Traceroute("2001:4860:4860::8888", opts, resChan)
	if err != nil {
		t.Fatalf("TestTraceroute failed due to an error: %v", err)
	}

	for hop := range resChan {
		printHop(hop)
	}
}
func TestTCPTraceouteChannelIPv6(t *testing.T) {
	fmt.Println("\nTesting asynchronous traceroute IPv6:")

	resChan := make(chan hop.TracerouteHop)
	errChan := make(chan error)

	go func() {
		opts := options.NewTracerouteOptions()
		opts.SetProbeProtocol(options.PROTOCOL_TCP)
		err := traceroute.Traceroute("2001:4860:4860::8888", opts, resChan)
		if err != nil {
			errChan <- fmt.Errorf("TestTraceroute failed due to an error: %v", err)

		}
	}()

	for {
		select {
		case hop, ok := <-resChan:
			if !ok {
				return
			}
			printHop(hop)
		case err := <-errChan:
			t.Fatal(err)
		}
	}
}

func TestTracerouteChannelHostBlockedICMPReply(t *testing.T) {
	fmt.Println("\nTesting asynchronous traceroute on a host that blocked ICMP reply:")

	resChan := make(chan hop.TracerouteHop)
	errChan := make(chan error)

	go func() {
		opts := options.NewTracerouteOptions()
		opts.SetMaxConsecutiveNoReplies(5)
		err := traceroute.Traceroute("irib.ir", opts, resChan)
		if err != nil {
			errChan <- fmt.Errorf("TestTraceroute failed due to an error: %v", err)
		}
	}()

	for {
		select {
		case hop, ok := <-resChan:
			if !ok {
				return
			}
			printHop(hop)
		case err := <-errChan:
			if !errors.Is(err, traceroute.ErrMaxConsecutiveNoRepliesExceeded) {
				t.Fatal(err)
			}
			// PASS
			return
		}
	}
}
