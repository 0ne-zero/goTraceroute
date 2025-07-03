package traceroute

import (
	"fmt"
	"testing"
)

func printHop(hop TracerouteHop) {
	fmt.Printf("%-3d %v (%v)  %v\n", hop.TTL, hop.HostOrAddressString(), hop.AddressString(), hop.ElapsedTime)
}

func TestTraceroute(t *testing.T) {
	fmt.Println("Testing synchronous traceroute:")
	options := NewTracerouteOptions()
	out, err := Traceroute("google.com", options)
	if err == nil {
		if len(out.Hops) == 0 {
			t.Errorf("TestTraceroute failed. Expected at least one hop")
		}
	} else {
		t.Errorf("TestTraceroute failed due to an error: %v", err)
	}

	for _, hop := range out.Hops {
		printHop(hop)
	}
	fmt.Println()
}

func TestTraceouteChannel(t *testing.T) {
	fmt.Println("\nTesting asynchronous traceroute:")
	c := make(chan TracerouteHop)
	go func() {
		for {
			hop, ok := <-c
			if !ok {
				fmt.Println()
				return
			}
			printHop(hop)
		}
	}()

	options := NewTracerouteOptions()
	out, err := Traceroute("google.com", options, c)
	if err == nil {
		if len(out.Hops) == 0 {
			t.Errorf("TestTracerouteChannel failed. Expected at least one hop")
		}
	} else {
		t.Errorf("TestTraceroute failed due to an error: %v", err)
	}
}
