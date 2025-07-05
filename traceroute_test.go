package traceroute

import (
	"fmt"
	"testing"
)

func printHop(hop TracerouteHop) {
	if hop.Address == nil && hop.Host == "" {
		fmt.Printf("%-3d * (*)  %v\n", hop.TTL, hop.ElapsedTime)
	} else {
		fmt.Printf("%-3d %v (%v)  %v\n", hop.TTL, hop.HostOrAddressString(), hop.AddressString(), hop.ElapsedTime)
	}
}

func TestTracerouteIPv4(t *testing.T) {
	fmt.Println("Testing synchronous traceroute IPv4:")
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
func TestTraceouteChannelIPv4(t *testing.T) {
	fmt.Println("\nTesting asynchronous traceroute IPv4:")
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
	out, err := Traceroute("google.ir", options, c)
	if err == nil {
		if len(out.Hops) == 0 {
			t.Errorf("TestTracerouteChannel failed. Expected at least one hop")
		}
	} else {
		t.Errorf("TestTraceroute failed due to an error: %v", err)
	}
}

func TestTracerouteIPv6(t *testing.T) {
	fmt.Println("Testing synchronous traceroute IPv6:")
	options := NewTracerouteOptions()
	out, err := Traceroute("2001:4860:4860::8888", options)
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
func TestTraceouteChannelIPv6(t *testing.T) {
	fmt.Println("\nTesting asynchronous traceroute IPv6:")
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
	out, err := Traceroute("2001:4860:4860::8888", options, c)
	if err == nil {
		if len(out.Hops) == 0 {
			t.Errorf("TestTracerouteChannel failed. Expected at least one hop")
		}
	} else {
		t.Errorf("TestTraceroute failed due to an error: %v", err)
	}
}

func TestTracerouteChannelHostBlockedICMPReply(t *testing.T) {
	fmt.Println("\nTesting asynchronous traceroute on a host that blocked ICMP reply:")
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
	out, err := Traceroute("irib.ir", options, c)
	if err == nil {
		if len(out.Hops) == 0 {
			t.Errorf("TestTracerouteChannel failed. Expected at least one hop")
		}
	} else {
		t.Errorf("TestTraceroute failed due to an error: %v", err)
	}
}
