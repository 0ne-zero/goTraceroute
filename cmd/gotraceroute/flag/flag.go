package flag

import (
	"flag"
	"fmt"
	"os"

	"github.com/0ne-zero/goTraceroute/pkg/core/options"
)

// ErrMissingHost is returned when no host is provided as argument
var ErrMissingHost = fmt.Errorf("host argument is required (e.g. traceroute [options] example.com)")

const defaultMaxConsecutiveNoReplies = 20

// CLIFlags holds parsed command-line flags and the host
type CLIFlags struct {
	DestPort                int
	MaxHops                 int
	FirstHop                int
	TimeoutMs               int
	DelayMs                 int
	Retries                 int
	PreferAddressFamily     int
	Host                    string
	Protocol                string
	MaxConsecutiveNoReplies int
}

// ParseFlags parses CLI flags and returns CLIFlags and an error if any
func ParseFlags() (*CLIFlags, error) {
	var flags CLIFlags

	flag.IntVar(&flags.FirstHop, "first-ttl", options.DefaultFirstHop, "Initial TTL to start probing from")
	flag.IntVar(&flags.MaxHops, "max-ttl", options.DefaultMaxHops, "Maximum TTL (max hops) to probe")

	flag.IntVar(&flags.DestPort, "dest-port", 0, "Destination port to probe")

	flag.IntVar(&flags.TimeoutMs, "timeout", options.DefaultTimeoutMs, "Timeout per probe in milliseconds")
	flag.IntVar(&flags.DelayMs, "delay", options.DefaultDelayMs, "Delay between sending probes in milliseconds")
	flag.IntVar(&flags.Retries, "retries", options.DefaultRetries, "Number of retries per hop except the first probe")
	flag.IntVar(&flags.PreferAddressFamily, "ip-version", 4, "Preferred address family: 4 for IPv4 or 6 for IPv6")

	flag.StringVar(&flags.Protocol, "protocol", "udp", "Protocol to use: udp or tcp")

	flag.IntVar(&flags.MaxConsecutiveNoReplies, "max-consecutive", defaultMaxConsecutiveNoReplies, "Max consecutive probes without reply to stop early (0 disables)")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] host\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if err := validate(&flags); err != nil {
		return nil, err
	}

	return &flags, nil
}

// validate checks CLI flags and sets defaults if needed
func validate(flags *CLIFlags) error {
	if flag.NArg() < 1 {
		return ErrMissingHost
	}
	flags.Host = flag.Arg(0)

	switch flags.Protocol {
	case "udp":
		if flags.DestPort == 0 {
			flags.DestPort = options.DefaultUDPDestPort
		}
	case "tcp":
		if flags.DestPort == 0 {
			flags.DestPort = options.DefaultTCPDestPort
		}
	default:
		return fmt.Errorf("invalid protocol: must be either \"udp\" or \"tcp\"")
	}

	if flags.MaxHops <= 0 || flags.MaxHops > 255 {
		return fmt.Errorf("max-ttl must be between 1 and 255")
	}
	if flags.FirstHop <= 0 || flags.FirstHop > flags.MaxHops {
		return fmt.Errorf("first-ttl must be between 1 and max-ttl")
	}

	if flags.DestPort < 1 {
		return fmt.Errorf("destination port must be greater than 0")
	}

	return nil
}

// PrintUsage prints CLI usage info
func PrintUsage() {
	flag.Usage()
}
