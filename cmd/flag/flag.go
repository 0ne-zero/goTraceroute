package flag

import (
	"flag"
	"fmt"
	"os"

	"github.com/0ne-zero/traceroute"
)

var ErrMissingHost = fmt.Errorf("missing host argument")

// CLIFlags holds parsed command-line flags and the host.
type CLIFlags struct {
	SrcPort             int
	DestPort            int
	MaxHops             int
	FirstHop            int
	TimeoutMs           int
	Retries             int
	PreferAddressFamily int
	Host                string
}

// parseFlags parses CLI flags and returns CLIFlags + possible error.
func ParseFlags() (*CLIFlags, error) {
	var flags CLIFlags

	flag.IntVar(&flags.MaxHops, "m", traceroute.DefaultMaxHops, "Max time-to-live (max hops)")
	flag.IntVar(&flags.SrcPort, "sp", traceroute.DefaultSrcPort, "UDP source port")
	flag.IntVar(&flags.DestPort, "dp", traceroute.DefaultDestPort, "UDP destination port")
	flag.IntVar(&flags.FirstHop, "f", traceroute.DefaultFirstHop, "First TTL to start probing from")
	flag.IntVar(&flags.TimeoutMs, "t", traceroute.DefaultTimeoutMs, "Timeout per probe in ms")
	flag.IntVar(&flags.Retries, "r", traceroute.DefaultRetries, "Number of retries per hop")
	flag.IntVar(&flags.PreferAddressFamily, "af", 4, "Prefer address family: '4' for IPv4, '6' for IPv6")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage: %s [options] host\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if err := validate(&flags); err != nil {
		return nil, err
	}
	return &flags, nil
}

func validate(flags *CLIFlags) error {
	if flag.NArg() < 1 {
		return ErrMissingHost
	}
	flags.Host = flag.Arg(0)

	// validate values
	if flags.MaxHops <= 0 || flags.MaxHops > 255 {
		return fmt.Errorf("max hops must be between 1 and 255")
	}
	if flags.FirstHop <= 0 || flags.FirstHop > flags.MaxHops {
		return fmt.Errorf("first hop must be between 1 and max hops")
	}

	if flags.SrcPort < 1 {
		return fmt.Errorf("source port must be greater than 0")
	}
	if flags.DestPort < 1 {
		return fmt.Errorf("destination port must be greater than 0")
	}
	return nil
}

func PrintUsage() {
	flag.Usage()
}
