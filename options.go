package traceroute

const (
	DefaultPort       = 33434
	DefaultMaxHops    = 64
	DefaultFirstHop   = 1
	DefaultTimeoutMs  = 500
	DefaultRetries    = 3
	DefaultPacketSize = 52
)

// tracerouteOptions holds configuration for a traceroute operation.
type tracerouteOptions struct {
	port       int
	maxHops    int
	firstHop   int
	timeoutMs  int
	maxRetries int
	packetSize int
}

// NewTracerouteOptions returns TracerouteOptions initialized with defaults.
func NewTracerouteOptions() *tracerouteOptions {
	return &tracerouteOptions{
		port:       DefaultPort,
		maxHops:    DefaultMaxHops,
		firstHop:   DefaultFirstHop,
		timeoutMs:  DefaultTimeoutMs,
		maxRetries: DefaultRetries,
		packetSize: DefaultPacketSize,
	}
}

func (o *tracerouteOptions) Port() int       { return o.port }
func (o *tracerouteOptions) MaxHops() int    { return o.maxHops }
func (o *tracerouteOptions) FirstHop() int   { return o.firstHop }
func (o *tracerouteOptions) TimeoutMs() int  { return o.timeoutMs }
func (o *tracerouteOptions) MaxRetries() int { return o.maxRetries }
func (o *tracerouteOptions) PacketSize() int { return o.packetSize }

func (o *tracerouteOptions) SetPort(port int)           { o.port = port }
func (o *tracerouteOptions) SetMaxHops(maxHops int)     { o.maxHops = maxHops }
func (o *tracerouteOptions) SetFirstHop(firstHop int)   { o.firstHop = firstHop }
func (o *tracerouteOptions) SetTimeoutMs(timeoutMs int) { o.timeoutMs = timeoutMs }
func (o *tracerouteOptions) SetRetries(retries int)     { o.maxRetries = retries }
func (o *tracerouteOptions) SetPacketSize(size int)     { o.packetSize = size }
