package traceroute

const (
	DefaultPort       = 33434
	DefaultMaxHops    = 64
	DefaultFirstHop   = 1
	DefaultTimeoutMs  = 500
	DefaultRetries    = 3
	DefaultPacketSize = 52
)

// TracerouteOptions holds configuration for a traceroute operation.
type TracerouteOptions struct {
	port       int
	maxHops    int
	firstHop   int
	timeoutMs  int
	retries    int
	packetSize int
}

// NewTracerouteOptions returns TracerouteOptions initialized with defaults.
func NewTracerouteOptions() *TracerouteOptions {
	return &TracerouteOptions{
		port:       DefaultPort,
		maxHops:    DefaultMaxHops,
		firstHop:   DefaultFirstHop,
		timeoutMs:  DefaultTimeoutMs,
		retries:    DefaultRetries,
		packetSize: DefaultPacketSize,
	}
}

func (o *TracerouteOptions) Port() int       { return o.port }
func (o *TracerouteOptions) MaxHops() int    { return o.maxHops }
func (o *TracerouteOptions) FirstHop() int   { return o.firstHop }
func (o *TracerouteOptions) TimeoutMs() int  { return o.timeoutMs }
func (o *TracerouteOptions) Retries() int    { return o.retries }
func (o *TracerouteOptions) PacketSize() int { return o.packetSize }

func (o *TracerouteOptions) SetPort(port int)           { o.port = port }
func (o *TracerouteOptions) SetMaxHops(maxHops int)     { o.maxHops = maxHops }
func (o *TracerouteOptions) SetFirstHop(firstHop int)   { o.firstHop = firstHop }
func (o *TracerouteOptions) SetTimeoutMs(timeoutMs int) { o.timeoutMs = timeoutMs }
func (o *TracerouteOptions) SetRetries(retries int)     { o.retries = retries }
func (o *TracerouteOptions) SetPacketSize(size int)     { o.packetSize = size }
