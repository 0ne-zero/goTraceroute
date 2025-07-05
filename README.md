#### 🛰️ GoTraceroute

A flexible, cross-platform traceroute library and CLI tool written in Go.
Supports IPv4 & IPv6, and works on Linux, macOS, and Windows.
> I personally tested only on Linux. Although it works, if didn't open an issue.


---

#### ✏️ Features

✅ IPv4 and IPv6 support

✅ Works transparently across Unix and Windows (using golang.org/x/sys + build tags)

✅ Simple context-aware API for use as a library or standalone CLI tool


---

#### ⚙️ Usage

###### CLI:

Build and run:

```bash
git clone https://github.com/0ne-zero/traceroute.git
cd traceroute
go build -o gotraceroute ./cmd/gotraceroute
sudo ./gotraceroute -h
```
> Note: On Linux and macOS, raw sockets require sudo.
On Windows, run from an elevated terminal.




---

###### Library:

Import and call:

```go
import (
    "context"
    "fmt"
    "log"

    "github.com/0ne-zero/traceroute"
)

func main() {
    // The options have default value, but you can change them based on your need
    opts := &traceroute.Options{}
    hopCh := make(chan traceroute.Hop)

    // Using context to set a timeout for the traceroute
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    // The TracerouteContext returns complete results and it also could take a channel as fourth argument and stream the results into it
    // Passing the channel to the function is optional
    result, err := traceroute.TracerouteContext(ctx, "example.com", opts, hopCh)
    if err != nil {
        log.Fatal(err)
    }

    // Consuming results from the passed channel 
    go func() {
        for hop := range hopCh {
            fmt.Printf("TTL %d\t%s\t%v\n", hop.TTL, hop.Address, hop.ElapsedTime)
        }
    }()

    // Use the final aggregated result if you need
    fmt.Println("Traceroute finished. Total hops:", len(result.Hops))
}
```

---

#### 📚 References

[RFC 792 — Internet Control Message Protocol (ICMP)](https://datatracker.ietf.org/doc/html/rfc792)
