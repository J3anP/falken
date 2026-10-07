package scanner

import (
	"context"
	"fmt"
	"net"
	"time"
)

var udpProbes = map[int][]byte{
	53:  {0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	123: append([]byte{0x1b}, make([]byte, 47)...),
	161: {0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63},
}

func scanPortUDP(ctx context.Context, target string, port int, timeoutMs int, results chan<- Result) {
	address := fmt.Sprintf("%s:%d", target, port)
	timeout := time.Duration(timeoutMs) * time.Millisecond

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "udp", address)
	if err != nil {
		return
	}
	defer conn.Close()

	probe, hasProbe := udpProbes[port]
	if !hasProbe {
		probe = []byte{0x00}
	}

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(probe); err != nil {
		return
	}

	buf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buf)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			results <- Result{Port: port, State: "open|filtered"}
			return
		}
		results <- Result{Port: port, State: "closed"}
		return
	}

	if n > 0 {
		results <- Result{Port: port, State: "open"}
	}
}