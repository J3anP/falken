package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// para determinar si el host esta vivo.
var discoveryPorts = []int{80, 443, 22, 445, 3389, 8080}

func IsHostAlive(ctx context.Context, target string, timeoutMs int) bool {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	aliveChan := make(chan bool, len(discoveryPorts))
	var wg sync.WaitGroup
	var d net.Dialer

	for _, port := range discoveryPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := net.JoinHostPort(target, fmt.Sprintf("%d", p))

			dialCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			conn, err := d.DialContext(dialCtx, "tcp", address)
			if err == nil {
				conn.Close()
				aliveChan <- true
				return
			}
			if netErr, ok := err.(net.Error); ok && !netErr.Timeout() {
				aliveChan <- true
			}
		}(port)
	}

	go func() {
		wg.Wait()
		close(aliveChan)
	}()

	for alive := range aliveChan {
		if alive {
			return true
		}
	}
	return false
}