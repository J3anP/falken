package scanner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

func GrabBanner(ctx context.Context, target string, port int, timeoutMs int) string {
	if tlsPorts[port] {
		if info := GrabTLSInfo(ctx, target, port, timeoutMs); info != "" {
			return info
		}
	}

	address := fmt.Sprintf("%s:%d", target, port)
	timeout := time.Duration(timeoutMs)*time.Millisecond

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err == nil && banner != "" {
		return sanitizeBanner(banner)
	}

	if port == 80 || port == 8080 || port == 8000 {
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
		conn.SetDeadline(time.Now().Add(timeout))
		banner, err = reader.ReadString('\n')
		if err == nil && banner != "" {
			return sanitizeBanner(banner)
		}
	}

	return ""
}

func sanitizeBanner(raw string) string {
	clean := strings.TrimSpace(raw)
	if len(clean) > 100 {
		clean = clean[:100] + "..."
	}
	return clean
}
