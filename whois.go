package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const ianaWhoisServer = "whois.iana.org:43"
const maxWhoisLines = 30

func WhoisLookup(ctx context.Context, domain string, timeoutMs int) (string, error) {
	timeout := time.Duration(timeoutMs) * time.Millisecond

	ianaResp, err := queryWhois(ctx, ianaWhoisServer, domain, timeout)
	if err != nil {
		return "", err
	}

	referServer := parseReferServer(ianaResp)
	if referServer == "" {
		return trimWhoisResponse(ianaResp), nil
	}

	finalResp, err := queryWhois(ctx, referServer+":43", domain, timeout)
	if err != nil {
		return trimWhoisResponse(ianaResp), nil
	}

	return trimWhoisResponse(finalResp), nil
}

func queryWhois(ctx context.Context, server, domain string, timeout time.Duration) (string, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", server)
	if err != nil {
		return "", fmt.Errorf("no se pudo conectar a %s: %w", server, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := fmt.Fprintf(conn, "%s\r\n", domain); err != nil {
		return "", err
	}

	var sb strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteByte('\n')
	}

	return sb.String(), nil
}

func parseReferServer(response string) string {
	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "refer:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "refer:"))
		}
	}
	return ""
}

func trimWhoisResponse(raw string) string {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	var kept []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "%") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		kept = append(kept, trimmed)
		if len(kept) >= maxWhoisLines {
			break
		}
	}
	return strings.Join(kept, "\n")
}