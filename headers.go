package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

func AuditSecurityHeaders(ctx context.Context, target string, useHTTPS bool, timeoutMs int) (map[string]string, error) {
	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, target)

	client := &http.Client{
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Falken/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := make(map[string]string, len(securityHeaders))
	for _, h := range securityHeaders {
		val := resp.Header.Get(h)
		if val == "" {
			result[h] = "ausente"
		} else {
			result[h] = val
		}
	}
	return result, nil
}