package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type wafSignature struct {
	name    string
	headers map[string]string 
	cookies []string
}

var wafSignatures = []wafSignature{
	{
		name:    "Cloudflare",
		headers: map[string]string{"Server": "cloudflare", "CF-RAY": ""},
		cookies: []string{"__cfduid", "__cf_bm", "cf_clearance"},
	},
	{
		name:    "Akamai",
		headers: map[string]string{"Server": "akamaighost", "X-Akamai-Transformed": ""},
	},
	{
		name:    "AWS WAF / CloudFront",
		headers: map[string]string{"X-Amz-Cf-Id": "", "Server": "cloudfront"},
	},
	{
		name:    "Sucuri",
		headers: map[string]string{"Server": "sucuri", "X-Sucuri-ID": ""},
	},
	{
		name:    "Imperva Incapsula",
		headers: map[string]string{"X-Iinfo": ""},
		cookies: []string{"incap_ses_", "visid_incap_"},
	},
	{
		name:    "F5 BIG-IP ASM",
		cookies: []string{"TS01", "BIGipServer"},
	},
	{
		name:    "Barracuda",
		cookies: []string{"barra_counter_session"},
	},
	{
		name:    "FortiWeb",
		cookies: []string{"FORTIWAFSID"},
	},
	{
		name:    "ModSecurity",
		headers: map[string]string{"Server": "mod_security"},
	},
	{
		name:    "Wordfence (WordPress)",
		headers: map[string]string{"X-Firewall": "wordfence"},
	},
}

func DetectWAF(ctx context.Context, target string, useHTTPS bool, timeoutMs int) string {
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
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Falken/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	rawCookies := strings.Join(resp.Header.Values("Set-Cookie"), "; ")

	for _, sig := range wafSignatures {
		for header, substr := range sig.headers {
			val := resp.Header.Get(header)
			if val == "" {
				continue
			}
			if substr == "" || strings.Contains(strings.ToLower(val), strings.ToLower(substr)) {
				return sig.name
			}
		}
		for _, cookiePattern := range sig.cookies {
			if strings.Contains(strings.ToLower(rawCookies), strings.ToLower(cookiePattern)) {
				return sig.name
			}
		}
	}

	return ""
}