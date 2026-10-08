package scanner

import "context"

type PassiveReport struct {
	Subdomains      []string          `json:"subdomains,omitempty"`
	DNS             DNSInfo           `json:"dns"`
	Whois           string            `json:"whois,omitempty"`
	FaviconHash     string            `json:"favicon_hash,omitempty"`
	SecurityHeaders map[string]string `json:"security_headers,omitempty"`
}

func RunPassiveRecon(ctx context.Context, target string, timeoutMs int) PassiveReport {
	var report PassiveReport

	if subs, err := CrtShSubdomains(ctx, target, timeoutMs); err == nil {
		report.Subdomains = subs
	}

	report.DNS = LookupDNSInfo(ctx, target)

	if whois, err := WhoisLookup(ctx, target, timeoutMs); err == nil {
		report.Whois = whois
	}

	if hash, err := FaviconHash(ctx, target, true, timeoutMs); err == nil {
		report.FaviconHash = hash
	} else if hash, err := FaviconHash(ctx, target, false, timeoutMs); err == nil {
		report.FaviconHash = hash
	}

	if headers, err := AuditSecurityHeaders(ctx, target, true, timeoutMs); err == nil {
		report.SecurityHeaders = headers
	} else if headers, err := AuditSecurityHeaders(ctx, target, false, timeoutMs); err == nil {
		report.SecurityHeaders = headers
	}

	return report
}