package scanner

import (
	"context"
	"net"
)

type DNSInfo struct {
	IPs   []string `json:"ips,omitempty"`
	MX    []string `json:"mx,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	NS    []string `json:"ns,omitempty"`
	CNAME string   `json:"cname,omitempty"`
}

func LookupDNSInfo(ctx context.Context, domain string) DNSInfo {
	var info DNSInfo

	if ips, err := net.DefaultResolver.LookupHost(ctx, domain); err == nil {
		info.IPs = ips
	}

	if mxRecords, err := net.DefaultResolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxRecords {
			info.MX = append(info.MX, mx.Host)
		}
	}

	if txtRecords, err := net.DefaultResolver.LookupTXT(ctx, domain); err == nil {
		info.TXT = txtRecords
	}

	if nsRecords, err := net.DefaultResolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nsRecords {
			info.NS = append(info.NS, ns.Host)
		}
	}

	if cname, err := net.DefaultResolver.LookupCNAME(ctx, domain); err == nil {
		info.CNAME = cname
	}

	return info
}