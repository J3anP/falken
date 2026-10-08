package scanner

import (
	"flag"
	"fmt"
	"os"
)

// Opciones
type Config struct {
	Target        string
	PortsRaw      string
	Workers       int
	OutputPath    string
	RateLimit     int  
	Timeout       int  
	GrabBanners   bool // -sV
	SkipDiscovery bool // -Pn
	UDP           bool // -sU
	WAFDetect     bool
	Passive bool
}

func ParseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.Target, "t", "", "Target IP or domain")
	flag.StringVar(&cfg.Target, "target", "", "Target IP or domain")

	flag.StringVar(&cfg.PortsRaw, "p", "1-1024", `Port range (e.g. "80,443,1-1024" or "top-100")`)
	flag.StringVar(&cfg.PortsRaw, "ports", "1-1024", `Port range (e.g. "80,443,1-1024" or "top-100")`)

	flag.IntVar(&cfg.Workers, "w", 100, "Number of concurrent workers")
	flag.IntVar(&cfg.Workers, "workers", 100, "Number of concurrent workers")

	flag.StringVar(&cfg.OutputPath, "o", "", "Output JSON file path")
	flag.StringVar(&cfg.OutputPath, "output", "", "Output JSON file path")

	flag.IntVar(&cfg.RateLimit, "rate", 0, "Max connections per second (0 = unlimited)")
	flag.IntVar(&cfg.Timeout, "timeout", 800, "Connection timeout in ms")
	flag.BoolVar(&cfg.GrabBanners, "sV", false, "Enable service/banner detection on open ports")
	flag.BoolVar(&cfg.SkipDiscovery, "Pn", false, "Skip host discovery, treat host as alive")
	flag.BoolVar(&cfg.UDP, "sU", false, "UDP scan mode instead of TCP")

	flag.BoolVar(&cfg.WAFDetect, "waf", false, "Detect WAF/CDN in front of the target via HTTP fingerprinting")
	flag.BoolVar(&cfg.Passive, "passive", false, "Run passive recon: subdomains (crt.sh), DNS records, WHOIS, favicon hash, security headers")
	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Uso: %s -t <target> -p <ports> [opciones]\n\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if cfg.Target == "" {
		flag.Usage()
		os.Exit(1)
	}
	return cfg
}
