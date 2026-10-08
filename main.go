package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/J3anP/falken/scanner"
)

func main() {
	scanner.PrintBanner()
	cfg := scanner.ParseFlags()

	ports, err := scanner.ParsePorts(cfg.PortsRaw)
	if err != nil {
		scanner.LogError("%v", err)
		os.Exit(1)
	}

	printScanInfo(cfg, ports)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var passiveReport *scanner.PassiveReport
	if cfg.Passive {
		scanner.LogInfo("Reconocimiento pasivo (crt.sh, DNS, WHOIS, favicon, headers)...")
		pr := scanner.RunPassiveRecon(ctx, cfg.Target, cfg.Timeout)
		passiveReport = &pr
	}

	var wafResult string
	if cfg.WAFDetect {
		wafResult = scanner.DetectWAF(ctx, cfg.Target, true, cfg.Timeout)
		if wafResult == "" {
			wafResult = scanner.DetectWAF(ctx, cfg.Target, false, cfg.Timeout)
		}
	}

	if !cfg.SkipDiscovery {
		scanner.LogInfo("Verificando host...")
	}

	report := scanner.RunScan(ctx, cfg, ports)
	report.Passive = passiveReport

	if !report.HostAlive {
		scanner.LogError("Host no responde (usa -Pn para forzar el escaneo)")
		os.Exit(1)
	}

	if passiveReport != nil {
		printPassiveReport(*passiveReport)
	}

	printFinalReport(report, len(ports), cfg.WAFDetect, wafResult)

	if cfg.OutputPath != "" {
		if err := scanner.ExportJSON(report, cfg.OutputPath); err != nil {
			scanner.LogError("%v", err)
			os.Exit(1)
		}
		scanner.LogSuccess("Resultados exportados a %s", cfg.OutputPath)
	}
}

func printScanInfo(cfg *scanner.Config, ports []int) {
	mode := "TCP"
	if cfg.UDP {
		mode = "UDP"
	}

	fmt.Printf("  Objetivo   %s\n", cfg.Target)
	fmt.Printf("  Puertos    %s\n", scanner.DescribePorts(cfg.PortsRaw, len(ports)))
	fmt.Printf("  Workers    %d\n", cfg.Workers)
	fmt.Printf("  Modo       %s\n", mode)
	if cfg.RateLimit > 0 {
		fmt.Printf("  Rate limit %d conexiones/seg\n", cfg.RateLimit)
	}
	fmt.Println()
}

func printPassiveReport(pr scanner.PassiveReport) {
	separator := strings.Repeat("-", 50)

	fmt.Println("\n" + separator)
	fmt.Println("  RECONOCIMIENTO PASIVO")
	fmt.Println(separator)

	if len(pr.Subdomains) > 0 {
		fmt.Printf("  Subdominios (%d, vía crt.sh):\n", len(pr.Subdomains))
		limit := len(pr.Subdomains)
		if limit > 15 {
			limit = 15
		}
		for _, s := range pr.Subdomains[:limit] {
			fmt.Printf("    - %s\n", s)
		}
		if len(pr.Subdomains) > limit {
			fmt.Printf("    ... y %d más\n", len(pr.Subdomains)-limit)
		}
	} else {
		fmt.Println("  Subdominios: ninguno encontrado")
	}

	fmt.Println()
	if len(pr.DNS.IPs) > 0 {
		fmt.Printf("  IPs           %s\n", strings.Join(pr.DNS.IPs, ", "))
	}
	if len(pr.DNS.MX) > 0 {
		fmt.Printf("  MX            %s\n", strings.Join(pr.DNS.MX, ", "))
	}
	if len(pr.DNS.NS) > 0 {
		fmt.Printf("  NS            %s\n", strings.Join(pr.DNS.NS, ", "))
	}
	if pr.DNS.CNAME != "" {
		fmt.Printf("  CNAME         %s\n", pr.DNS.CNAME)
	}
	if len(pr.DNS.TXT) > 0 {
		fmt.Printf("  TXT           %d registro(s)\n", len(pr.DNS.TXT))
	}

	if pr.FaviconHash != "" {
		fmt.Printf("\n  Favicon hash  %s)\n", pr.FaviconHash, pr.FaviconHash)
	}

	if len(pr.SecurityHeaders) > 0 {
		fmt.Println("\n  Headers de seguridad:")
		for _, h := range []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"} {
			val, ok := pr.SecurityHeaders[h]
			if !ok {
				continue
			}
			fmt.Printf("    %-28s %s\n", h, val)
		}
	}

	if pr.Whois != "" {
		fmt.Println("\n  WHOIS")
	}

	fmt.Println(separator)
}

func printFinalReport(report scanner.ScanReport, portsScanned int, wafRequested bool, wafResult string) {
	separator := strings.Repeat("-", 50)

	fmt.Println("\n" + separator)
	fmt.Printf("  RESULTADOS — %s\n", report.Target)
	fmt.Println(separator)

	if wafRequested {
		if wafResult != "" {
			fmt.Printf("  WAF/CDN     %s\n", wafResult)
		} else {
			fmt.Println("  WAF/CDN     no detectado")
		}
	}

	fmt.Printf("  Puertos     %d abiertos / %d escaneados\n", len(report.OpenPorts), portsScanned)
	fmt.Printf("  Duración    %s\n", report.Duration)
	if report.Interrupted {
		fmt.Println("  Estado      interrumpido")
	}

	if len(report.OpenPorts) > 0 {
		fmt.Println(separator)
		for _, r := range report.OpenPorts {
			if r.Service != "" {
				fmt.Printf("  %-6d  open   %s\n", r.Port, r.Service)
			} else {
				fmt.Printf("  %-6d  open\n", r.Port)
			}
		}
	}

	fmt.Println(separator)
}