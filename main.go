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

	if !report.HostAlive {
		scanner.LogError("Host no responde (usa -Pn para forzar el escaneo igual)")
		os.Exit(1)
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
		fmt.Println("  Estado      interrumpido (resultados parciales)")
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