package main

import (
	"fmt"
	"os"
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

	scanner.LogInfo("Objetivo:   %s", cfg.Target)
	scanner.LogInfo("Puertos:    %d (%s)", len(ports), cfg.PortsRaw)
	scanner.LogInfo("Workers:    %d", cfg.Workers)
	if cfg.RateLimit > 0 {
		scanner.LogInfo("Rate limit: %d conexiones/seg", cfg.RateLimit)
	}
	fmt.Println()

	if !cfg.SkipDiscovery {
		scanner.LogInfo("Verificando si el host está activo...")
	}

	report := scanner.RunScan(cfg, ports)

	if !report.HostAlive {
		scanner.LogError("Host no responde (usa -Pn para forzar el escaneo igual)")
		os.Exit(1)
	}

	printSummary(report, len(ports))

	if cfg.OutputPath != "" {
		if err := scanner.ExportJSON(report, cfg.OutputPath); err != nil {
			scanner.LogError("%v", err)
			os.Exit(1)
		}
		scanner.LogSuccess("Resultados exportados a %s", cfg.OutputPath)
	}
}

func printSummary(report scanner.ScanReport, portsScanned int) {
	separator := strings.Repeat("-", 46)
	fmt.Println("\n" + separator)
	fmt.Println("  RESUMEN DEL ESCANEO")
	fmt.Println(separator)
	fmt.Printf("  Objetivo:         %s\n", report.Target)
	fmt.Printf("  Puertos abiertos: %d / %d\n", len(report.OpenPorts), portsScanned)
	fmt.Printf("  Duración:         %s\n", report.Duration)
	fmt.Println(separator)
}
