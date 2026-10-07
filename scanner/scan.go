package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Result struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
}

type ScanReport struct {
	Target      string    `json:"target"`
	HostAlive   bool      `json:"host_alive"`
	StartTime   time.Time `json:"start_time"`
	Duration    string    `json:"duration"`
	Interrupted bool      `json:"interrupted,omitempty"`
	OpenPorts   []Result  `json:"open_ports"`
}

func RunScan(ctx context.Context, cfg *Config, ports []int) ScanReport {
	start := time.Now()

	if !cfg.SkipDiscovery {
		alive := IsHostAlive(ctx, cfg.Target, cfg.Timeout)
		if !alive {
			return ScanReport{
				Target: cfg.Target, HostAlive: false,
				StartTime: start, Duration: time.Since(start).String(),
			}
		}
	}

	total := len(ports)
	jobs := make(chan int, total)
	results := make(chan Result, total)
	var wg sync.WaitGroup
	var scanned int64

	var limiter <-chan time.Time
	if cfg.RateLimit > 0 {
		interval := time.Second / time.Duration(cfg.RateLimit)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		limiter = ticker.C
	}

	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				n := atomic.LoadInt64(&scanned)
				fmt.Printf("\r[*] Progreso: %d/%d puertos (%.1f%%)", n, total, float64(n)/float64(total)*100)
			case <-done:
				return
			}
		}
	}()

	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case port, ok := <-jobs:
					if !ok {
						return
					}
					if limiter != nil {
						select {
						case <-limiter:
						case <-ctx.Done():
							return
						}
					}
					if cfg.UDP {
						scanPortUDP(ctx, cfg.Target, port, cfg.Timeout, results)
					} else {
						scanPortTCP(ctx, cfg.Target, port, cfg.Timeout, cfg.GrabBanners, results)
					}
					atomic.AddInt64(&scanned, 1)
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	//Productor
	go func() {
		defer close(jobs)
		for _, p := range ports {
			select {
			case jobs <- p:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(done)
		close(results)
	}()

	var open []Result
	for r := range results {
		open = append(open, r)
		if r.Service != "" {
			LogSuccess("%d/tcp abierto - %s", r.Port, r.Service)
		} else {
			LogSuccess("%d/tcp abierto", r.Port)
		}
	}
	fmt.Printf("\r[*] Progreso: %d/%d puertos (100.0%%)\n", total, total)

	interrupted := ctx.Err() != nil
	if interrupted {
		LogError("Escaneo interrumpido...")
	}

	return ScanReport{
		Target:      cfg.Target,
		HostAlive:   true,
		StartTime:   start,
		Duration:    time.Since(start).String(),
		Interrupted: interrupted,
		OpenPorts:   open,
	}
}

func scanPortTCP(ctx context.Context, target string, port int, timeoutMs int, grabBanner bool, results chan<- Result) {
	address := fmt.Sprintf("%s:%d", target, port)
	timeout := time.Duration(timeoutMs) * time.Millisecond

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return
	}
	conn.Close()

	res := Result{Port: port, State: "open"}
	if grabBanner {
		res.Service = GrabBanner(ctx, target, port, timeoutMs)
	}
	results <- res
}