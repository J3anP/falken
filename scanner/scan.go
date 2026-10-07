package scanner

import (
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
	Target    string    `json:"target"`
	HostAlive bool      `json:"host_alive"`
	StartTime time.Time `json:"start_time"`
	Duration  string    `json:"duration"`
	OpenPorts []Result  `json:"open_ports"`
}

func RunScan(cfg *Config, ports []int) ScanReport {
	start := time.Now()

	if !cfg.SkipDiscovery {
		alive := IsHostAlive(cfg.Target, cfg.Timeout)
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
			for port := range jobs {
				if limiter != nil {
					<-limiter // bloquea el worker hasta el siguiente tick permitido
				}
				if cfg.UDP {
					scanPortUDP(cfg.Target, port, cfg.Timeout, results)
				} else {
					scanPortTCP(cfg.Target, port, cfg.Timeout, cfg.GrabBanners, results)
				}
				atomic.AddInt64(&scanned, 1)
			}
		}()
	}

	//Productor
	go func() {
		for _, p := range ports {
			jobs <- p
		}
		close(jobs)
	}()

	//Cierre de canales cuando todos los workers terminan
	go func() {
		wg.Wait()
		close(done)
		close(results)
	}()

	//Consumidor
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

	return ScanReport{
		Target:    cfg.Target,
		HostAlive: true,
		StartTime: start,
		Duration:  time.Since(start).String(),
		OpenPorts: open,
	}
}

func scanPortTCP(target string, port int, timeoutMs int, grabBanner bool, results chan<- Result) {
	address := fmt.Sprintf("%s:%d", target, port)
	timeout := time.Duration(timeoutMs)*time.Millisecond

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return
	}
	conn.Close()

	res := Result{Port: port, State: "open"}
	if grabBanner {
		res.Service = GrabBanner(target, port, timeoutMs)
	}
	results <- res
}
