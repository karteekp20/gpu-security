package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"gpusecurity/internal/domain"
	"gpusecurity/internal/report"
	"gpusecurity/internal/scan"
)

func main() {
	targetsArg := flag.String("targets", "", "comma-separated hosts/IPs to scan")
	targetsFile := flag.String("targets-file", "", "file with one host/IP per line")
	outDir := flag.String("out", "./report", "output directory for report files")
	timeout := flag.Duration("timeout", 4*time.Second, "per-probe timeout")
	concurrency := flag.Int("concurrency", 32, "max concurrent host probes")
	flag.Parse()

	targets, err := loadTargets(*targetsArg, *targetsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no targets: use -targets host1,host2 or -targets-file hosts.txt")
		os.Exit(2)
	}

	fmt.Printf("ray-guard: scanning %d target(s)...\n", len(targets))
	start := time.Now()

	scanner := scan.New(*timeout)
	sem := make(chan struct{}, *concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var observations []domain.Observation
	ctx := context.Background()

	for _, t := range targets {
		t := t
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			obs := scanner.ProbeHost(ctx, t)
			mu.Lock()
			observations = append(observations, obs...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	findings := scan.Detect(observations)
	result := domain.NewScanResult(start, time.Now(), len(targets), findings)

	if err := report.Write(*outDir, result); err != nil {
		fmt.Fprintln(os.Stderr, "report error:", err)
		os.Exit(1)
	}
	report.PrintSummary(os.Stdout, result)
	fmt.Printf("\nreport written to %s/ (report.json, report.html)\n", *outDir)
}

func loadTargets(arg, file string) ([]string, error) {
	var out []string
	for _, s := range strings.Split(arg, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "#") {
				out = append(out, s)
			}
		}
	}
	return out, nil
}
