package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gpusecurity/internal/benchmark"
	"gpusecurity/internal/domain"
	"gpusecurity/internal/report"
	"gpusecurity/internal/scan"
)

// Exit codes. 0 = clean, 1 = runtime error, 2 = usage error; 3-6 encode the
// worst severity observed so a tenant can gate their own CI on the result;
// 7 = inconclusive, meaning no target responded and nothing was verified.
const (
	exitRuntimeError = 1
	exitUsageError   = 2
)

func main() {
	os.Exit(run())
}

func run() int {
	targetsArg := flag.String("targets", "", "comma-separated hosts/IPs to scan")
	targetsFile := flag.String("targets-file", "", "file with one host/IP per line")
	cidrArg := flag.String("cidr", "", "comma-separated CIDR blocks to expand and scan")
	allowLargeCIDR := flag.Bool("allow-large-cidr", false, "permit CIDR blocks wider than /16 (IPv4) or /112 (IPv6)")
	portsArg := flag.String("ports", "", "override probe ports: service=port pairs and/or bare ports (e.g. vllm=8100,9000)")
	bucketsArg := flag.String("buckets", "", "comma-separated object-storage bucket URLs to check for public listing")
	outDir := flag.String("out", "./report", "output directory for report files")
	snapshotPath := flag.String("benchmark-snapshot", "", "write an anonymized benchmark snapshot to this path (no network egress)")
	timeout := flag.Duration("timeout", 4*time.Second, "per-probe timeout")
	concurrency := flag.Int("concurrency", 32, "max concurrent host probes")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("ray-guard", domain.Version)
		return 0
	}

	targets, err := loadTargets(*targetsArg, *targetsFile, *cidrArg, *allowLargeCIDR)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageError
	}
	buckets := splitList(*bucketsArg)
	if len(targets) == 0 && len(buckets) == 0 {
		fmt.Fprintln(os.Stderr, "no targets: use -targets host1,host2 / -targets-file hosts.txt / -cidr 10.0.0.0/24 / -buckets URL")
		return exitUsageError
	}

	checks := scan.DefaultChecks()
	if *portsArg != "" {
		checks, err = scan.ApplyPortOverrides(checks, *portsArg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitUsageError
		}
	}

	// Check the output paths BEFORE touching the network. A scan that runs to
	// completion and then cannot write its report has cost the operator a
	// second pass over a customer's cluster to fix a typo - and the
	// authorization they hold may well have been for one scan in one window.
	if err := ensureWritable(*outDir); err != nil {
		fmt.Fprintln(os.Stderr, "error: cannot write to -out directory:", err)
		return exitUsageError
	}
	if *snapshotPath != "" {
		if err := ensureWritable(filepath.Dir(*snapshotPath)); err != nil {
			fmt.Fprintln(os.Stderr, "error: cannot write -benchmark-snapshot there:", err)
			return exitUsageError
		}
	}

	if len(targets) > 0 {
		fmt.Printf("ray-guard %s: scanning %d target(s)...\n", domain.Version, len(targets))
	}
	if len(buckets) > 0 {
		fmt.Printf("ray-guard %s: checking %d bucket(s)...\n", domain.Version, len(buckets))
	}
	start := time.Now()

	scanner := scan.NewWithChecks(*timeout, checks)
	ctx := context.Background()
	observations, hosts := probeAll(ctx, scanner, targets, buckets, *concurrency)

	findings := scan.Detect(observations)
	result := domain.NewScanResult(start, time.Now(), hosts, findings)

	if err := report.Write(*outDir, result); err != nil {
		fmt.Fprintln(os.Stderr, "report error:", err)
		return exitRuntimeError
	}
	if *snapshotPath != "" {
		if err := benchmark.Write(*snapshotPath, result, time.Now()); err != nil {
			fmt.Fprintln(os.Stderr, "snapshot error:", err)
			return exitRuntimeError
		}
	}

	report.PrintSummary(os.Stdout, result)
	fmt.Printf("\nreport written to %s/ (report.json, report.html)\n", *outDir)
	if *snapshotPath != "" {
		fmt.Printf("anonymized benchmark snapshot written to %s (not transmitted)\n", *snapshotPath)
	}
	return result.ExitCode()
}

func probeAll(ctx context.Context, scanner *scan.Scanner, targets, buckets []string, concurrency int) ([]domain.Observation, []domain.HostSummary) {
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var observations []domain.Observation
	var hosts []domain.HostSummary

	for _, t := range targets {
		t := t
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			hs := scanner.ProbeHost(ctx, t)
			mu.Lock()
			observations = append(observations, hs.Observations...)
			hosts = append(hosts, hs.Summary())
			mu.Unlock()
		}()
	}

	for _, b := range buckets {
		b := b
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			o, err := scanner.ProbeBucket(ctx, b)
			if err != nil {
				fmt.Fprintln(os.Stderr, "bucket check:", err)
				return
			}
			state := domain.HostResponded
			if o.HTTPStatus == 0 {
				state = domain.HostNoResponse
			}
			mu.Lock()
			observations = append(observations, o)
			hosts = append(hosts, domain.HostSummary{Host: o.Host, State: state})
			mu.Unlock()
		}()
	}

	wg.Wait()
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	return observations, hosts
}

// ensureWritable creates dir if needed and confirms a file can actually be
// created in it. Owner-only, matching the permissions the report is written
// with: a report naming a client's exposed services is a map for anyone who
// wants in.
func ensureWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".ray-guard-writecheck-*")
	if err != nil {
		return err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(name)
}

func loadTargets(arg, file, cidr string, allowLarge bool) ([]string, error) {
	var out []string
	out = append(out, splitList(arg)...)

	if file != "" {
		// #nosec G304 -- this is the -targets-file the operator passed; reading
		// the path they named is the feature.
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

	if cidr != "" {
		hosts, err := scan.ExpandCIDR(cidr, allowLarge)
		if err != nil {
			return nil, err
		}
		out = append(out, hosts...)
	}

	return dedupe(out), nil
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
