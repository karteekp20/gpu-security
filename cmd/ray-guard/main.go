package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
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
// 7 = inconclusive, meaning no target responded and nothing was verified;
// 130 = interrupted before the scan finished (domain.ExitInterrupted).
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
	label := flag.String("label", "", "engagement label shown on the report (e.g. \"Acme Corp - 2026-10-12\"); never written to the benchmark snapshot")
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

	// Same reason as the output-path check below: an operator who mistyped one
	// of five buckets should find out now, not from a stderr line in the
	// middle of a sweep and a report that quietly omits something in scope.
	for _, b := range buckets {
		if err := scan.ValidateBucketURL(b); err != nil {
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
	ctx, stopSignals := interruptible()
	defer stopSignals()
	observations, hosts, interrupted := probeAll(ctx, scanner, targets, buckets, *concurrency)

	findings := scan.Detect(observations)
	requested := len(targets) + len(buckets)
	// Deliberately not clever: a signal is taken at face value even when every
	// target happens to have been recorded anyway. "All hosts recorded" is not
	// proof of coverage - a host counts as responded as soon as one port
	// answers, so the last host probed may have had ports cut short. Trading a
	// withheld grade on a scan that finished in the same instant for a
	// possible false all-clear is the wrong way round.
	var result domain.ScanResult
	if interrupted {
		result = domain.NewPartialScanResult(start, time.Now(), requested, hosts, findings)
	} else {
		result = domain.NewScanResult(start, time.Now(), hosts, findings)
	}
	result.Label = strings.TrimSpace(*label)
	// The vantage is part of the evidence: a month later, "three of twelve
	// didn't answer" is only interpretable alongside where the scan ran from.
	if h, err := os.Hostname(); err == nil {
		result.ScannedFrom = h
	}

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

// probeAll fans out over targets and buckets, and reports whether it was cut
// short. A cancelled context stops dispatch rather than racing through the
// remaining targets: a probe we abandoned must not be recorded at all, because
// "did not answer" is a claim about the customer's host and "we stopped" is a
// claim about us.
func probeAll(ctx context.Context, scanner *scan.Scanner, targets, buckets []string, concurrency int) ([]domain.Observation, []domain.HostSummary, bool) {
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var observations []domain.Observation
	var hosts []domain.HostSummary

	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		t := t
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			hs := scanner.ProbeHost(ctx, t)
			// A probe that was cancelled mid-flight reports "no response" or
			// even "unresolved" - the resolver fails on a dead context too.
			// Recording either would put a host on the report as unreachable
			// when the only thing that happened is that we gave up on it.
			if ctx.Err() != nil && hs.State != domain.HostResponded {
				return
			}
			mu.Lock()
			observations = append(observations, hs.Observations...)
			hosts = append(hosts, hs.Summary())
			mu.Unlock()
		}()
	}

	for _, b := range buckets {
		if ctx.Err() != nil {
			break
		}
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
			if ctx.Err() != nil && state != domain.HostResponded {
				return
			}
			mu.Lock()
			observations = append(observations, o)
			hosts = append(hosts, domain.HostSummary{Host: o.Host, State: state})
			mu.Unlock()
		}()
	}

	wg.Wait()
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	return observations, hosts, ctx.Err() != nil
}

// interruptible returns a context cancelled by Ctrl-C, so a scan stopped in
// the middle still writes the report for what it did reach.
//
// This is an operator affordance, not a nicety: the reason to stop a running
// scan is usually that it is pointed at the wrong subnet or that the
// authorization window closed, and in both cases throwing away the work means
// re-scanning a customer's cluster to find out what was already known.
//
// The handler is detached after the first signal, so a second Ctrl-C gets the
// default behaviour and kills the process immediately. An operator who wants
// out now must be able to get out now.
func interruptible() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		select {
		case <-sig:
			signal.Stop(sig)
			fmt.Fprintln(os.Stderr,
				"\ninterrupted: stopping probes and writing a partial report "+
					"(press Ctrl-C again to abandon it)")
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, func() {
		signal.Stop(sig)
		cancel()
	}
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
