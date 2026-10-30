package scan

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	// minPrefixV4 / minPrefixV6 are the widest networks we expand without an
	// explicit override. Pointing a scanner at a /8 by typo is a real way to
	// annoy a customer's network team on the first engagement.
	minPrefixV4 = 16
	minPrefixV6 = 112
	// maxExpandedHosts is a hard ceiling that -allow-large-cidr does not lift.
	maxExpandedHosts = 1 << 18
)

// ExpandCIDR turns a comma-separated list of CIDR blocks into host addresses.
// Network and broadcast addresses are skipped for IPv4 blocks that have them.
func ExpandCIDR(spec string, allowLarge bool) ([]string, error) {
	var out []string
	for _, raw := range strings.Split(spec, ",") {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		hosts, err := expandOne(item, allowLarge)
		if err != nil {
			return nil, err
		}
		if len(out)+len(hosts) > maxExpandedHosts {
			return nil, fmt.Errorf("-cidr would expand to more than %d hosts; scan it in smaller blocks", maxExpandedHosts)
		}
		out = append(out, hosts...)
	}
	return out, nil
}

func expandOne(item string, allowLarge bool) ([]string, error) {
	p, err := netip.ParsePrefix(item)
	if err != nil {
		return nil, fmt.Errorf("invalid -cidr entry %q: %w", item, err)
	}
	p = p.Masked()

	minPrefix := minPrefixV4
	if p.Addr().Is6() && !p.Addr().Is4In6() {
		minPrefix = minPrefixV6
	}
	if p.Bits() < minPrefix && !allowLarge {
		return nil, fmt.Errorf("%s is wider than /%d; pass -allow-large-cidr if you really mean it", item, minPrefix)
	}

	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits > 18 {
		return nil, fmt.Errorf("%s would expand to more than %d hosts; scan it in smaller blocks", item, maxExpandedHosts)
	}

	// hostBits is non-negative (Masked guarantees Bits <= BitLen) and capped
	// at 18 just above, so this shift cannot overflow.
	total := 1 << hostBits
	skipEnds := !p.Addr().Is6() && hostBits >= 2

	out := make([]string, 0, total)
	addr := p.Addr()
	for i := 0; i < total; i++ {
		if !(skipEnds && (i == 0 || i == total-1)) {
			out = append(out, addr.String())
		}
		addr = addr.Next()
		if !addr.IsValid() {
			break
		}
	}
	return out, nil
}

// NormalizeTarget checks that a -targets / -targets-file entry is something we
// can actually probe, and returns the host to probe for it.
//
// This is a usage error (the scan does not start) rather than a warning,
// because the alternative is silence that reads as a clean result. An entry we
// cannot dial is recorded as "unresolved" - which is exactly what a genuine
// DNS failure in the customer's environment looks like. Measured before this
// check existed:
//
//	ray-guard -targets https://10.0.0.5:8265,127.0.0.1
//	=> Grade: A+ (score 100/100), exit 0, "1 unresolved"
//
// That paste is the likeliest one an operator makes, because the dashboard URL
// is what is in their browser tab. The host they put in scope was never
// probed, the report graded clean, and the one line admitting it is
// indistinguishable from the customer's own DNS being flaky. It is the rev-7
// false all-clear in a third shape: there the subnet was dark, then our own
// descriptor limit, and here the operator's own command line.
//
// Rejecting costs nothing: nothing has touched the network yet, so the fix is
// to retype the entry rather than to re-scan a customer's cluster against an
// authorization that may have been for one window (docs/assessment/authorization.md).
func NormalizeTarget(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty target")
	}
	// A v6 literal is often pasted in the brackets a URL requires. Accept it;
	// net.JoinHostPort puts them back on itself.
	if inner, ok := strings.CutPrefix(s, "["); ok {
		if host, ok := strings.CutSuffix(inner, "]"); ok {
			s = host
		}
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		if err := checkZone(addr.Zone()); err != nil {
			return "", err
		}
		// Canonicalize so "::1" and "0:0:0:0:0:0:0:1" are one target rather
		// than two, and so the report names the host the same way twice.
		return addr.String(), nil
	}
	if err := checkHostname(s); err != nil {
		return "", err
	}
	return s, nil
}

// checkZone constrains the IPv6 zone, which netip does not: it accepts any
// bytes after the '%', including ']', '@', '/' and '#'. Those are the
// characters that end the host inside a URL, so an entry like
// "::%]@elsewhere.example" renders a probe URL whose authority is no longer
// the target. net/url refuses every such form outright, so what actually
// happens today is the quiet miss of the zone bug rather than a probe sent
// somewhere else - but "we probe the host we were given and nothing else"
// should hold because of what we accept, not because net/url catches it
// downstream. A zone names a local interface; that is all it may be.
//
// Found by FuzzNormalizeTarget within seconds of the property being written.
func checkZone(zone string) error {
	if zone == "" {
		return nil
	}
	// IFNAMSIZ is 16 on Linux; the slack is for platforms that allow more.
	const maxZone = 64
	if len(zone) > maxZone {
		return fmt.Errorf("the zone %q is %d characters; an interface name is at most %d", zone, len(zone), maxZone)
	}
	for _, r := range zone {
		if !isHostRune(r) && r != '.' {
			return fmt.Errorf("the zone %q contains %q; a zone names a local interface, e.g. fe80::1%%eth0", zone, r)
		}
	}
	return nil
}

// ValidateTarget reports whether an entry is probeable, discarding the
// normalized form. It exists for callers that only want the check.
func ValidateTarget(raw string) error {
	_, err := NormalizeTarget(raw)
	return err
}

// checkHostname rejects everything that is not a DNS name, and tries to say
// what the operator probably meant. The hints matter more than the rejection:
// "not a valid target" sends someone to the README, while "that is a URL, pass
// the host" is fixed in the same keystroke.
func checkHostname(s string) error {
	if _, rest, ok := strings.Cut(s, "://"); ok {
		host := hostOfURL(rest)
		// The entry is echoed with any userinfo removed. A pasted URL can
		// carry a token, and this message goes to stderr - which on a tenant
		// gating its CI on the exit code is a log that is kept.
		return fmt.Errorf("%q is a URL: pass just the host (%q) - ray-guard picks the ports itself, and -ports moves one",
			redactUserinfo(s), host)
	}
	if strings.ContainsAny(s, " \t") {
		if strings.Contains(s, "#") {
			return fmt.Errorf("%q has a trailing comment: a `#` comment must be on a line of its own", s)
		}
		return fmt.Errorf("%q contains whitespace: one host per entry", s)
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return fmt.Errorf("%q is a CIDR block: pass it with -cidr, which expands it", s)
	}
	if strings.Contains(s, "/") {
		return fmt.Errorf("%q is not a host: pass a hostname or IP, a CIDR block with -cidr, or a bucket URL with -buckets", s)
	}
	if host, port, ok := strings.Cut(s, ":"); ok {
		if allDigits(port) && port != "" && !strings.Contains(host, ":") {
			return fmt.Errorf("%q is host:port: pass just the host (%q) - ray-guard probes its own port list, and -ports moves a service",
				s, host)
		}
		return fmt.Errorf("%q is neither a hostname nor an IP address (a malformed IPv6 literal?)", s)
	}

	const maxDNSName = 253
	if len(s) > maxDNSName {
		return fmt.Errorf("target is %d characters long; a DNS name is at most %d", len(s), maxDNSName)
	}
	// A single trailing dot is the DNS root and is legal.
	labels := strings.Split(strings.TrimSuffix(s, "."), ".")
	numericOnly := true
	for _, l := range labels {
		if l == "" {
			return fmt.Errorf("%q has an empty label: check for a doubled or leading dot", s)
		}
		if len(l) > 63 {
			return fmt.Errorf("%q has a %d-character label; the limit is 63", s, len(l))
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%q has a label starting or ending with '-': is a flag or a line continuation glued to it?", s)
		}
		for _, r := range l {
			// Underscore is not legal in a hostname but is common in real
			// internal DNS and in container names, so it is allowed: being
			// stricter than the resolver would reject targets that work.
			if !isHostRune(r) {
				return fmt.Errorf("%q contains %q, which cannot appear in a hostname", s, r)
			}
		}
		if !allDigits(l) {
			numericOnly = false
		}
	}
	if numericOnly {
		// Dotted digits that netip rejected: 10.0.0.256, 10.0.0.05, 10.0.0.
		// Treating these as hostnames would send them to the resolver, which
		// fails, and the report would call the typo an unresolved host.
		return fmt.Errorf("%q looks like an IP address but is not a valid one", s)
	}
	return nil
}

func isHostRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '-', r == '_':
		return true
	}
	return false
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// hostOfURL pulls the host out of the remainder of a URL for the hint only.
// It is deliberately not url.Parse: this input already failed to be a target,
// so it may be anything, and a hint is not worth an error path of its own.
func hostOfURL(rest string) string {
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:] // userinfo is not a host
	}
	if h, _, ok := strings.Cut(rest, "]"); ok && strings.HasPrefix(h, "[") {
		return strings.TrimPrefix(h, "[") // bracketed v6 literal
	}
	if h, port, ok := strings.Cut(rest, ":"); ok && allDigits(port) {
		return h
	}
	return rest
}

// redactUserinfo removes a user:password@ prefix from a URL-shaped entry
// before it is echoed in an error. We never put a credential an operator
// pasted by mistake into their terminal history or their CI log.
func redactUserinfo(s string) string {
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		return s
	}
	authority := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority = rest[:i]
	}
	i := strings.LastIndex(authority, "@")
	if i < 0 {
		return s
	}
	return scheme + "://" + "[redacted]@" + rest[i+1:]
}
