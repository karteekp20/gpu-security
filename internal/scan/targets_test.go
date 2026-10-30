package scan

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestExpandCIDRSkipsNetworkAndBroadcast(t *testing.T) {
	hosts, err := ExpandCIDR("192.0.2.0/30", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.0.2.1", "192.0.2.2"}
	if len(hosts) != len(want) {
		t.Fatalf("want %v, got %v", want, hosts)
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Errorf("host %d: want %s, got %s", i, want[i], hosts[i])
		}
	}
}

func TestExpandCIDRSlash31KeepsBothAddresses(t *testing.T) {
	hosts, err := ExpandCIDR("192.0.2.0/31", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("a /31 is a point-to-point link; want 2 hosts, got %v", hosts)
	}
}

func TestExpandCIDRSlash24(t *testing.T) {
	hosts, err := ExpandCIDR("10.1.2.0/24", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 254 {
		t.Fatalf("want 254 usable hosts in a /24, got %d", len(hosts))
	}
}

func TestExpandCIDRMultipleBlocks(t *testing.T) {
	hosts, err := ExpandCIDR("192.0.2.0/30, 198.51.100.0/30", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 4 {
		t.Fatalf("want 4 hosts across two /30s, got %v", hosts)
	}
}

func TestExpandCIDRRefusesLargeBlockByDefault(t *testing.T) {
	if _, err := ExpandCIDR("10.0.0.0/8", false); err == nil {
		t.Fatal("expected a /8 to be refused without -allow-large-cidr")
	}
}

func TestExpandCIDRHardCeilingIgnoresOverride(t *testing.T) {
	// The override widens the guard; it does not remove the hard ceiling.
	if _, err := ExpandCIDR("10.0.0.0/8", true); err == nil {
		t.Fatal("expected a /8 to exceed the hard ceiling even with the override")
	}
}

func TestExpandCIDRInvalid(t *testing.T) {
	if _, err := ExpandCIDR("not-a-cidr", false); err == nil {
		t.Fatal("expected an error for a malformed CIDR")
	}
}

func TestApplyPortOverrideMovesService(t *testing.T) {
	checks, err := ApplyPortOverrides(DefaultChecks(), "vllm=8100")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range checks {
		if c.Service == "vllm" && c.Port != 8100 {
			t.Errorf("vllm should have moved to 8100, got %d", c.Port)
		}
		if c.Service == "triton" && c.Port != 8000 {
			t.Errorf("triton should be untouched on 8000, got %d", c.Port)
		}
	}
}

func TestApplyPortOverrideAddsBarePort(t *testing.T) {
	checks, err := ApplyPortOverrides(DefaultChecks(), "9000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, c := range checks {
		if c.Port == 9000 && c.Service == ServiceUnknown {
			found = true
		}
	}
	if !found {
		t.Error("expected a bare port to be probed as an unidentified service")
	}
}

func TestApplyPortOverrideRejectsUnknownService(t *testing.T) {
	if _, err := ApplyPortOverrides(DefaultChecks(), "not-a-service=9000"); err == nil {
		t.Fatal("expected an error for an unknown service name")
	}
}

func TestApplyPortOverrideRejectsBadPort(t *testing.T) {
	for _, spec := range []string{"vllm=0", "vllm=99999", "vllm=abc", "70000"} {
		if _, err := ApplyPortOverrides(DefaultChecks(), spec); err == nil {
			t.Errorf("expected an error for %q", spec)
		}
	}
}

// FuzzExpandCIDR looks for a -cidr value that panics or escapes the limits.
// The function does arithmetic on prefix lengths and a left shift on host
// bits, which is exactly the shape of code that is fine until it is not; and
// its input comes from an operator's command line, often pasted.
func FuzzExpandCIDR(f *testing.F) {
	for _, seed := range []string{
		"10.0.0.0/24", "10.0.0.0/31", "10.0.0.0/32", "0.0.0.0/0",
		"192.168.1.0/23,10.0.0.0/30", "fd00::/120", "::/0",
		"::ffff:10.0.0.0/120", "10.0.0.5", "10.0.0.0/33", "",
		",,", " 10.0.0.0/30 ", "10.0.0.0/8",
	} {
		f.Add(seed, false)
		f.Add(seed, true)
	}

	f.Fuzz(func(t *testing.T, spec string, allowLarge bool) {
		hosts, err := ExpandCIDR(spec, allowLarge)
		if err != nil {
			if hosts != nil {
				t.Errorf("ExpandCIDR(%q) returned %d hosts alongside an error", spec, len(hosts))
			}
			return
		}
		if len(hosts) > maxExpandedHosts {
			t.Errorf("ExpandCIDR(%q) returned %d hosts, over the %d ceiling",
				spec, len(hosts), maxExpandedHosts)
		}
		for _, h := range hosts {
			if _, perr := netip.ParseAddr(h); perr != nil {
				t.Errorf("ExpandCIDR(%q) returned %q, which is not an address", spec, h)
			}
		}
	})
}

// TestExpandCIDRIPv6 pins the v6 rules, which differ from v4 in two ways that
// are easy to get wrong: there is no network or broadcast address to skip, so
// a /120 is 256 usable hosts rather than 254; and the width limit is /112
// rather than /16, because a v6 subnet of the same prefix length is
// astronomically larger.
func TestExpandCIDRIPv6(t *testing.T) {
	hosts, err := ExpandCIDR("fd00::/120", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 256 {
		t.Errorf("a v6 /120 should expand to 256 hosts (no network/broadcast to skip), got %d", len(hosts))
	}
	if hosts[0] != "fd00::" {
		t.Errorf("the first address of a v6 block is usable; got %q", hosts[0])
	}

	// /111 is wider than the v6 floor and must be refused without the flag.
	if _, err := ExpandCIDR("fd00::/111", false); err == nil {
		t.Error("a /111 should be refused without -allow-large-cidr")
	}
	if _, err := ExpandCIDR("fd00::/111", true); err != nil {
		t.Errorf("-allow-large-cidr should permit a /111: %v", err)
	}

	// Unmasked input is masked, so a host address inside a block expands to
	// the block rather than silently scanning from the middle.
	hosts, err = ExpandCIDR("fd00::ff/126", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 4 || hosts[0] != "fd00::fc" {
		t.Errorf("expected the masked /126 fd00::fc-ff, got %v", hosts)
	}
}

// -----------------------------------------------------------------------------
// Target validation
//
// The case that motivates all of this: `-targets https://10.0.0.5:8265` was
// accepted, recorded as an unresolved host, and - with any one reachable host
// alongside it - graded A+ with exit 0. See NormalizeTarget.
// -----------------------------------------------------------------------------

func TestNormalizeTargetAcceptsWhatWeCanProbe(t *testing.T) {
	cases := map[string]string{
		"10.0.0.5":                   "10.0.0.5",
		" 10.0.0.5 ":                 "10.0.0.5",
		"::1":                        "::1",
		"[::1]":                      "::1",
		"0:0:0:0:0:0:0:1":            "::1", // canonicalized: one target, not two
		"fd00::ff":                   "fd00::ff",
		"ray-head":                   "ray-head",
		"ray-head.internal.acme.com": "ray-head.internal.acme.com",
		"ray_head.internal":          "ray_head.internal", // illegal in DNS, common in practice
		"RAY-HEAD.Internal":          "RAY-HEAD.Internal",
		"gpu01.":                     "gpu01.", // the trailing root dot is legal
		"node-1a2b":                  "node-1a2b",
	}
	for in, want := range cases {
		got, err := NormalizeTarget(in)
		if err != nil {
			t.Errorf("NormalizeTarget(%q) = error %v, want it accepted", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNormalizeTargetRejectsWithAUsefulHint checks the rejection AND the hint.
// The hint is most of the value: "not a valid target" sends an operator to the
// README mid-engagement, while "that is a URL, pass the host" is fixed in the
// same keystroke.
func TestNormalizeTargetRejectsWithAUsefulHint(t *testing.T) {
	cases := []struct{ in, wantHint string }{
		{"https://10.0.0.5:8265", "pass just the host"},
		{"http://ray-head/dashboard", "pass just the host"},
		{"10.0.0.5:8265", "-ports"},
		{"[::1]:8265", "IPv6"},
		{"10.0.0.0/24", "-cidr"},
		{"fd00::/120", "-cidr"},
		{"10.0.0.5/ui", "-buckets"},
		{"ray-head # head node", "line of its own"},
		{"ray head", "whitespace"},
		{`"10.0.0.5"`, "cannot appear in a hostname"},
		{"10.0.0.256", "not a valid one"},
		{"10.0.0.05", "not a valid one"},
		{"10.0.0", "not a valid one"},
		{"host..internal", "empty label"},
		{".host", "empty label"},
		{"-timeout", "flag"},
		{"", "empty target"},
	}
	for _, c := range cases {
		_, err := NormalizeTarget(c.in)
		if err == nil {
			t.Errorf("NormalizeTarget(%q) was accepted; it cannot be probed, so it would be reported as an unresolved host", c.in)
			continue
		}
		if !strings.Contains(err.Error(), c.wantHint) {
			t.Errorf("NormalizeTarget(%q) said %q, want it to mention %q", c.in, err, c.wantHint)
		}
	}
}

// TestNormalizeTargetRejectsOverlongNames covers the two DNS length limits,
// which are the only rejections here an operator could hit with input that is
// otherwise shaped correctly.
func TestNormalizeTargetRejectsOverlongNames(t *testing.T) {
	longLabel := strings.Repeat("a", 64)
	if _, err := NormalizeTarget(longLabel + ".internal"); err == nil {
		t.Error("a 64-character label was accepted; the limit is 63")
	}
	if _, err := NormalizeTarget(strings.Repeat("a", 63) + ".internal"); err != nil {
		t.Errorf("a 63-character label must be accepted: %v", err)
	}
	whole := strings.TrimSuffix(strings.Repeat("abcdefgh.", 29), ".") // 260 chars
	if _, err := NormalizeTarget(whole); err == nil {
		t.Errorf("a %d-character name was accepted; the limit is 253", len(whole))
	}
}

// TestNormalizeTargetNeverEchoesACredential: a pasted URL can carry a token,
// and this error lands on stderr, which is a kept log in any CI that gates on
// the exit code.
func TestNormalizeTargetNeverEchoesACredential(t *testing.T) {
	_, err := NormalizeTarget("https://admin:s3cr3t-token@10.0.0.5:8265/")
	if err == nil {
		t.Fatal("a URL was accepted as a target")
	}
	if strings.Contains(err.Error(), "s3cr3t-token") || strings.Contains(err.Error(), "admin:") {
		t.Errorf("the error echoed the credential back: %q", err)
	}
	if !strings.Contains(err.Error(), "10.0.0.5") {
		t.Errorf("the error dropped the host, which is the whole hint: %q", err)
	}
}

// FuzzNormalizeTarget asserts the property that keeps a scan inside its
// authorization: anything accepted as a target must survive being put into a
// probe URL as itself, naming no other host and introducing no path. A target
// that changed meaning between validation and the GET would be a probe nobody
// authorized - the same property the -ports corpus guards for ports.
func FuzzNormalizeTarget(f *testing.F) {
	for _, seed := range []string{
		"10.0.0.5", "::1", "[::1]", "ray-head", "ray_head.internal", "gpu01.",
		"https://10.0.0.5:8265", "10.0.0.5:8265", "10.0.0.0/24", "10.0.0.256",
		"ray-head # note", "", " ", "..", "-x", "a@b", "%2e%2e", "0:0:0:0:0:0:0:1",
		"fe80::1%eth0", "localhost\n10.0.0.5", "10.0.0.5?x=1", "x\\y",
		// Zones found by this fuzz target: netip accepts any bytes after the
		// '%', including the ones that terminate a host inside a URL.
		"::%#", "::%]@elsewhere.example", "::%/evil", "::%" + strings.Repeat("e", 80),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, in string) {
		host, err := NormalizeTarget(in)
		if err != nil {
			return
		}
		if host == "" {
			t.Fatalf("NormalizeTarget(%q) accepted and returned an empty host", in)
		}
		// urlHost is what the probe itself uses to render the host, so this
		// is the real path and not a re-implementation of it.
		probe := "http://" + urlHost(host, 8265) + "/v1/models"
		u, perr := url.Parse(probe)
		if perr != nil {
			t.Fatalf("NormalizeTarget(%q) = %q, which does not form a probe URL: %v", in, host, perr)
		}
		// The URL must name exactly the host we validated, on the port we
		// chose, with the path we chose - nothing smuggled into any of the three.
		want := strings.Trim(host, "[]")
		if u.Hostname() != want {
			t.Errorf("NormalizeTarget(%q) = %q, but the probe URL addresses %q", in, host, u.Hostname())
		}
		if u.Port() != "8265" {
			t.Errorf("NormalizeTarget(%q) = %q, but the probe URL port is %q", in, host, u.Port())
		}
		if u.Path != "/v1/models" || u.RawQuery != "" || u.User != nil {
			t.Errorf("NormalizeTarget(%q) = %q, but the probe URL is %q", in, host, u.String())
		}
		// And it must be dialable as an address pair, which is the other half
		// of what the probe does with it.
		if _, _, serr := net.SplitHostPort(net.JoinHostPort(host, "8265")); serr != nil {
			t.Errorf("NormalizeTarget(%q) = %q, which is not a dialable host: %v", in, host, serr)
		}
	})
}
