package scan

import (
	"net/netip"
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
