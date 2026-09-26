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
