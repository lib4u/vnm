package netstate

import (
	"net/netip"
	"slices"
)

// NormalizePrefixes returns the ranges masked, sorted, without duplicates and
// without ranges contained in another one. The result is deterministic, so two
// equal inputs render to byte-identical rulesets and the agent can compare the
// kernel state against the desired one without false drift.
func NormalizePrefixes(in []netip.Prefix) []netip.Prefix {
	masked := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		masked = append(masked, unmap(p).Masked())
	}
	slices.SortFunc(masked, comparePrefixes)

	out := make([]netip.Prefix, 0, len(masked))
	for _, p := range masked {
		if n := len(out); n > 0 && covers(out[n-1], p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// comparePrefixes orders by family, then address, then shorter prefix first —
// so a covering range always precedes the ranges it covers.
func comparePrefixes(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// covers reports whether outer contains the whole of inner.
func covers(outer, inner netip.Prefix) bool {
	return outer.Addr().BitLen() == inner.Addr().BitLen() &&
		outer.Bits() <= inner.Bits() &&
		outer.Contains(inner.Addr())
}

// SplitByFamily partitions ranges into IPv4 and IPv6.
func SplitByFamily(in []netip.Prefix) (v4, v6 []netip.Prefix) {
	v4, v6 = []netip.Prefix{}, []netip.Prefix{}
	for _, p := range in {
		if FamilyOf(p) == IPv4 {
			v4 = append(v4, p)
			continue
		}
		v6 = append(v6, p)
	}
	return v4, v6
}

// unmap turns an IPv4-mapped IPv6 range (::ffff:a.b.c.d/96+) into the IPv4
// range it means: as IPv6 it would sit in a v6 set and never match the IPv4
// traffic it names.
func unmap(p netip.Prefix) netip.Prefix {
	const mappedBits = 96
	if !p.Addr().Is4In6() || p.Bits() < mappedBits {
		return p
	}
	return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-mappedBits)
}
