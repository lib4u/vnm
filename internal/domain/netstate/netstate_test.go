package netstate

import (
	"net/netip"
	"slices"
	"testing"
)

func TestExitRulesFailClosed(t *testing.T) {
	rules := ExitRules(2)
	lookup, unreachable := rules[0], rules[1]

	if lookup.Action != RuleLookup || lookup.Table != 51822 || lookup.Priority != 1004 {
		t.Fatalf("lookup rule: %+v", lookup)
	}
	// The unreachable rule must come right after the lookup and carry the same
	// mark: a marked packet that finds no route must fail, not fall through to
	// the main table and leave directly.
	if unreachable.Action != RuleUnreachable || unreachable.Priority != lookup.Priority+1 || unreachable.Mark != lookup.Mark {
		t.Fatalf("unreachable rule: %+v", unreachable)
	}
}

func TestExitSlotsStayInOwnedRange(t *testing.T) {
	for slot := range 5 {
		for _, r := range ExitRules(slot) {
			if r.Priority < OwnedPriorities[0] || r.Priority > OwnedPriorities[1] {
				t.Fatalf("slot %d: priority %d outside owned range %v", slot, r.Priority, OwnedPriorities)
			}
		}
	}
	// Slot 0 is the mark Xray outbounds on the fleet already use.
	if ExitMark(0) != 51820 || ExitTable(0) != 51820 {
		t.Fatalf("slot 0: mark %d table %d", ExitMark(0), ExitTable(0))
	}
}

func TestNormalizePrefixes(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("10.1.2.3/24"), // unmasked
		netip.MustParsePrefix("10.0.0.0/8"),  // covers the one above
		netip.MustParsePrefix("2a00::/16"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"), // duplicate
		netip.MustParsePrefix("2a00:1::/32"),  // covered
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2a00::/16"),
	}
	if got := NormalizePrefixes(in); !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// An IPv4-mapped range is the IPv4 range it names.
func TestNormalizeUnmaps4In6(t *testing.T) {
	got := NormalizePrefixes([]netip.Prefix{
		netip.MustParsePrefix("::ffff:198.51.100.0/120"),
		netip.MustParsePrefix("::ffff:0:0/96"),
	})
	want := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	got = NormalizePrefixes([]netip.Prefix{netip.MustParsePrefix("::ffff:198.51.100.7/128")})
	if want := []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
