// Package testsupport holds fixtures shared by the tests of several packages.
package testsupport

import (
	"net/netip"
	"net/url"
	"regexp"
	"slices"

	"github.com/lib4u/vnm/internal/domain/policy"
)

// Addresses of the fixture world. They come from the documentation ranges,
// which are not special-purpose and so are never exempted by the planner.
var (
	// RUSite is a destination inside RURanges.
	RUSite = netip.MustParseAddr("198.51.100.10")
	// RUClient is a client address that is itself inside RURanges: the policy
	// must never touch traffic answering it (invariant I-3).
	RUClient = netip.MustParseAddr("198.51.100.50")
	// ForeignSite is a destination outside every list.
	ForeignSite = netip.MustParseAddr("203.0.113.10")
	// WarpEndpoint is the exit's peer.
	WarpEndpoint = netip.MustParseAddrPort("192.0.2.1:2408")
	// Management is an exempt address.
	Management = netip.MustParsePrefix("192.0.2.200/32")
	// DNSUpstream answers the node's resolver; a foreign address.
	DNSUpstream = netip.MustParseAddrPort("203.0.113.53:53")
	// Scanner is a source the guard refuses; a foreign address.
	Scanner = netip.MustParseAddr("203.0.113.66")
)

// RUSuffixes are the zones of the fixture "ru_suffix" list, and so its
// resolved domains.
var RUSuffixes = []string{"ru", "xn--p1ai"}

// ScannerRanges are the fixture "scanners" guard list. Management is in it on
// purpose: exempt must win over the guard (G-3).
var ScannerRanges = []netip.Prefix{
	netip.PrefixFrom(Scanner, 32),
	Management,
	netip.MustParsePrefix("2001:db8:666::/48"),
}

// Geo are the fixture's geo file URLs. They only need to be valid https URLs:
// the real source is the operator's choice and lives in configs/vnm.yaml.
var Geo = policy.GeoFiles{
	GeoIP:   "https://geo.example.test/geoip.dat",
	GeoSite: "https://geo.example.test/geosite.dat",
}

// RURanges are the resolved ranges of the fixture "ru_ip" list.
var RURanges = []netip.Prefix{
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("2001:db8:100::/48"),
}

// Policy returns a valid policy: RU ranges and zones through the "warp" exit,
// block as fallback; scanners refused by the guard.
func Policy() policy.Config {
	health, _ := url.Parse("https://www.cloudflare.com/cdn-cgi/trace")
	return policy.Config{
		Version: policy.CurrentVersion,
		Mode:    policy.ModeEnforce,
		Geo:     Geo,
		DNS: policy.DNS{
			Port:      5353,
			Upstreams: []netip.AddrPort{DNSUpstream},
		},
		Uplinks: []string{"ens3"},
		Exits: []policy.Exit{{
			Name:      "warp",
			Slot:      0,
			Iface:     "warp",
			Conf:      "/etc/vnm/exits/warp/warp.conf",
			Endpoints: []netip.AddrPort{WarpEndpoint},
			Health:    policy.Probe{URL: health, Expect: regexp.MustCompile(`warp=(on|plus)`)},
		}},
		Lists: []policy.List{
			{Name: "ru_ip", IP: []policy.Source{{Kind: policy.SourceGeoIP, Value: "ru"}}, Bounds: policy.DefaultBounds},
			{Name: "ru_suffix", Suffix: slices.Clone(RUSuffixes), Bounds: policy.DefaultBounds},
			{Name: "scanners", ExtraCIDR: ScannerRanges, Bounds: policy.DefaultBounds},
		},
		Rules: []policy.Rule{{
			Lists:    []string{"ru_ip", "ru_suffix"},
			Action:   policy.Action{Kind: policy.ActionExit, Exit: "warp"},
			Fallback: policy.ActionBlock,
		}},
		Exempt: []netip.Prefix{Management},
		Guard: policy.Guard{
			Mode:  policy.ModeEnforce,
			Rules: []policy.GuardRule{{Lists: []string{"scanners"}, Action: policy.GuardDrop, Log: true}},
		},
	}
}
