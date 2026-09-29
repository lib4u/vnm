package iproute

import (
	"strconv"
	"strings"

	"github.com/lib4u/vnm/internal/domain/netstate"
)

// route is one entry of `ip -j route show`. ip prints no type for a unicast
// route, no metric for metric 0, no protocol for boot — all three hold for the
// agent's routes — and no device for a route without one of its own: an
// unreachable route, or one whose devices are in its nexthops.
type route struct {
	Type     string    `json:"type"`
	Dst      string    `json:"dst"`
	Tos      string    `json:"tos"`
	Dev      string    `json:"dev"`
	Table    string    `json:"table"`
	Metric   int       `json:"metric"`
	Protocol string    `json:"protocol"`
	Prefsrc  string    `json:"prefsrc"`
	Gateway  string    `json:"gateway"`
	NHID     int       `json:"nhid"`
	Nexthops []nexthop `json:"nexthops"`
}

type nexthop struct {
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	Weight  int    `json:"weight"`
}

// parseRoute maps a default route of an owned table to the domain. What tells
// it apart beyond its type, metric and device goes into Extra: a TOS, which a
// deletion must name or it finds no route, and the protocol, source and
// nexthops, which the agent's routes never have. The rest — flags, scope,
// metrics such as mtu — is left out: ReplaceRoute overwrites a route of the
// agent's type, metric and TOS whatever else it carries.
func parseRoute(e route, table int) netstate.Route {
	out := netstate.Route{Table: table, Type: routeType(e.Type), Metric: e.Metric, Dev: e.Dev}
	var extra []string
	add := func(arg, v string) {
		if v != "" {
			extra = append(extra, arg, v)
		}
	}
	add("tos", e.Tos)
	add("proto", e.Protocol)
	add("src", e.Prefsrc)
	switch {
	case e.NHID != 0:
		// ip prints the device and gateway of a nexthop object, but refuses
		// them next to its id.
		out.Dev = ""
		add("nhid", strconv.Itoa(e.NHID))
	case len(e.Nexthops) > 0:
		for _, nh := range e.Nexthops {
			extra = append(extra, "nexthop")
			add("via", nh.Gateway)
			add("dev", nh.Dev)
			if nh.Weight != 0 {
				add("weight", strconv.Itoa(nh.Weight))
			}
		}
	default:
		add("via", e.Gateway)
	}
	out.Extra = strings.Join(extra, " ")
	return out
}

// routeType maps ip's type name to the domain, where unicast is the zero
// value.
func routeType(name string) netstate.RouteType {
	if name == "unicast" {
		return netstate.RouteUnicast
	}
	return netstate.RouteType(name)
}
