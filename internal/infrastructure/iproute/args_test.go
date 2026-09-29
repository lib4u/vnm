package iproute_test

import (
	"slices"
	"testing"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/infrastructure/iproute"
)

func TestRuleArgs(t *testing.T) {
	rules := netstate.ExitRules(0)
	tests := []struct {
		rule netstate.IPRule
		want []string
	}{
		{rules[0], []string{"priority", "1000", "fwmark", "0xca6c/0xffff", "lookup", "51820"}},
		{rules[1], []string{"priority", "1001", "fwmark", "0xca6c/0xffff", "unreachable"}},
	}
	for _, tt := range tests {
		if got := iproute.RuleArgs(tt.rule); !slices.Equal(got, tt.want) {
			t.Errorf("RuleArgs(%+v) = %v, want %v", tt.rule, got, tt.want)
		}
	}
}

func TestRouteArgs(t *testing.T) {
	got := iproute.RouteArgs(netstate.Route{Table: 51820, Dev: "warp"})
	want := []string{"unicast", "default", "table", "51820", "dev", "warp"}
	if !slices.Equal(got, want) {
		t.Fatalf("RouteArgs = %v, want %v", got, want)
	}
}
