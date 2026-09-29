package resolver_test

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/infrastructure/dnsd"
	"github.com/lib4u/vnm/internal/infrastructure/resolver"
)

// The resolver gets the sets under their kernel names, the uplinks it must
// never answer on, and every domain.
func TestConfig(t *testing.T) {
	c := resolver.Config(netstate.DNSState{
		Port:      5353,
		Upstreams: []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")},
		Sets:      []netstate.DomainSet{{Set4: "ru_domain_d4", Set6: "ru_domain_d6", Domains: []string{"vk.com", "ya.ru"}}},
	}, []string{"ens3"})

	data, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var got dnsd.Config
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := dnsd.DomainSet{Set4: "l_ru_domain_d4", Set6: "l_ru_domain_d6", Domains: []string{"vk.com", "ya.ru"}}
	if got.Port != 5353 || !slices.Equal(got.Uplinks, []string{"ens3"}) || len(got.Sets) != 1 ||
		got.Sets[0].Set4 != want.Set4 || got.Sets[0].Set6 != want.Set6 || !slices.Equal(got.Sets[0].Domains, want.Domains) ||
		!slices.Equal(got.Upstreams, []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")}) {
		t.Fatalf("config %+v", got)
	}
}
