package dnsd

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// Addition is addresses for one set, all of the set's family.
type Addition struct {
	Set   string
	Addrs []netip.Addr
}

// index finds the lists a name belongs to: an entry covers the domain and
// every name under it, as dnsmasq's nftset did (dns ТЗ §3.3).
type index struct {
	sets     []DomainSet
	byDomain map[string][]int
}

func newIndex(sets []DomainSet) *index {
	x := &index{sets: sets, byDomain: map[string][]int{}}
	for i, s := range sets {
		for _, d := range s.Domains {
			d = normalize(d)
			if !slices.Contains(x.byDomain[d], i) {
				x.byDomain[d] = append(x.byDomain[d], i)
			}
		}
	}
	return x
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// match adds to hit the sets whose lists cover name.
func (x *index) match(name string, hit map[int]bool) {
	name = normalize(name)
	for name != "" {
		for _, i := range x.byDomain[name] {
			hit[i] = true
		}
		_, rest, ok := strings.Cut(name, ".")
		if !ok {
			return
		}
		name = rest
	}
}

// hits returns the lists an answer belongs to. The names of an answer are the
// question's, the owners of its answer records and the targets of its CNAMEs.
// Only a successful answer belongs anywhere.
func (x *index) hits(m *dns.Msg) map[int]bool {
	hit := map[int]bool{}
	if m.Rcode != dns.RcodeSuccess || len(x.sets) == 0 {
		return hit
	}
	for _, q := range m.Question {
		x.match(q.Name, hit)
	}
	for _, rr := range m.Answer {
		x.match(rr.Header().Name, hit)
		if c, ok := rr.(*dns.CNAME); ok {
			x.match(c.Target, hit)
		}
	}
	return hit
}

// stripIPv6 removes the IPv6 addresses — AAAA records and the IPv6 hints of
// HTTPS and SVCB records — from an answer belonging to a list whose IPv6 is
// blocked while its IPv4 leaves through an exit: the client then connects
// over IPv4 and reaches the site, where IPv6 would find it unreachable. An
// AAAA question is left with no answer, which clients take as "no IPv6".
func (x *index) stripIPv6(m *dns.Msg, hit map[int]bool) {
	strip := false
	for i := range hit {
		strip = strip || x.sets[i].NoAAAA
	}
	if !strip {
		return
	}
	m.Answer = slices.DeleteFunc(m.Answer, func(rr dns.RR) bool {
		switch r := rr.(type) {
		case *dns.AAAA:
			return true
		case *dns.RRSIG:
			return r.TypeCovered == dns.TypeAAAA
		case *dns.HTTPS:
			r.Value = withoutIPv6Hint(r.Value)
		case *dns.SVCB:
			r.Value = withoutIPv6Hint(r.Value)
		}
		return false
	})
	m.Extra = slices.DeleteFunc(m.Extra, func(rr dns.RR) bool { _, ok := rr.(*dns.AAAA); return ok })
}

func withoutIPv6Hint(kv []dns.SVCBKeyValue) []dns.SVCBKeyValue {
	return slices.DeleteFunc(kv, func(p dns.SVCBKeyValue) bool { _, ok := p.(*dns.SVCBIPv6Hint); return ok })
}

// additions returns what an answer puts into the sets: every address it
// carries — A, AAAA and the address hints of HTTPS and SVCB records — goes
// into the sets of every list it belongs to.
func (x *index) additions(m *dns.Msg, hit map[int]bool) []Addition {
	if len(hit) == 0 {
		return nil
	}
	var v4, v6 []netip.Addr
	for _, rr := range m.Answer {
		switch r := rr.(type) {
		case *dns.A:
			v4 = appendAddr(v4, r.A)
		case *dns.AAAA:
			v6 = appendAddr(v6, r.AAAA)
		case *dns.HTTPS:
			v4, v6 = appendHints(v4, v6, r.Value)
		case *dns.SVCB:
			v4, v6 = appendHints(v4, v6, r.Value)
		}
	}
	if len(v4)+len(v6) == 0 {
		return nil
	}
	var out []Addition
	for i := range x.sets {
		if !hit[i] {
			continue
		}
		if len(v4) > 0 {
			out = append(out, Addition{Set: x.sets[i].Set4, Addrs: v4})
		}
		if len(v6) > 0 {
			out = append(out, Addition{Set: x.sets[i].Set6, Addrs: v6})
		}
	}
	return out
}

func appendHints(v4, v6 []netip.Addr, kv []dns.SVCBKeyValue) ([]netip.Addr, []netip.Addr) {
	for _, p := range kv {
		switch h := p.(type) {
		case *dns.SVCBIPv4Hint:
			for _, ip := range h.Hint {
				v4 = appendAddr(v4, ip)
			}
		case *dns.SVCBIPv6Hint:
			for _, ip := range h.Hint {
				v6 = appendAddr(v6, ip)
			}
		}
	}
	return v4, v6
}

// appendAddr adds an address in its own family's form, once.
func appendAddr(addrs []netip.Addr, ip []byte) []netip.Addr {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return addrs
	}
	a = a.Unmap()
	if slices.Contains(addrs, a) {
		return addrs
	}
	return append(addrs, a)
}
