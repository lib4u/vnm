package nftables

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/usecase/inspect"
)

var _ inspect.Kernel = (*Firewall)(nil)

// Live reads the agent's table from the kernel: which of its list sets hold
// addr, and the health sets.
func (f *Firewall) Live(ctx context.Context, addr netip.Addr) (inspect.Live, error) {
	dump, ok, err := f.readTable(ctx)
	if err != nil || !ok {
		return inspect.Live{}, err
	}

	live := inspect.Live{Present: true, Holding: map[string]bool{}}
	for _, item := range dump.Nftables {
		set := item.Set
		if set == nil {
			continue
		}
		switch planned, isList := strings.CutPrefix(set.Name, listPrefix); {
		case isList:
			held, err := holds(set.Elem, addr)
			if err != nil {
				return inspect.Live{}, fmt.Errorf("set %s: %w", set.Name, err)
			}
			live.Holding[planned] = held
		case set.Name == setDeadExits:
			marks, err := numbers(set.Elem)
			if err != nil {
				return inspect.Live{}, fmt.Errorf("set %s: %w", set.Name, err)
			}
			live.Health.DeadSlots = slotsOf(marks)
		case set.Name == setDNSPorts:
			ports, err := numbers(set.Elem)
			if err != nil {
				return inspect.Live{}, fmt.Errorf("set %s: %w", set.Name, err)
			}
			for _, p := range ports {
				live.Health.ResolverUp = live.Health.ResolverUp || p == dnsPort
			}
		}
	}
	return live, nil
}

// holds reports whether any element of an address set covers addr. nft writes
// an element as a bare address, a prefix or a range.
func holds(elems []json.RawMessage, addr netip.Addr) (bool, error) {
	for _, raw := range elems {
		lo, hi, err := addrRange(raw)
		if err != nil {
			return false, err
		}
		if lo.Compare(addr) <= 0 && addr.Compare(hi) <= 0 {
			return true, nil
		}
	}
	return false, nil
}

func addrRange(raw json.RawMessage) (lo, hi netip.Addr, err error) {
	var elem struct {
		Prefix *struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
		Range []string `json:"range"`
	}
	if v, err := elementValue(raw); err == nil {
		a, err := netip.ParseAddr(v)
		return a, a, err
	}
	if err := json.Unmarshal(raw, &elem); err != nil {
		return lo, hi, fmt.Errorf("element %s: %w", raw, err)
	}
	switch {
	case elem.Prefix != nil:
		a, err := netip.ParseAddr(elem.Prefix.Addr)
		if err != nil {
			return lo, hi, err
		}
		p := netip.PrefixFrom(a, elem.Prefix.Len).Masked()
		return p.Addr(), lastAddr(p), nil
	case len(elem.Range) == 2:
		if lo, err = netip.ParseAddr(elem.Range[0]); err != nil {
			return lo, hi, err
		}
		hi, err = netip.ParseAddr(elem.Range[1])
		return lo, hi, err
	}
	return lo, hi, fmt.Errorf("element %s is not an address, prefix or range", raw)
}

// lastAddr is the highest address of a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// numbers reads the elements of a set of integers — marks or ports.
func numbers(elems []json.RawMessage) ([]uint64, error) {
	out := make([]uint64, 0, len(elems))
	for _, raw := range elems {
		var n uint64
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, fmt.Errorf("element %s is not a number: %w", raw, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// slotsOf maps exit marks back to their slots.
func slotsOf(marks []uint64) []int {
	var slots []int
	for slot := range netstate.MaxSlots {
		for _, m := range marks {
			if m == uint64(netstate.ExitMark(slot)) {
				slots = append(slots, slot)
			}
		}
	}
	return slots
}
