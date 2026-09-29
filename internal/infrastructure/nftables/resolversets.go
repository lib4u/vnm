package nftables

import (
	"context"
	"fmt"
	"sync"

	gnft "github.com/google/nftables"

	"github.com/lib4u/vnm/internal/infrastructure/dnsd"
)

// ResolverSets adds the resolver's addresses to the agent's dynamic sets over
// netlink (dns ТЗ §3.3). The elements have no timeout, like the ones dnsmasq
// added: an entry expiring while a client still holds the answer would let
// its connection out directly.
type ResolverSets struct {
	mu sync.Mutex
}

// Add adds every addition in one transaction. An address already in its set is
// not an error.
func (r *ResolverSets) Add(_ context.Context, adds []dnsd.Addition) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	conn, err := gnft.New()
	if err != nil {
		return fmt.Errorf("nftables netlink: %w", err)
	}
	table := &gnft.Table{Name: TableName, Family: gnft.TableFamilyINet}
	for _, a := range adds {
		elems := make([]gnft.SetElement, 0, len(a.Addrs))
		for _, addr := range a.Addrs {
			elems = append(elems, gnft.SetElement{Key: addr.AsSlice()})
		}
		if err := conn.SetAddElements(&gnft.Set{Table: table, Name: a.Set}, elems); err != nil {
			return fmt.Errorf("set %s: %w", a.Set, err)
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("add to sets: %w", err)
	}
	return nil
}
