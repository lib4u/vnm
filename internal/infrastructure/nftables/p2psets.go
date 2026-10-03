package nftables

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	gnft "github.com/google/nftables"
)

// P2PSets adds the p2p part's runtime elements over netlink (p2p ТЗ §3.3–3.4):
// peers of detected BitTorrent flows and banned tunnel clients, each with a
// timeout, so the kernel forgets them on its own.
type P2PSets struct {
	mu sync.Mutex
}

// AddPeer refuses every packet to addr for ttl.
func (p *P2PSets) AddPeer(_ context.Context, addr netip.Addr, ttl time.Duration) error {
	set := setP2PPeers4
	if addr.Is6() {
		set = setP2PPeers6
	}
	return p.add(set, addr, ttl)
}

// Ban refuses a tunnel client's traffic for ttl.
func (p *P2PSets) Ban(_ context.Context, addr netip.Addr, ttl time.Duration) error {
	set := setP2PBan4
	if addr.Is6() {
		set = setP2PBan6
	}
	return p.add(set, addr, ttl)
}

// add adds one element. Adding an address already in the set is no error; its
// timeout is not renewed, which is why the watcher re-adds a peer only after
// its refusal ran out.
func (p *P2PSets) add(set string, addr netip.Addr, ttl time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	conn, err := gnft.New()
	if err != nil {
		return fmt.Errorf("nftables netlink: %w", err)
	}
	table := &gnft.Table{Name: TableName, Family: gnft.TableFamilyINet}
	elem := gnft.SetElement{Key: addr.Unmap().AsSlice(), Timeout: ttl}
	if err := conn.SetAddElements(&gnft.Set{Table: table, Name: set, HasTimeout: true}, []gnft.SetElement{elem}); err != nil {
		return fmt.Errorf("set %s: %w", set, err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("add %s to %s: %w", addr, set, err)
	}
	return nil
}
