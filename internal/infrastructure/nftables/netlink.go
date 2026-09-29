package nftables

import (
	"context"
	"fmt"

	gnft "github.com/google/nftables"
)

// The agent asks the kernel about its table every pass. The nft tool answers
// even `list tables` by first loading the whole ruleset — tens of thousands of
// set elements, some 30 MB and 0.15 s a call — so these two small questions go
// over netlink, which returns only the objects asked for.

// Present reports whether the agent's table exists.
func (f *Firewall) Present(context.Context) (bool, error) {
	conn, err := gnft.New()
	if err != nil {
		return false, fmt.Errorf("nftables netlink: %w", err)
	}
	tables, err := conn.ListTablesOfFamily(gnft.TableFamilyINet)
	if err != nil {
		return false, fmt.Errorf("list tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == TableName {
			return true, nil
		}
	}
	return false, nil
}

// Counters returns the packet counts of the agent's named counters. Only first
// packets of connections reach them, so a count is a number of connections.
//
// A kernel whose rules cannot reference named counters counts nothing: the
// counters exist and stay zero, so none is reported rather than false zeros.
func (f *Firewall) Counters(ctx context.Context) (map[string]uint64, error) {
	if !f.kernelFeatures(ctx).NamedCounters {
		return map[string]uint64{}, nil
	}
	conn, err := gnft.New()
	if err != nil {
		return nil, fmt.Errorf("nftables netlink: %w", err)
	}
	objs, err := conn.GetObjects(&gnft.Table{Name: TableName, Family: gnft.TableFamilyINet})
	if err != nil {
		return nil, fmt.Errorf("list counters: %w", err)
	}
	counters := map[string]uint64{}
	for _, o := range objs {
		if c, ok := o.(*gnft.CounterObj); ok {
			counters[c.Name] = c.Packets
		}
	}
	return counters, nil
}
