package nftables

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/infrastructure/runner"
)

// tableDump is the shape of `nft -j list table` this package reads.
type tableDump struct {
	Nftables []struct {
		Set *struct {
			Name  string            `json:"name"`
			Type  json.RawMessage   `json:"type"`
			Flags []string          `json:"flags"`
			Elem  []json.RawMessage `json:"elem"`
		} `json:"set"`
		Chain *struct {
			Name string `json:"name"`
		} `json:"chain"`
		Counter *struct {
			Name string `json:"name"`
		} `json:"counter"`
	} `json:"nftables"`
}

// readTable returns the agent's table as the kernel holds it; ok is false when
// there is none.
func (f *Firewall) readTable(ctx context.Context) (dump tableDump, ok bool, err error) {
	present, err := f.Present(ctx)
	if err != nil || !present {
		return tableDump{}, false, err
	}
	out, err := f.run.Run(ctx, runner.Command{Name: "nft", Args: []string{"-j", "list", "table", TableFamily, TableName}})
	if err != nil {
		return tableDump{}, false, err
	}
	if err := json.Unmarshal([]byte(out), &dump); err != nil {
		return tableDump{}, false, fmt.Errorf("parse nft table: %w", err)
	}
	return dump, true, nil
}

// inventory is what the agent's table holds before a replacement: its objects
// by name, and the shape of each set.
type inventory struct {
	chains   []string
	counters []string
	sets     map[string]setShape
}

// setShape is what decides whether an existing set can be kept as it is.
type setShape struct {
	typ      string
	interval bool
	timeout  bool
}

func (f *Firewall) inventory(ctx context.Context) (inventory, error) {
	dump, ok, err := f.readTable(ctx)
	if err != nil || !ok {
		return inventory{}, err
	}
	inv := inventory{sets: map[string]setShape{}}
	for _, item := range dump.Nftables {
		switch {
		case item.Chain != nil:
			inv.chains = append(inv.chains, item.Chain.Name)
		case item.Counter != nil:
			inv.counters = append(inv.counters, item.Counter.Name)
		case item.Set != nil:
			var typ string
			if err := json.Unmarshal(item.Set.Type, &typ); err != nil {
				typ = string(item.Set.Type) // a concatenation: never one of ours to keep
			}
			inv.sets[item.Set.Name] = setShape{typ: typ, interval: slices.Contains(item.Set.Flags, "interval"), timeout: slices.Contains(item.Set.Flags, "timeout")}
		}
	}
	return inv, nil
}

// replaceScript returns one transaction that turns the table the inventory
// describes into the state.
//
// The table itself is never deleted. What the resolver put into a dynamic set
// the new state keeps must survive the replacement — an address missing even
// for an instant lets a connection to a listed domain out directly (I-1) —
// and so must the named counters, which monitoring reads as monotonic. Every
// chain is emptied and removed, which releases the sets; then every other set
// and every counter the state drops is removed, and the table is declared
// anew: declaring a set or a counter that already exists keeps it as it is.
func replaceScript(s netstate.State, inv inventory, f Features) string {
	w := &writer{}
	w.line(0, "table %s %s", TableFamily, TableName)
	for _, c := range inv.chains {
		w.line(0, "flush chain %s %s %s", TableFamily, TableName, c)
	}
	for _, c := range inv.chains {
		w.line(0, "delete chain %s %s %s", TableFamily, TableName, c)
	}
	keep := keptSets(s)
	for _, name := range sortedNames(inv.sets) {
		if want, ok := keep[name]; !ok || want != inv.sets[name] {
			w.line(0, "delete set %s %s %s", TableFamily, TableName, name)
		}
	}
	keepCounters := counters(s)
	for _, c := range inv.counters {
		if !slices.Contains(keepCounters, c) {
			w.line(0, "delete counter %s %s %s", TableFamily, TableName, c)
		}
	}
	return w.String() + render(s, f) + HealthScript(s.Health)
}

// keptSets are the sets a replacement keeps with their elements: the ones
// filled at runtime — the resolver's, and the p2p part's peers and bans. Every
// other set is rewritten from the state.
func keptSets(s netstate.State) map[string]setShape {
	keep := map[string]setShape{}
	for _, set := range s.Classify.Sets {
		if set.Dynamic {
			keep[SetName(set.Name)] = setShape{typ: addrType(set.Family)}
		}
	}
	if s.P2P.Active() {
		maps.Copy(keep, p2pSetShapes)
	}
	return keep
}

func sortedNames(m map[string]setShape) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// elementValue reads a set element: a plain address, or an object carrying it
// as "val" when the element has attributes.
func elementValue(raw json.RawMessage) (string, error) {
	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		return plain, nil
	}
	var wrapped struct {
		Elem struct {
			Val string `json:"val"`
		} `json:"elem"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil || wrapped.Elem.Val == "" {
		return "", fmt.Errorf("element %s is not an address", raw)
	}
	return wrapped.Elem.Val, nil
}
