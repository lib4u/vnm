package kernel

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// A replacement keeps the named counters: monitoring reads them as monotonic,
// and a reset on every policy change would show as a counter restart.
func TestCountersSurviveReplace(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.applier.Apply(ctx, desired(t)); err != nil {
		t.Fatal(err)
	}
	// A datagram to an RU address is classified by the output chain; it needs
	// a route to be sent at all.
	r.sh(t, "ip link add cnt0 type dummy 2>/dev/null; ip link set cnt0 up; ip route replace 198.51.100.0/24 dev cnt0")
	r.sh(t, "echo x > /dev/udp/198.51.100.10/53 || true")
	before := r.counter(t, "r0_ru_ip_4")
	if before == 0 {
		t.Fatal("the decision was not counted")
	}

	next := desired(t)
	next.Classify.Observe = true // any change that replaces the table
	if err := r.applier.Apply(ctx, next); err != nil {
		t.Fatal(err)
	}
	if after := r.counter(t, "r0_ru_ip_4"); after < before {
		t.Fatalf("counter reset by the replace: %d → %d", before, after)
	}
}

// Applying the same state again must not duplicate a single rule, and a chain
// the new state drops must go.
func TestReplaceIsExact(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	state := desired(t)
	var tables []string
	for range 2 {
		if err := r.applier.Apply(ctx, state); err != nil {
			t.Fatal(err)
		}
		// Kept sets list before recreated ones; only the content counts.
		lines := strings.Split(r.sh(t, "nft list table inet vnm"), "\n")
		slices.Sort(lines)
		tables = append(tables, strings.Join(lines, "\n"))
	}
	if tables[0] != tables[1] {
		t.Fatalf("a second apply of the same state changed the table:\n%s\n---\n%s", tables[0], tables[1])
	}

	state.Guard.Rules = nil
	if err := r.applier.Apply(ctx, state); err != nil {
		t.Fatal(err)
	}
	if table := r.sh(t, "nft list table inet vnm"); strings.Contains(table, "chain guard") || strings.Contains(table, "g_scanners") {
		t.Fatalf("the dropped guard stayed:\n%s", table)
	}
}

func (r rig) counter(t *testing.T, name string) uint64 {
	t.Helper()
	counters, err := r.fw.Counters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return counters[name]
}
