package nftables

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lib4u/vnm/internal/testsupport"
)

// A kernel without nft_objref (some hosting images) rejects every rule that references a
// named counter; without the feature no rule references one, and the table
// still loads.
func TestRenderWithoutNamedCounters(t *testing.T) {
	state := testsupport.MustPlan(t, testsupport.PlanInput())
	out := render(state, Features{})
	if strings.Contains(out, "counter name") {
		t.Fatalf("a rule references a named counter:\n%s", out)
	}
	if !strings.Contains(render(state, AllFeatures), "counter name") {
		t.Fatal("a stock kernel lost its counters")
	}

	testsupport.RequireNetns(t)
	path := filepath.Join(t.TempDir(), "vnm.nft")
	if err := os.WriteFile(path, []byte(replaceScript(state, inventory{}, Features{})), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := testsupport.InNetns(t, "nft -f "+path); err != nil {
		t.Fatalf("nft rejected the table without counters: %v\n%s", err, out)
	}
}
