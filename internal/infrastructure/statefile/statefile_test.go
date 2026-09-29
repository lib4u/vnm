package statefile_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lib4u/vnm/internal/infrastructure/statefile"
	"github.com/lib4u/vnm/internal/testsupport"
	"github.com/lib4u/vnm/internal/usecase/planner"
)

func TestRoundTrip(t *testing.T) {
	in := testsupport.PlanInput()
	in.Exits = map[string]planner.ExitStatus{"warp": {Present: true}}
	want := testsupport.MustPlan(t, in)
	store := statefile.New(filepath.Join(t.TempDir(), "state"))

	if _, ok, err := store.LastGood(); ok || err != nil {
		t.Fatalf("empty store: ok=%t err=%v", ok, err)
	}
	if err := store.SaveLastGood(want); err != nil {
		t.Fatalf("SaveLastGood: %v", err)
	}
	got, ok, err := store.LastGood()
	if err != nil || !ok {
		t.Fatalf("LastGood: ok=%t err=%v", ok, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip changed the state:\n got %+v\nwant %+v", got, want)
	}
}

// A corrupt file must not read as "no state": the boot unit would then bring
// the node up with no policy at all.
func TestCorruptFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "last-good.json"), []byte("{truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := statefile.New(dir).LastGood(); err == nil || ok {
		t.Fatalf("corrupt file: ok=%t err=%v", ok, err)
	}
}
