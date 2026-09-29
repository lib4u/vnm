package agent_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/usecase/lists"
)

// A remote source with no local copy at all is missing, not fresh.
func TestSnapshotMissingLists(t *testing.T) {
	r := newRig()
	r.ref.missing = true
	r.pass()
	if st := r.metrics.last.Lists["ru_ip"]; !st.Missing || st.Age != 0 {
		t.Fatalf("ru_ip = %+v", st)
	}
}

// A guard list that fails to resolve guards nothing, and the egress goes in
// regardless (G-4); for the same policy its previous ranges stay.
func TestGuardListFailsOpenAlone(t *testing.T) {
	r := newRig()
	r.lists.guardErr = errors.New("html instead of a list")
	r.pass()
	if len(r.kernel.applies) != 1 {
		t.Fatalf("egress waited for a guard list: %d applies", len(r.kernel.applies))
	}
	for _, set := range r.kernel.applies[0].Classify.Sets {
		if set.Name == "scanners_4" && len(set.Prefixes) != 0 {
			t.Fatalf("failed guard list has ranges: %+v", set)
		}
	}
	if !r.metrics.last.Lists["scanners"].Failed {
		t.Fatal("the failure is not reported")
	}

	// Resolves, then its next copy breaks: the ranges in force stay.
	r.lists.guardErr = nil
	r.ref.updated = r.ref.updated.Add(time.Hour)
	r.pass()
	r.lists.guardErr = errors.New("cut off")
	r.ref.updated = r.ref.updated.Add(time.Hour)
	r.pass()
	last := r.kernel.applies[len(r.kernel.applies)-1]
	for _, set := range last.Classify.Sets {
		if set.Name == "scanners_4" && len(set.Prefixes) == 0 {
			t.Fatal("a broken copy emptied a guard list that was in force")
		}
	}

	// Switching the guard to observe rewrites the file, not the list: its
	// ranges in force still stay.
	r.cfg.cfg.Guard.Mode, r.cfg.version = policy.ModeObserve, "v2"
	r.pass()
	last = r.kernel.applies[len(r.kernel.applies)-1]
	if !last.Guard.Observe {
		t.Fatal("the mode switch was not applied")
	}
	for _, set := range last.Classify.Sets {
		if set.Name == "scanners_4" && len(set.Prefixes) == 0 {
			t.Fatal("a file edit elsewhere emptied a failed guard list")
		}
	}
}

// The egress off leaves the guard: it resolves and applies its lists alone.
func TestEgressOffKeepsGuard(t *testing.T) {
	r := newRig()
	r.cfg.cfg.Mode = policy.ModeOff
	r.pass()
	if len(r.kernel.applies) != 1 || !r.kernel.applies[0].Guard.Active() || r.kernel.applies[0].Classify.Classifies() {
		t.Fatalf("applies = %+v", r.kernel.applies)
	}
}

// A policy that starts reading a new source downloads it at once, not after a
// day — until then the new policy cannot be applied.
// Copies refreshed by anyone — the agent's own download or `vnm lists update`
// — are re-resolved on the next pass, and only once.
func TestUpdatedCopiesAreReresolved(t *testing.T) {
	r := newRig()
	r.pass()
	r.ref.updated = r.ref.updated.Add(time.Hour)
	r.pass()
	r.pass()
	if r.lists.calls != 2 {
		t.Fatalf("resolves = %d, want 2: once at start, once for the new copies", r.lists.calls)
	}
}

// Without lists nothing is applied, and every pass tries again: the node has
// no policy until the lists arrive.
func TestNoListsYetRetriesEveryPass(t *testing.T) {
	r := newRig()
	r.lists.err = errors.New("not downloaded yet")
	r.pass()
	if len(r.kernel.applies) != 0 {
		t.Fatalf("applied without lists: %d", len(r.kernel.applies))
	}
	r.lists.err = nil
	r.pass()
	if len(r.kernel.applies) != 1 {
		t.Fatalf("lists arrived, applies = %d", len(r.kernel.applies))
	}
}

// Lifting the policy needs no lists: a node whose lists never arrived must
// still be switchable off.
func TestOffNeedsNoLists(t *testing.T) {
	r := newRig()
	r.lists.err = errors.New("never downloaded")
	r.cfg.cfg.Mode = policy.ModeOff
	r.cfg.cfg.Guard.Mode = policy.ModeOff
	r.pass()
	if len(r.kernel.applies) != 1 || !r.kernel.applies[0].Empty() {
		t.Fatalf("applies = %+v, want the empty state", r.kernel.applies)
	}
}

// A new policy is planned only with its own lists. When they cannot be
// resolved, the state applied for the previous policy stays — the old lists are
// never planned under the new rules — and its exits' health keeps updating.
func TestUnresolvedPolicyKeepsAppliedStateAndHealth(t *testing.T) {
	r := newRig()
	r.pass()
	r.lists.err = lists.ErrOutOfBounds
	r.cfg.cfg.Lists[0].IP[0].Value, r.cfg.version = "by", "v2"
	r.pass()
	if len(r.kernel.applies) != 1 {
		t.Fatalf("applies = %d: the new rules were planned over the old lists", len(r.kernel.applies))
	}

	r.exits.healthy = false
	r.pass()
	if len(r.kernel.health) != 1 || len(r.kernel.health[0].DeadSlots) != 1 {
		t.Fatalf("dead sets = %v: health must keep updating while the policy waits", r.kernel.health)
	}

	// The lists of the new policy arrive — other ranges, as geoip:by would
	// give — and the new policy goes in.
	r.lists.err, r.lists.ranges = nil, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	r.pass()
	if len(r.kernel.applies) != 2 {
		t.Fatalf("applies = %d after the lists arrived", len(r.kernel.applies))
	}
}

// A copy confirmed current is not re-read: re-parsing tens of megabytes of
// geo files for an unchanged copy would be for nothing.
func TestConfirmedCopiesAreNotReread(t *testing.T) {
	r := newRig()
	r.ref.modified = r.ref.updated
	r.pass()
	r.ref.updated = r.ref.updated.Add(24 * time.Hour)
	r.pass()
	if r.lists.calls != 1 {
		t.Fatalf("resolves = %d: a confirmation re-read the lists", r.lists.calls)
	}
	// Yet the lists are as old as their last confirmation.
	if age := r.metrics.last.Lists["ru_ip"].Age; age != r.now.Sub(r.ref.updated) {
		t.Fatalf("ru_ip age = %v after the confirmation", age)
	}
}
