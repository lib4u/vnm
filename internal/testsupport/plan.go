package testsupport

import (
	"net/netip"
	"testing"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/usecase/planner"
)

// ResolverUID is the fixture resolver's user.
const ResolverUID = 997

// PlanInput is a complete planner input over the fixture policy: every list
// resolved, the exit and the resolver up. Tests change only what they test.
func PlanInput() planner.Input {
	return planner.Input{
		Policy:   Policy(),
		Ranges:   map[string][]netip.Prefix{"ru_ip": RURanges, "scanners": ScannerRanges},
		Domains:  map[string][]string{"ru_suffix": RUSuffixes},
		Exits:    map[string]planner.ExitStatus{"warp": {Present: true, Healthy: true}},
		Resolver: planner.ResolverStatus{UID: ResolverUID, Up: true},
	}
}

// MustPlan plans in, failing the test on error.
func MustPlan(t testing.TB, in planner.Input) netstate.State {
	t.Helper()
	s, err := planner.Plan(in)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return s
}
