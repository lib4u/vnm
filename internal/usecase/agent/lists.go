package agent

import (
	"context"
	"fmt"
	"maps"
	"reflect"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/usecase/lists"
	"github.com/lib4u/vnm/internal/usecase/planner"
)

// checkLists reads the local copies — downloaded and `file:` sources alike —
// and marks the lists stale when the content of any of them changed. A copy
// merely confirmed current changes nothing: re-reading tens of megabytes of
// geo files for it would be for nothing.
func (a *Agent) checkLists() {
	copies := a.d.Refresher.Copies(a.cfg)
	same := maps.EqualFunc(copies, a.copies, func(x, y lists.Copy) bool {
		return x.Missing == y.Missing && x.Modified.Equal(y.Modified)
	})
	// The copies are kept either way: their verification times are the lists'
	// ages.
	a.copies = copies
	if !same {
		a.stale = true
	}
}

// resolveLists makes sure the lists of the current policy are resolved.
//
//   - A policy whose parts are all off needs none.
//   - A policy whose lists were never resolved is retried every pass: it is a
//     local read, and the copies may have just arrived. Until it succeeds the
//     policy cannot be planned — the lists of an older policy are never
//     substituted, that would be a policy nobody wrote.
//   - Changed copies for the same policy are tried once; on failure the lists
//     in use stay, since the same data would fail the same way every pass.
//   - A guard list that fails alone keeps its previous ranges while its own
//     definition is unchanged — whatever else changed in the file — or
//     guards nothing (G-4); the rest is applied either way.
func (a *Agent) resolveLists(ctx context.Context) error {
	if len(a.cfg.ListUses()) == 0 {
		return nil
	}
	current := a.rangesFor == a.version
	if current && !a.stale {
		return nil
	}
	a.stale = false

	var previous map[string]lists.Sizes
	if a.applied != nil {
		previous = familySizes(*a.applied)
	}
	resolved, err := a.d.Lists.Resolve(ctx, a.cfg, previous)
	var domains map[string][]string
	if err == nil {
		domains, err = a.d.Lists.Domains(ctx, a.cfg)
	}
	if err != nil {
		if !current {
			return fmt.Errorf("lists of the current policy are not resolved: %w", err)
		}
		a.listsCurrent = false
		a.d.Log.Warn("lists not updated, the previous ones stay", "error", err)
		return nil
	}

	failed := map[string]bool{}
	for name, ferr := range resolved.Failed {
		failed[name] = true
		def, _ := a.cfg.List(name)
		if kept, ok := a.ranges[name]; ok && reflect.DeepEqual(a.rangeDefs[name], def) {
			resolved.Ranges[name] = kept
			a.d.Log.Warn("guard list not updated, its previous ranges stay", "list", name, "error", ferr)
			continue
		}
		a.d.Log.Error("guard list not resolved, it guards nothing", "list", name, "error", ferr)
	}
	defs := make(map[string]policy.List, len(resolved.Ranges))
	for name := range resolved.Ranges {
		defs[name], _ = a.cfg.List(name)
	}
	a.ranges, a.domains, a.rangesFor, a.rangeDefs = resolved.Ranges, domains, a.version, defs
	a.failed, a.listsCurrent = failed, true
	return nil
}

// familySizes returns each list's ranges per family in an applied state — the
// reference the next resolved lists are checked against (ТЗ §7.4).
func familySizes(s netstate.State) map[string]lists.Sizes {
	out := map[string]lists.Sizes{}
	for _, set := range s.Classify.Sets {
		if set.Dynamic {
			continue
		}
		sizes := out[set.List]
		if set.Family == netstate.IPv6 {
			sizes.V6 += len(set.Prefixes)
		} else {
			sizes.V4 += len(set.Prefixes)
		}
		out[set.List] = sizes
	}
	return out
}

// listStatuses reports every list of the policy. The age of a list is the age
// of its oldest local copy, not of the last resolve: re-reading old copies
// after a failed download must not make stale lists look fresh, and a copy
// that never arrived is missing.
func (a *Agent) listStatuses() map[string]ListStatus {
	var sizes map[string]int
	if a.applied != nil {
		sizes = planner.ListSizes(*a.applied)
	}
	now := a.d.Now()
	out := map[string]ListStatus{}
	for _, l := range a.cfg.Lists {
		st := ListStatus{Entries: sizes[l.Name], Failed: a.failed[l.Name]}
		urls := a.cfg.ListRemoteURLs(l)
		if len(urls) > 0 {
			st.Refresh = l.RefreshOrDefault()
		}
		for _, u := range urls {
			switch c, ok := a.copies[u]; {
			case !ok || c.Missing || c.Err != nil:
				st.Missing = true
			default:
				st.Age = max(st.Age, now.Sub(c.Updated))
			}
		}
		out[l.Name] = st
	}
	return out
}
