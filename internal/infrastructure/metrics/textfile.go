// Package metrics publishes the agent's state as a Prometheus textfile for
// node_exporter's textfile collector (ТЗ §7.5). Labels only take values from
// small fixed sets — exit, list and counter names — never addresses.
package metrics

import (
	"fmt"
	"slices"
	"strings"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/atomicfile"
	"github.com/lib4u/vnm/internal/usecase/agent"
)

// Textfile writes metrics to a file, replacing it atomically: the collector
// must never read half a file.
type Textfile struct {
	path string
}

var _ agent.Metrics = (*Textfile)(nil)

// NewTextfile returns a Textfile writing to path.
func NewTextfile(path string) *Textfile {
	return &Textfile{path: path}
}

// Publish writes the snapshot.
func (t *Textfile) Publish(s agent.Snapshot) error {
	return atomicfile.WriteFile(t.path, []byte(Render(s)), 0o644)
}

// Render returns the snapshot in the Prometheus text format, sorted so that
// equal snapshots render identically.
func Render(s agent.Snapshot) string {
	var b strings.Builder
	metric := func(name, help, typ string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}

	metric("vnm_config_valid", "1 when the policy file is valid; 0 means the last valid one is in force.", "gauge")
	fmt.Fprintf(&b, "vnm_config_valid %d\n", boolValue(s.ConfigValid))
	metric("vnm_policy_applied", "1 when the kernel holds the policy in the file; 0 while it cannot be planned or applied.", "gauge")
	fmt.Fprintf(&b, "vnm_policy_applied %d\n", boolValue(s.PolicyApplied))
	metric("vnm_lists_current", "0 while the lists in force are older than the local copies, which did not resolve.", "gauge")
	fmt.Fprintf(&b, "vnm_lists_current %d\n", boolValue(s.ListsCurrent))

	metric("vnm_mode", "Policy mode; in observe the decision counters count what enforce would do.", "gauge")
	for _, mode := range policy.Modes {
		fmt.Fprintf(&b, "vnm_mode{mode=%q} %d\n", mode, boolValue(s.Mode == mode))
	}

	metric("vnm_exit_healthy", "1 when the exit passes its health check.", "gauge")
	for _, e := range s.Exits {
		fmt.Fprintf(&b, "vnm_exit_healthy{exit=%q} %d\n", e.Name, boolValue(e.Healthy))
	}
	metric("vnm_exit_present", "1 when the exit's interface exists.", "gauge")
	for _, e := range s.Exits {
		fmt.Fprintf(&b, "vnm_exit_present{exit=%q} %d\n", e.Name, boolValue(e.Present))
	}
	metric("vnm_exit_alert", "1 when the exit has been dead longer than 15 minutes.", "gauge")
	for _, e := range s.Exits {
		fmt.Fprintf(&b, "vnm_exit_alert{exit=%q} %d\n", e.Name, boolValue(e.Alert))
	}

	names := sortedKeys(s.Lists)
	metric("vnm_list_entries", "Address ranges of each list in the applied state.", "gauge")
	for _, name := range names {
		fmt.Fprintf(&b, "vnm_list_entries{list=%q} %d\n", name, s.Lists[name].Entries)
	}
	metric("vnm_list_age_seconds", "Age of the oldest local copy of a list's remote sources.", "gauge")
	for _, name := range names {
		switch st := s.Lists[name]; {
		case st.Missing:
			// Never downloaded is older than any threshold: the stale-lists
			// alert must fire, not read a zero age as fresh.
			fmt.Fprintf(&b, "vnm_list_age_seconds{list=%q} +Inf\n", name)
		case st.Refresh > 0:
			fmt.Fprintf(&b, "vnm_list_age_seconds{list=%q} %.0f\n", name, st.Age.Seconds())
		}
	}
	metric("vnm_list_refresh_seconds", "How old a list's remote copies may get before they are downloaded again.", "gauge")
	for _, name := range names {
		if st := s.Lists[name]; st.Refresh > 0 {
			fmt.Fprintf(&b, "vnm_list_refresh_seconds{list=%q} %.0f\n", name, st.Refresh.Seconds())
		}
	}
	metric("vnm_list_failed", "1 when a list's last resolution failed; a guard list then keeps its previous ranges or guards nothing.", "gauge")
	for _, name := range names {
		fmt.Fprintf(&b, "vnm_list_failed{list=%q} %d\n", name, boolValue(s.Lists[name].Failed))
	}

	metric("vnm_guard_mode", "Guard mode; in observe the refused counts are what enforce would refuse.", "gauge")
	for _, mode := range policy.Modes {
		fmt.Fprintf(&b, "vnm_guard_mode{mode=%q} %d\n", mode, boolValue(s.Guard.Mode == mode))
	}
	metric("vnm_guard_refused_total", "Packets of new inbound connections the guard refused, per list — a retransmitted SYN counts again; in observe, would have refused.", "counter")
	for _, name := range sortedKeys(s.Guard.Refused) {
		fmt.Fprintf(&b, "vnm_guard_refused_total{list=%q} %d\n", name, s.Guard.Refused[name])
	}

	metric("vnm_p2p_mode", "P2P part mode; in observe the refused counts are what enforce would refuse.", "gauge")
	for _, mode := range policy.Modes {
		fmt.Fprintf(&b, "vnm_p2p_mode{mode=%q} %d\n", mode, boolValue(s.P2P.Mode == mode))
	}
	metric("vnm_p2p_refused_total", "Packets matching a BitTorrent signature the kernel refused, per signature; in observe, would have refused.", "counter")
	for _, name := range sortedKeys(s.P2P.Refused) {
		fmt.Fprintf(&b, "vnm_p2p_refused_total{signature=%q} %d\n", name, s.P2P.Refused[name])
	}
	if s.P2P.NDPI {
		metric("vnm_p2p_ndpi_up", "1 while nDPId writes its verdicts to the agent.", "gauge")
		fmt.Fprintf(&b, "vnm_p2p_ndpi_up %d\n", boolValue(s.P2P.Connected))
		metric("vnm_p2p_detections_total", "BitTorrent flows nDPI found by packet inspection.", "counter")
		fmt.Fprintf(&b, "vnm_p2p_detections_total %d\n", s.P2P.Detections)
		metric("vnm_p2p_peers_total", "Peers refused for a while; in observe, that would have been.", "counter")
		fmt.Fprintf(&b, "vnm_p2p_peers_total %d\n", s.P2P.Peers)
		metric("vnm_p2p_bans_total", "Tunnel clients banned for a swarm of peers; in observe, that would have been.", "counter")
		fmt.Fprintf(&b, "vnm_p2p_bans_total %d\n", s.P2P.Bans)
	}

	if s.Resolver.Enabled {
		metric("vnm_resolver_up", "1 while the resolver answers and DNS is redirected to it.", "gauge")
		fmt.Fprintf(&b, "vnm_resolver_up %d\n", boolValue(s.Resolver.Up))
	}

	metric("vnm_connections_total", "Connections matched by each classification counter.", "counter")
	for _, name := range sortedKeys(s.Counters) {
		fmt.Fprintf(&b, "vnm_connections_total{counter=%q} %d\n", name, s.Counters[name])
	}

	metric("vnm_apply_errors_total", "Failed attempts to apply a state since the agent started.", "counter")
	fmt.Fprintf(&b, "vnm_apply_errors_total %d\n", s.ApplyErrors)
	metric("vnm_drift_total", "Times the kernel was found to differ from the applied state.", "counter")
	fmt.Fprintf(&b, "vnm_drift_total %d\n", s.Drift)
	metric("vnm_last_reconcile_timestamp_seconds", "When the last reconcile pass ran.", "gauge")
	fmt.Fprintf(&b, "vnm_last_reconcile_timestamp_seconds %d\n", s.LastReconcile.Unix())
	return b.String()
}

func boolValue(v bool) int {
	if v {
		return 1
	}
	return 0
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
