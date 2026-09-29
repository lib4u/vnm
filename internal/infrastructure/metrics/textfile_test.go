package metrics_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/metrics"
	"github.com/lib4u/vnm/internal/usecase/agent"
	"github.com/lib4u/vnm/internal/usecase/exits"
)

func snapshot() agent.Snapshot {
	return agent.Snapshot{
		ConfigValid: true,
		Mode:        policy.ModeObserve,
		Exits:       []exits.Status{{Name: "warp", Present: true, Healthy: false, Alert: true}},
		Lists: map[string]agent.ListStatus{
			"ru_ip":    {Entries: 25113, Age: 50 * time.Hour, Refresh: 24 * time.Hour},
			"scanners": {Entries: 164, Failed: true},
		},
		Guard:         agent.GuardSnapshot{Mode: policy.ModeObserve, Refused: map[string]uint64{"scanners": 9}},
		Resolver:      agent.ResolverSnapshot{Enabled: true},
		Counters:      map[string]uint64{"r0_ru_ip_4": 12, "listen_bypass": 3},
		LastReconcile: time.Unix(1790000000, 0),
	}
}

func TestRender(t *testing.T) {
	out := metrics.Render(snapshot())
	for _, want := range []string{
		"vnm_config_valid 1\n",
		`vnm_mode{mode="observe"} 1` + "\n",
		`vnm_mode{mode="enforce"} 0` + "\n",
		`vnm_exit_healthy{exit="warp"} 0` + "\n",
		`vnm_exit_alert{exit="warp"} 1` + "\n",
		`vnm_list_entries{list="ru_ip"} 25113` + "\n",
		`vnm_list_age_seconds{list="ru_ip"} 180000` + "\n",
		`vnm_list_refresh_seconds{list="ru_ip"} 86400` + "\n",
		`vnm_list_failed{list="scanners"} 1` + "\n",
		`vnm_guard_mode{mode="observe"} 1` + "\n",
		`vnm_guard_refused_total{list="scanners"} 9` + "\n",
		"vnm_resolver_up 0\n",
		`vnm_connections_total{counter="r0_ru_ip_4"} 12` + "\n",
		"vnm_last_reconcile_timestamp_seconds 1790000000\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Counters are sorted, so equal snapshots render identically.
	if strings.Index(out, "listen_bypass") > strings.Index(out, "r0_ru_ip_4") {
		t.Error("counters not sorted")
	}
}

// Lists that never arrived must trip the stale-lists alert, not look fresh.
func TestMissingListsRenderInfinitelyOld(t *testing.T) {
	s := snapshot()
	s.Lists["ru_ip"] = agent.ListStatus{Missing: true, Refresh: 24 * time.Hour}
	if out := metrics.Render(s); !strings.Contains(out, `vnm_list_age_seconds{list="ru_ip"} +Inf`+"\n") {
		t.Fatalf("missing lists rendered as:\n%s", out)
	}
}

func TestPublishReplacesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vnm.prom")
	tf := metrics.NewTextfile(path)
	for range 2 {
		if err := tf.Publish(snapshot()); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.HasPrefix(string(data), "# HELP vnm_config_valid") {
		t.Fatalf("file = %q, %v", data, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary files left: %v", entries)
	}
}
