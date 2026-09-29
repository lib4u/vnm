package statusfile_test

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/statusfile"
	"github.com/lib4u/vnm/internal/usecase/agent"
	"github.com/lib4u/vnm/internal/usecase/exits"
)

func TestRoundTrip(t *testing.T) {
	want := agent.Snapshot{
		ConfigValid: true,
		Mode:        policy.ModeEnforce,
		Exits:       []exits.Status{{Name: "warp", Slot: 0, Present: true, Healthy: true}},
		Lists: map[string]agent.ListStatus{
			"ru_ip":    {Entries: 25113, Age: 50 * time.Hour, Refresh: 24 * time.Hour},
			"scanners": {Missing: true, Failed: true, Refresh: 12 * time.Hour},
		},
		Guard:         agent.GuardSnapshot{Mode: policy.ModeObserve, Refused: map[string]uint64{"scanners": 3}},
		Resolver:      agent.ResolverSnapshot{Enabled: true, Up: true},
		Counters:      map[string]uint64{"r0_ru_ip_4": 12},
		ApplyErrors:   1,
		Drift:         2,
		LastReconcile: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC),
	}
	f := statusfile.New(filepath.Join(t.TempDir(), "status.json"))
	if err := f.Publish(want); err != nil {
		t.Fatal(err)
	}
	got, err := f.Read()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, want)
	}
}

func TestReadMissing(t *testing.T) {
	if _, err := statusfile.New(filepath.Join(t.TempDir(), "status.json")).Read(); err == nil {
		t.Fatal("a missing file read as a snapshot")
	}
}
