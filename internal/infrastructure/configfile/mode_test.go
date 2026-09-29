package configfile_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/configfile"
)

func TestWithModeKeepsTheRestOfTheFile(t *testing.T) {
	data, err := os.ReadFile("../../../configs/vnm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	parts := []struct {
		key  []string
		line string // the only line allowed to change
		mode func(policy.Config) policy.Mode
	}{
		{[]string{"mode"}, "mode:", func(c policy.Config) policy.Mode { return c.Mode }},
		{[]string{"guard", "mode"}, "  mode:", func(c policy.Config) policy.Mode { return c.Guard.Mode }},
	}
	for _, part := range parts {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeOff, policy.ModeObserve} {
			out, err := configfile.WithMode(data, part.key, mode)
			if err != nil {
				t.Fatalf("%v %s: %v", part.key, mode, err)
			}
			if cfg, err := configfile.Parse(out); err != nil || part.mode(cfg) != mode {
				t.Fatalf("%v %s: parsed %v", part.key, mode, err)
			}
			// Everything but the mode line is byte-identical.
			want := strings.Split(string(data), "\n")
			got := strings.Split(string(out), "\n")
			if len(got) != len(want) {
				t.Fatalf("%v %s: %d lines, want %d", part.key, mode, len(got), len(want))
			}
			for i := range want {
				if got[i] != want[i] && !strings.HasPrefix(want[i], part.line) {
					t.Fatalf("%v %s: line %d changed: %q → %q", part.key, mode, i+1, want[i], got[i])
				}
			}
		}
	}
}

func TestWithModeMissingKey(t *testing.T) {
	data, err := os.ReadFile("../../../configs/vnm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	noGuardMode := bytes.Replace(data, []byte("\n  mode: off\n"), []byte("\n"), 1)
	if _, err := configfile.WithMode(noGuardMode, []string{"guard", "mode"}, policy.ModeObserve); err == nil || !strings.Contains(err.Error(), "no guard.mode key") {
		t.Fatalf("err = %v", err)
	}
}

func TestWithModeQuotedAndCommented(t *testing.T) {
	data, err := os.ReadFile("../../../configs/vnm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	quoted := bytes.Replace(data, []byte("\nmode: observe"), []byte("\nmode: \"observe\"   # first day"), 1)
	out, err := configfile.WithMode(quoted, []string{"mode"}, policy.ModeEnforce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("\nmode: enforce   # first day\n")) {
		t.Fatalf("mode line: %s", out[:200])
	}
}

// An anchor moves the value's bytes away from what the parser reports: the
// edit refuses instead of writing a broken token.
func TestWithModeRefusesAnchors(t *testing.T) {
	data, err := os.ReadFile("../../../configs/vnm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	anchored := bytes.Replace(data, []byte("\nmode: observe"), []byte("\nmode: &m observe"), 1)
	if _, err := configfile.WithMode(anchored, []string{"mode"}, policy.ModeEnforce); err == nil || !strings.Contains(err.Error(), "anchor") {
		t.Fatalf("err = %v", err)
	}
}
