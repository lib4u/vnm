package install

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/lib4u/vnm/internal/domain/netstate"
)

// A WARP set up by hand or by wtm (installer §2.1). Its objects are taken over
// or removed; anything else in the owned rule range stops the migration.
const (
	legacyUnit = "wg-quick@warp.service"
	// legacyFailClosed is a hand-made WARP setup's boot unit that put a blackhole rule
	// at 1001; left enabled, it would add it again beside the agent's.
	legacyFailClosed = "warp-failclosed.service"
	// legacyCron is wtm's watchdog: it goes first, or it restarts what is
	// being removed.
	legacyCron = "/etc/cron.d/wtm-warp-watchdog"
)

// legacyFiles are removed after a backup. Directories are only removed; their
// content is wtm's own code, not configuration.
var legacyFiles = []string{
	"/etc/wireguard/warp.conf",
	"/etc/wireguard/wgcf-account.toml",
	"/etc/wireguard/wgcf-profile.conf",
	"/etc/wireguard/warp-xray-outbound.json",
	"/etc/wireguard/warp-sockopt-outbound.json",
	"/etc/systemd/system/" + legacyFailClosed,
	"/usr/local/bin/wtm",
	"/opt/wtm",
}

// ErrUnknownRules means the owned rule range holds rules that are neither the
// agent's nor a known WARP's. The migration stops before changing anything:
// removing them could break whatever put them there.
var ErrUnknownRules = errors.New("unknown rules in the owned priority range")

// legacySlot is the exit slot whose mark hand-made WARP setups route by: the
// agent's slot 0 was given their 0xca6c so that Xray keeps working unchanged.
const legacySlot = 0

// MigrationPlan sorts the rules of the owned range.
type MigrationPlan struct {
	Ours, Legacy, Unknown []netstate.IPRule
}

// PlanMigration sorts rules into the agent's own (masked exit rules), a
// hand-made WARP's (the mark of legacySlot without a mask and nothing else to
// match on, any action), and the rest.
func PlanMigration(rules []netstate.IPRule) MigrationPlan {
	var own []netstate.IPRule
	for slot := range netstate.MaxSlots {
		r := netstate.ExitRules(slot)
		own = append(own, r[:]...)
	}
	var p MigrationPlan
	for _, r := range rules {
		switch {
		case slices.Contains(own, r):
			p.Ours = append(p.Ours, r)
		case r.Mark == netstate.ExitMark(legacySlot) && r.Mask == 0 && r.Extra == "":
			p.Legacy = append(p.Legacy, r)
		default:
			p.Unknown = append(p.Unknown, r)
		}
	}
	return p
}

// Migrate removes a hand-made or wtm WARP, keeping the node fail-closed at every
// step, and reports whether there was one:
//
//  1. inventory and backup, stop on unknown rules;
//  2. the agent's unreachable and lookup rules go in, then the old rules go —
//     from here a mark without a route is refused, not sent out directly;
//  3. the old WARP is removed: the watchdog first, then the interface, then
//     its files.
func (in *Installer) Migrate(ctx context.Context, stateDir string) (bool, error) {
	rules, err := in.rules.Rules(ctx)
	if err != nil {
		return false, err
	}
	plan := PlanMigration(rules)
	if len(plan.Unknown) > 0 {
		return false, fmt.Errorf("%w: %+v — decide what they are before installing", ErrUnknownRules, plan.Unknown)
	}
	present := in.legacyFiles()
	if len(plan.Legacy) == 0 && len(present) == 0 && !in.svc.Enabled(ctx, legacyUnit) && !in.svc.Enabled(ctx, legacyFailClosed) {
		return false, nil
	}

	backup := filepath.Join(stateDir, "migration", time.Now().UTC().Format("20060102-150405"))
	if err := in.backup(backup, present, plan.Legacy); err != nil {
		return false, fmt.Errorf("backup to %s: %w", backup, err)
	}

	if err := in.takeOverRules(ctx, plan); err != nil {
		return false, err
	}
	if err := in.files.Remove(legacyCron); err != nil {
		return false, err
	}
	for _, unit := range []string{legacyUnit, legacyFailClosed} {
		if err := in.svc.DisableNow(ctx, unit); err != nil {
			return false, err
		}
	}
	for _, path := range present {
		if err := in.files.Remove(path); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (in *Installer) legacyFiles() []string {
	var present []string
	for _, path := range append([]string{legacyCron}, legacyFiles...) {
		if in.files.Exists(path) {
			present = append(present, path)
		}
	}
	return present
}

// backup copies the old configuration files and the old rules; directories are
// skipped (see legacyFiles).
func (in *Installer) backup(dir string, files []string, rules []netstate.IPRule) error {
	for _, path := range files {
		data, err := in.files.Read(path)
		if err != nil {
			continue // a directory, or gone meanwhile
		}
		name := strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "_")
		if _, err := in.files.Write(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	var b strings.Builder
	for _, r := range rules {
		fmt.Fprintf(&b, "%+v\n", r)
	}
	_, err := in.files.Write(filepath.Join(dir, "rules.txt"), []byte(b.String()), 0o600)
	return err
}

// takeOverRules installs the agent's exit rules of legacySlot, unreachable
// first, then deletes the old ones.
func (in *Installer) takeOverRules(ctx context.Context, plan MigrationPlan) error {
	own := netstate.ExitRules(legacySlot)
	for _, r := range []netstate.IPRule{own[1], own[0]} {
		if slices.Contains(plan.Ours, r) {
			continue
		}
		if err := in.rules.AddRule(ctx, r); err != nil {
			return fmt.Errorf("add rule %+v: %w", r, err)
		}
	}
	for _, r := range plan.Legacy {
		if err := in.rules.DeleteRule(ctx, r); err != nil {
			return fmt.Errorf("delete old rule %+v: %w", r, err)
		}
	}
	return nil
}
