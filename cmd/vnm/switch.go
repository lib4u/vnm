package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lib4u/vnm/internal/app"
	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/usecase/agent"
	"github.com/lib4u/vnm/internal/usecase/modeswitch"
)

// applyWait is how long a switch waits for the agent to apply it; the agent
// passes every 15 s.
const applyWait = time.Minute

// switchable are the parts with a mode of their own, by command, and how the
// agent's snapshot reports each.
var switchable = map[string]struct {
	part     modeswitch.Part
	reported func(agent.Snapshot) policy.Mode
}{
	"egress": {modeswitch.Egress, func(s agent.Snapshot) policy.Mode { return s.Mode }},
	"guard":  {modeswitch.Guard, func(s agent.Snapshot) policy.Mode { return s.Guard.Mode }},
	"p2p":    {modeswitch.P2P, func(s agent.Snapshot) policy.Mode { return s.P2P.Mode }},
}

// runSwitch runs `vnm egress|guard|p2p observe|enforce|off|confirm|rollback`.
func runSwitch(ctx context.Context, command string, args []string) error {
	target := switchable[command]
	usage := fmt.Errorf("usage: vnm %s observe|enforce|off [-auto-rollback 5m] | confirm | rollback", command)
	if target.part.Protects {
		usage = fmt.Errorf("usage: vnm %s observe|enforce|off [-allow-leak] [-auto-rollback 5m] | confirm | rollback", command)
	}
	if len(args) == 0 {
		return usage
	}
	fs, paths := pathFlags(command + " " + args[0])
	allowLeak := fs.Bool("allow-leak", false, "consent to letting listed destinations out through the node's own address")
	autoRollback := fs.Duration("auto-rollback", 0, "undo the switch after this long unless confirmed from a new session")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	sw := paths.ModeSwitch()

	switch args[0] {
	case "confirm":
		if err := sw.Confirm(ctx); err != nil {
			return err
		}
		fmt.Println("switch kept")
		return nil
	case "rollback":
		// The timer runs this too: once the file is restored, the rollback has
		// done its job, and a slow agent or a confirm that won the race is no
		// failure — a failed transient unit would only get in the way.
		since := time.Now()
		cfg, err := sw.Rollback(ctx)
		if errors.Is(err, modeswitch.ErrNothingPending) {
			fmt.Println("nothing to roll back")
			return nil
		}
		if err != nil {
			return err
		}
		mode := target.part.Mode(cfg)
		fmt.Printf("policy restored, %s %s\n", command, mode)
		if err := waitApplied(ctx, *paths, target.reported, mode, since); err != nil {
			fmt.Println("warning:", err)
		}
		return nil
	}

	mode, ok := policy.ParseMode(args[0])
	if !ok {
		return usage
	}
	since := time.Now()
	res, err := sw.Set(ctx, target.part, mode, modeswitch.Options{AllowLeak: *allowLeak, AutoRollback: *autoRollback})
	if err != nil {
		return err
	}
	if !res.Changed {
		fmt.Printf("%s already %s\n", command, mode)
		return nil
	}
	fmt.Printf("%s %s → %s\n", command, res.From, res.To)
	if *autoRollback > 0 {
		fmt.Printf("provisional: rolls back in %v unless you run `vnm %s confirm` from a NEW ssh session\n", *autoRollback, command)
	}
	return waitApplied(ctx, *paths, target.reported, mode, since)
}

// waitApplied waits until the agent reports a pass in mode made after since.
func waitApplied(ctx context.Context, paths app.Paths, reported func(agent.Snapshot) policy.Mode, mode policy.Mode, since time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, applyWait)
	defer cancel()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	status := paths.Status()
	for {
		if s, err := status.Read(); err == nil && reported(s) == mode && s.LastReconcile.After(since) {
			fmt.Println("applied by the agent")
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("the agent has not applied the switch within " + applyWait.String() +
				"; see `vnm status` and `journalctl -u vnm-agent`")
		case <-tick.C:
		}
	}
}
