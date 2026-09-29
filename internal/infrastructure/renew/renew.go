// Package renew runs an exit's renew command (policy.Renew): whatever issues
// the exit new credentials is the operator's, the agent only runs it.
package renew

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lib4u/vnm/internal/domain/policy"
	"github.com/lib4u/vnm/internal/infrastructure/runner"
	"github.com/lib4u/vnm/internal/usecase/exits"
)

// Command runs renew commands.
type Command struct {
	run runner.Runner
}

var _ exits.Renewer = (*Command)(nil)

// New returns a Command running through r, whose timeout bounds a renewal.
func New(r runner.Runner) *Command {
	return &Command{run: r}
}

// Renew runs the exit's renew command.
func (c *Command) Renew(ctx context.Context, e policy.Exit) error {
	if e.Renew == nil || len(e.Renew.Command) == 0 {
		return errors.New("the exit has no renew command")
	}
	out, err := c.run.Run(ctx, runner.Command{Name: e.Renew.Command[0], Args: e.Renew.Command[1:]})
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(e.Renew.Command, " "), err, strings.TrimSpace(out))
	}
	return nil
}
