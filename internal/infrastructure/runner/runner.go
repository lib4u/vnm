// Package runner isolates the agent from os/exec. Everything the agent does to
// the kernel goes through nft and ip, so routing all of it through one narrow
// interface is what makes the adapters testable against fakes, and what keeps
// timeouts and error reporting in one place.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Command is one invocation of an external tool.
type Command struct {
	Name string
	Args []string
	// Stdin is fed to the command; empty means no input.
	Stdin string
}

func (c Command) String() string {
	return strings.Join(append([]string{c.Name}, c.Args...), " ")
}

// Runner executes a command and returns its stdout.
type Runner interface {
	Run(ctx context.Context, cmd Command) (string, error)
}

// ExitError reports a command that ran and exited non-zero.
type ExitError struct {
	Cmd    string
	Code   int
	Stderr string
}

func (e *ExitError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		return fmt.Sprintf("%s: exit status %d", e.Cmd, e.Code)
	}
	return fmt.Sprintf("%s: exit status %d: %s", e.Cmd, e.Code, msg)
}

// System is the production Runner.
type System struct {
	// Timeout caps a single command, so a wedged tool cannot hang the agent.
	Timeout time.Duration
}

var _ Runner = System{}

// Run executes cmd.
func (s System) Run(ctx context.Context, cmd Command) (string, error) {
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}

	c := exec.CommandContext(ctx, cmd.Name, cmd.Args...)
	if cmd.Stdin != "" {
		c.Stdin = strings.NewReader(cmd.Stdin)
	}
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	err := c.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stdout.String(), &ExitError{Cmd: cmd.String(), Code: exitErr.ExitCode(), Stderr: stderr.String()}
	}
	if err != nil {
		return stdout.String(), fmt.Errorf("%s: %w", cmd, err)
	}
	return stdout.String(), nil
}
