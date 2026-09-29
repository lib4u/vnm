package nftables

import (
	"context"
	"fmt"
	"sync"

	"github.com/lib4u/vnm/internal/domain/netstate"
	"github.com/lib4u/vnm/internal/infrastructure/runner"
	"github.com/lib4u/vnm/internal/usecase/apply"
)

// Firewall applies the nft side of the state through the nft tool.
type Firewall struct {
	run runner.Runner

	probed   sync.Once
	features Features
}

var _ apply.Firewall = (*Firewall)(nil)

// NewFirewall returns a Firewall that runs nft through r.
func NewFirewall(r runner.Runner) *Firewall {
	return &Firewall{run: r}
}

// Check validates the replacement against the kernel without applying it.
func (f *Firewall) Check(ctx context.Context, s netstate.State) error {
	inv, err := f.inventory(ctx)
	if err != nil {
		return fmt.Errorf("read the table: %w", err)
	}
	return f.nft(ctx, replaceScript(s, inv, f.kernelFeatures(ctx)), "-c", "-f", "-")
}

// Apply replaces the agent's table with the state in one transaction; what
// the resolver put into the dynamic sets the state keeps stays (see
// replaceScript).
func (f *Firewall) Apply(ctx context.Context, s netstate.State) error {
	inv, err := f.inventory(ctx)
	if err != nil {
		return fmt.Errorf("read the table: %w", err)
	}
	return f.nft(ctx, replaceScript(s, inv, f.kernelFeatures(ctx)), "-f", "-")
}

// SetHealth applies the health to the applied table.
func (f *Firewall) SetHealth(ctx context.Context, h netstate.Health) error {
	return f.nft(ctx, HealthScript(h), "-f", "-")
}

// Remove deletes the agent's table; the add-then-delete pair makes it succeed
// whether or not the table exists.
func (f *Firewall) Remove(ctx context.Context) error {
	script := fmt.Sprintf("table %[1]s %[2]s\ndelete table %[1]s %[2]s\n", TableFamily, TableName)
	return f.nft(ctx, script, "-f", "-")
}

// objrefProbe references a named counter from a rule; nft -c checks it
// against the kernel without committing anything.
const objrefProbe = "table inet vnm_probe {\n\tcounter c {}\n\tchain x {\n\t\tcounter name c\n\t}\n}\n"

// kernelFeatures learns once what the kernel supports beyond the base.
func (f *Firewall) kernelFeatures(ctx context.Context) Features {
	f.probed.Do(func() {
		f.features = Features{NamedCounters: f.nft(ctx, objrefProbe, "-c", "-f", "-") == nil}
	})
	return f.features
}

func (f *Firewall) nft(ctx context.Context, script string, args ...string) error {
	_, err := f.run.Run(ctx, runner.Command{Name: "nft", Args: args, Stdin: script})
	return err
}
