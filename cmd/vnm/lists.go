package main

import (
	"context"
	"fmt"

	"github.com/lib4u/vnm/internal/app"
	"github.com/lib4u/vnm/internal/infrastructure/configfile"
)

// runListsUpdate downloads the policy's remote list sources now. The agent
// notices the new copies on its next pass and re-resolves the lists.
func runListsUpdate(ctx context.Context, paths app.Paths) error {
	cfg, err := configfile.Load(paths.Config)
	if err != nil {
		return err
	}
	if err := paths.ListRefresher().RefreshAll(ctx, cfg); err != nil {
		return err
	}
	fmt.Println("lists downloaded; the agent re-reads them on its next pass")
	return nil
}
