package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/lib4u/vnm/internal/app"
	"github.com/lib4u/vnm/internal/usecase/doctor"
)

// runDoctor checks the node end to end; any failure makes the exit code
// non-zero.
func runDoctor(ctx context.Context, paths app.Paths) error {
	findings := paths.Doctor().Run(ctx)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, f := range findings {
		fmt.Fprintf(w, "%s\t%s\t%s\n", f.Level, f.Check, f.Detail)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if doctor.Failed(findings) {
		return errors.New("the node has failures")
	}
	return nil
}
