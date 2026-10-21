// Command kvcbom assesses post-quantum cryptographic readiness from CycloneDX CBOMs.
//
// The command layer is deliberately thin: it parses flags and calls the engine
// packages under pkg/. See docs/ for usage.
package main

import (
	"fmt"
	"os"

	"github.com/Aadil-Nabi/kvcbom/internal/cli"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		if err.Error() != "" {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(cli.CodeOf(err))
	}
}
