package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// progress prints human-friendly, step-by-step feedback for a long command. It
// writes to stderr so stdout stays clean, shows a green check when the output is
// an interactive terminal with colour enabled, and degrades to a plain "[ok]"
// marker otherwise (redirected output, CI, or --no-color / NO_COLOR).
type progress struct {
	w     io.Writer
	color bool
}

const (
	ansiGreen = "\x1b[32m"
	ansiReset = "\x1b[0m"
	checkMark = "✓" // ✓
)

// newProgress builds a progress reporter for the command's stderr.
func newProgress(cmd *cobra.Command) *progress {
	w := cmd.ErrOrStderr()
	noColor, _ := cmd.Flags().GetBool("no-color")
	if os.Getenv("NO_COLOR") != "" {
		noColor = true
	}
	color := !noColor && isTerminal(w)
	if color {
		if f, ok := w.(*os.File); ok {
			enableVirtualTerminal(f) // make ANSI work on Windows consoles; no-op elsewhere
		}
	}
	return &progress{w: w, color: color}
}

// step reports one completed pipeline stage.
func (p *progress) step(format string, a ...any) {
	if p == nil {
		return
	}
	msg := fmt.Sprintf(format, a...)
	if p.color {
		fmt.Fprintf(p.w, "%s%s%s %s\n", ansiGreen, checkMark, ansiReset, msg)
	} else {
		fmt.Fprintf(p.w, "[ok] %s\n", msg)
	}
}

// done prints the success banner followed by the list of written files.
func (p *progress) done(files []string) {
	if p == nil {
		return
	}
	if p.color {
		fmt.Fprintf(p.w, "\n%s%s Report generated successfully%s\n", ansiGreen, checkMark, ansiReset)
	} else {
		fmt.Fprintln(p.w, "\nReport generated successfully")
	}
	for _, f := range files {
		fmt.Fprintf(p.w, "    %s\n", f)
	}
}

// isTerminal reports whether w is an interactive character device (a console),
// using only the standard library so the single-binary, no-dependency build is
// preserved. A redirected file or pipe is not a character device.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
