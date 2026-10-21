// Package cli holds shared plumbing for the command-line layer: documented exit
// codes, a coded-error type that carries the intended exit code, and logger setup.
package cli

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Exit codes, documented in the CLI reference. The CLI maps every outcome to one.
const (
	ExitOK         = 0 // success
	ExitUsage      = 1 // bad invocation (flags/args)
	ExitValidation = 2 // input validation failure
	ExitPolicy     = 3 // policy threshold breached (--fail-on)
	ExitInternal   = 4 // unexpected internal error
)

// ExitError wraps an error with the process exit code it should produce.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

// Coded tags err with an exit code. Returns nil when err is nil.
func Coded(code int, err error) error {
	if err == nil {
		return nil
	}
	return &ExitError{Code: code, Err: err}
}

// Codedf builds a coded error from a format string.
func Codedf(code int, format string, a ...any) error {
	return &ExitError{Code: code, Err: fmt.Errorf(format, a...)}
}

// CodeOf extracts the exit code from err. A nil error is success; errors not tagged with
// a code are treated as usage errors (cobra flag/argument failures surface this way).
func CodeOf(err error) int {
	if err == nil {
		return ExitOK
	}
	var e *ExitError
	if errors.As(err, &e) {
		return e.Code
	}
	return ExitUsage
}

// SetupLogger configures the default slog logger. Output goes to w (stderr in the
// binary). noColor is accepted for forward compatibility; the stdlib handlers emit no
// colour, so it is currently a no-op.
func SetupLogger(w io.Writer, level, format string, noColor bool) error {
	_ = noColor
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info", "":
		lvl = slog.LevelInfo
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return fmt.Errorf("invalid --log-level %q (want debug|info|warn|error)", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	switch strings.ToLower(format) {
	case "json":
		h = slog.NewJSONHandler(w, opts)
	case "text", "":
		h = slog.NewTextHandler(w, opts)
	default:
		return fmt.Errorf("invalid --log-format %q (want text|json)", format)
	}
	slog.SetDefault(slog.New(h))
	return nil
}
