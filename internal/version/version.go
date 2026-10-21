// Package version carries build information injected at link time via -ldflags.
package version

import "fmt"

// These are overridden at build time, e.g.:
//
//	-ldflags "-X github.com/Aadil-Nabi/kvcbom/internal/version.Version=1.0.0 \
//	          -X .../version.Commit=$(git rev-parse --short HEAD) \
//	          -X .../version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String renders a one-line human-readable version banner.
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, Date)
}
