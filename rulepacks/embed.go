// Package rulepacks embeds the rule packs shipped with kvcbom so the tool works fully
// offline. Each pack is a single YAML file named <id>.yaml. The pkg/rulepack loader
// reads these bytes; this package holds no logic beyond exposing the embedded files.
package rulepacks

import (
	"embed"
	"io/fs"
	"sort"
	"strings"
)

// FS holds the embedded rule-pack YAML files.
//
//go:embed *.yaml
var FS embed.FS

// Names returns the embedded pack IDs (file base names without extension), sorted.
func Names() []string {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		out = append(out, strings.TrimSuffix(name, ".yaml"))
	}
	sort.Strings(out)
	return out
}

// Read returns the bytes of the embedded pack with the given ID, if present.
func Read(id string) ([]byte, bool) {
	b, err := FS.ReadFile(id + ".yaml")
	if err != nil {
		return nil, false
	}
	return b, true
}
