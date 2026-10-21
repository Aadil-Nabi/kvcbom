package diff

import (
	"fmt"
	"strings"
)

// Markdown renders a diff Result as Markdown for pasting into tickets and PRs.
func Markdown(res *Result) string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "# Assessment diff\n\n")
	fmt.Fprintf(b, "Baseline: %s (pack %s %s) — %d assets, %d findings  \n",
		res.Baseline.GeneratedAt, res.Baseline.PackID, res.Baseline.PackVersion, res.Baseline.Assets, res.Baseline.Findings)
	fmt.Fprintf(b, "Current:  %s (pack %s %s) — %d assets, %d findings  \n\n",
		res.Current.GeneratedAt, res.Current.PackID, res.Current.PackVersion, res.Current.Assets, res.Current.Findings)

	s := res.Summary
	fmt.Fprintf(b, "**Assets:** +%d added, -%d removed, %d changed.  \n", s.AssetsAdded, s.AssetsRemoved, s.AssetsChanged)
	fmt.Fprintf(b, "**Findings:** +%d new, -%d resolved.", s.FindingsAdded, s.FindingsResolved)
	if len(s.NewFindingsBySev) > 0 {
		parts := make([]string, 0, len(s.NewFindingsBySev))
		for _, c := range s.NewFindingsBySev {
			parts = append(parts, fmt.Sprintf("%s %d", c.Severity, c.Count))
		}
		fmt.Fprintf(b, " New by severity: %s.", strings.Join(parts, ", "))
	}
	fmt.Fprintf(b, "\n\n")

	if len(res.AssetsChanged) > 0 {
		fmt.Fprintf(b, "## Risk changes\n\n")
		fmt.Fprintf(b, "| Asset | Status | Score | HNDL | Direction |\n|---|---|---|---|---|\n")
		for _, c := range res.AssetsChanged {
			status := c.ToStatus
			if c.StatusChanged {
				status = fmt.Sprintf("%s → %s", c.FromStatus, c.ToStatus)
			}
			score := fmt.Sprintf("%.2f", c.ToFinal)
			if c.ScoreChanged {
				score = fmt.Sprintf("%.2f → %.2f", c.FromFinal, c.ToFinal)
			}
			dir := "improved"
			if c.Regressed {
				dir = "**regressed**"
			}
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n", mdEsc(c.Name), status, score, hndlArrow(c), dir)
		}
		fmt.Fprintf(b, "\n")
	}

	writeFindingTable(b, "New findings", res.FindingsAdded)
	writeFindingTable(b, "Resolved findings", res.FindingsResolved)
	writeAssetList(b, "Assets added", res.AssetsAdded)
	writeAssetList(b, "Assets removed", res.AssetsRemoved)

	if res.Summary.AssetsAdded == 0 && res.Summary.AssetsRemoved == 0 && res.Summary.AssetsChanged == 0 &&
		res.Summary.FindingsAdded == 0 && res.Summary.FindingsResolved == 0 {
		fmt.Fprintf(b, "No changes between the two assessments.\n")
	}
	return b.String()
}

func writeFindingTable(b *strings.Builder, title string, fs []FindingRef) {
	if len(fs) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s\n\n| Severity | Finding | Asset |\n|---|---|---|\n", title)
	for _, f := range fs {
		fmt.Fprintf(b, "| %s | %s | `%s` |\n", f.Severity, mdEsc(f.Title), f.AssetID)
	}
	fmt.Fprintf(b, "\n")
}

func writeAssetList(b *strings.Builder, title string, as []AssetRef) {
	if len(as) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s\n\n", title)
	for _, a := range as {
		fmt.Fprintf(b, "- %s (`%s`) — %s, score %.2f\n", mdEsc(a.Name), a.AssetID, a.QuantumStatus, a.Final)
	}
	fmt.Fprintf(b, "\n")
}

func hndlArrow(c AssetChange) string {
	switch {
	case c.FromHNDL == c.ToHNDL:
		return yesno(c.ToHNDL)
	case c.ToHNDL:
		return "no → yes"
	default:
		return "yes → no"
	}
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func mdEsc(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "\r", "").Replace(s)
}
