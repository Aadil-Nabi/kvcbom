// Package html renders a Report as a single, self-contained HTML file (SPEC §9): inline
// CSS, no external fonts, scripts, or CDNs, and print-friendly in black and white. All
// data-derived text flows through html/template's contextual auto-escaping; the package
// never wraps input in template.HTML, so a crafted asset name cannot inject markup.
package html

import (
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"

	"github.com/Aadil-Nabi/kvcbom/pkg/report"
)

// Renderer writes a Report as self-contained HTML.
type Renderer struct{}

var funcs = template.FuncMap{
	"pct2": func(f float64) string { return strconv.FormatFloat(f, 'f', 2, 64) },
	"num":  func(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) },
	"yesno": func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	},
	"dict": func(title string, counts []report.Count) map[string]any {
		return map[string]any{"title": title, "counts": counts}
	},
	"caplist": func(names []string, n int) string {
		if len(names) <= n {
			return strings.Join(names, ", ")
		}
		return strings.Join(names[:n], ", ") + fmt.Sprintf(" (+%d more)", len(names)-n)
	},
}

var tmpl = template.Must(template.New("report").Funcs(funcs).Parse(pageTemplate))

// Render implements report.Renderer.
func (Renderer) Render(r *report.Report, w io.Writer) error {
	return tmpl.Execute(w, r)
}

const pageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: Georgia, 'Times New Roman', serif; color: #111; background: #fff;
  max-width: 54rem; margin: 2rem auto; padding: 0 1.25rem; line-height: 1.5; }
h1, h2, h3 { font-family: Arial, Helvetica, sans-serif; line-height: 1.25; }
h1 { font-size: 1.9rem; margin: 0 0 .25rem; }
h2 { font-size: 1.3rem; margin: 2rem 0 .5rem; border-bottom: 2px solid #111; padding-bottom: .2rem; }
h3 { font-size: 1.05rem; margin: 1.25rem 0 .4rem; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; font-size: .92rem; }
th, td { border: 1px solid #999; padding: .35rem .5rem; text-align: left; vertical-align: top; }
th { background: #f0f0f0; }
code { font-family: 'Courier New', monospace; font-size: .85rem; word-break: break-all; }
.meta { font-size: .9rem; color: #333; }
.meta div { margin: .1rem 0; }
.warn { border: 1px solid #111; background: #f6f6f6; padding: .6rem .9rem; margin: 1rem 0; }
.sev { font-family: Arial, sans-serif; font-size: .78rem; font-weight: bold; text-transform: uppercase;
  border: 1px solid #111; padding: 0 .35rem; white-space: nowrap; }
.muted { color: #555; }
footer { margin-top: 3rem; padding-top: .75rem; border-top: 1px solid #999; font-size: .8rem; color: #555; }
@media print { body { margin: 0; max-width: none; } h2 { page-break-after: avoid; } table { page-break-inside: avoid; } }
</style>
</head>
<body>
<h1>{{.Title}}</h1>
<div class="meta">
  {{if .Assessment.Organisation}}<div><strong>Organisation:</strong> {{.Assessment.Organisation}}</div>{{end}}
  {{if .Assessment.Scope}}<div><strong>Scope:</strong> {{.Assessment.Scope}}</div>{{end}}
  {{if .Assessment.Assessor}}<div><strong>Assessor:</strong> {{.Assessment.Assessor}}</div>{{end}}
  <div><strong>Generated:</strong> {{.GeneratedAt}}</div>
  <div><strong>Tool:</strong> {{.Tool.Name}} {{.Tool.Version}}</div>
  <div><strong>Rule pack:</strong> {{.Pack.ID}} {{.Pack.Version}} ({{.Pack.Status}})</div>
</div>

{{if .Warnings.Messages}}
<div class="warn">
<strong>Warnings</strong>
<ul>{{range .Warnings.Messages}}<li>{{.}}</li>{{end}}</ul>
</div>
{{end}}

<h2>Executive summary</h2>
<p>This assessment covers <strong>{{.Summary.TotalAssets}}</strong> cryptographic asset(s) and raised
<strong>{{.Summary.TotalFindings}}</strong> finding(s). Harvest-now-decrypt-later (HNDL) exposure:
<strong>{{.Summary.HNDLAssetCount}}</strong> asset(s).</p>

{{if .Summary.TopRisks}}
<h3>Top risks</h3>
<table><thead><tr><th>Asset</th><th>Quantum status</th><th>HNDL</th><th>Score</th></tr></thead>
<tbody>{{range .Summary.TopRisks}}<tr><td>{{.Name}}</td><td>{{.QuantumStatus}}</td><td>{{yesno .HNDL}}</td><td>{{pct2 .Final}}</td></tr>{{end}}</tbody></table>
{{end}}

{{if .Summary.MoscaByScenario}}
<h3>Mosca exposure by scenario</h3>
<table><thead><tr><th>Scenario</th><th>Years until CRQC</th><th>Exposed assets</th><th>HNDL assets</th></tr></thead>
<tbody>{{range .Summary.MoscaByScenario}}<tr><td>{{.Scenario}}</td><td>{{num .YearsUntil}}</td><td>{{.ExposedAssets}}</td><td>{{.HNDLAssets}}</td></tr>{{end}}</tbody></table>
{{end}}

<h2>Inventory</h2>
{{template "counts" dict "By asset type" .Inventory.ByType}}
{{template "counts" dict "By quantum status" .Inventory.ByQuantumStatus}}
{{template "counts" dict "By evidence confidence" .Inventory.ByConfidence}}
{{template "counts" dict "By system" .Inventory.BySystem}}

<h2>Findings</h2>
{{if .FindingGroups}}
<p class="muted">Grouped by type; {{len .Findings}} finding(s) in total.</p>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Assets</th><th>Affected</th></tr></thead>
<tbody>{{range .FindingGroups}}<tr>
  <td><span class="sev">{{.Severity}}</span></td>
  <td>{{.Title}}{{if .Explanation}}<br><span class="muted">{{.Explanation}}</span>{{end}}{{if .RequiresVerification}}<br><span class="muted">{{.RequiresVerification}} require verification</span>{{end}}</td>
  <td>{{.Count}}</td>
  <td>{{caplist .Assets 12}}</td>
</tr>{{end}}</tbody></table>
{{else}}<p>No findings.</p>{{end}}

{{if .Systems}}
<h2>Per-system view</h2>
{{range .Systems}}
<h3>{{.System.Name}}{{if .System.CrownJewel}} (crown jewel){{end}}</h3>
<p>Criticality: {{.System.Criticality}}. Assets: {{len .AssetIDs}}. Worst score: {{pct2 .WorstFinal}}.</p>
{{if .FindingCounts}}<p>Findings: {{range .FindingCounts}}{{.Key}} {{.Count}}; {{end}}</p>{{end}}
{{end}}
{{end}}

{{if .Frameworks}}
<h2>Framework mapping</h2>
{{range .Frameworks}}
<h3>{{.Name}}</h3>
<table><thead><tr><th>Finding type</th><th>Control</th><th>Findings</th><th>Verified</th></tr></thead>
<tbody>{{range .Mappings}}<tr><td>{{.FindingType}}</td><td>{{.ControlID}}</td><td>{{.FindingCount}}</td><td>{{if .Unverified}}NO (TODO){{else}}yes{{end}}</td></tr>{{end}}</tbody></table>
{{end}}
{{end}}

{{if .Remediation}}
<h2>Remediation roadmap</h2>
{{range .Remediation}}
<h3><span class="sev">{{.TopSeverity}}</span> {{.Summary}}</h3>
{{if .Detail}}<p>{{.Detail}}</p>{{end}}
<p class="muted">Applies to {{.FindingCount}} finding(s): {{range .FindingTypes}}{{.}}; {{end}}{{if .References}}<br>References: {{range .References}}{{.}}; {{end}}{{end}}</p>
{{end}}
{{end}}

{{if .AffectedAssets}}
<h2>Affected assets &mdash; remediation detail</h2>
<p class="muted">The {{len .AffectedAssets}} algorithm(s) that need action, with where each was found.</p>
<table><thead><tr><th>Severity</th><th>Algorithm</th><th>Status</th><th>Role</th><th>Occurrences</th><th>Found at</th></tr></thead>
<tbody>{{range .AffectedAssets}}<tr>
  <td><span class="sev">{{.Severity}}</span></td>
  <td>{{.Name}}</td>
  <td>{{.Status}}</td>
  <td>{{.Primitive}}</td>
  <td>{{.Count}}</td>
  <td>{{caplist .Locations 6}}</td>
</tr>{{end}}</tbody></table>
{{end}}

<h2>Appendix</h2>
<h3>Methodology</h3>
<p>{{.Appendix.Methodology}}</p>
<h3>Scoring</h3>
<p><code>{{.Appendix.ScoringFormula}}</code></p>
{{if .Appendix.MergeDecisions}}
<h3>Merge decisions</h3>
<p class="muted">{{len .Appendix.MergeDecisions}} asset(s) were formed by merging duplicate records across inputs.</p>
<ul>{{range .Appendix.MergeDecisions}}<li>{{if .AssetName}}{{.AssetName}} {{end}}(<code>{{.AssetID}}</code>) &mdash; merged {{len .Sources}} source record(s)</li>{{end}}</ul>
{{end}}
{{if .Appendix.Sources}}
<h3>Sources</h3>
<ul>{{range .Appendix.Sources}}<li><strong>{{.ID}}</strong> [{{.Status}}]: {{.Title}} &mdash; {{.URL}}</li>{{end}}</ul>
{{end}}
{{if .Inputs}}
<h3>Input files</h3>
<ul>{{range .Inputs}}<li><code>{{.File}}</code> &mdash; <code>{{.SHA256}}</code></li>{{end}}</ul>
{{end}}

<footer>Generated by {{.Tool.Name}} {{.Tool.Version}} using rule pack {{.Pack.ID}} {{.Pack.Version}}. This report makes no network calls and contains no external resources.</footer>
</body>
</html>

{{define "counts"}}{{if .counts}}<h3>{{.title}}</h3>
<table><thead><tr><th></th><th>Count</th></tr></thead>
<tbody>{{range .counts}}<tr><td>{{.Key}}</td><td>{{.Count}}</td></tr>{{end}}</tbody></table>
{{end}}{{end}}
`
