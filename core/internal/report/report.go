// Package report turns a workspace's findings into an exportable artifact —
// JSON for tooling, CSV for spreadsheets, and a single self-contained HTML
// file for sharing with a client or stakeholder without extra setup.
// SARIF/PDF export (plan §7) follow the same Data -> []byte shape once added.
package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"time"

	"github.com/sentrybench/core/internal/models"
)

type Data struct {
	Workspace   models.Workspace
	Findings    []models.Finding
	GeneratedAt time.Time
}

func GenerateJSON(d Data) ([]byte, error) {
	out := struct {
		Workspace   string          `json:"workspace"`
		GeneratedAt time.Time       `json:"generatedAt"`
		Summary     map[string]int  `json:"summary"`
		Findings    []models.Finding `json:"findings"`
	}{
		Workspace:   d.Workspace.Name,
		GeneratedAt: d.GeneratedAt,
		Summary:     severityCounts(d.Findings),
		Findings:    d.Findings,
	}
	return json.MarshalIndent(out, "", "  ")
}

func GenerateCSV(d Data) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	if err := w.Write([]string{"Severity", "Title", "Check ID", "Method", "URL", "Description", "Evidence", "Remediation", "Found At"}); err != nil {
		return nil, err
	}
	for _, f := range sortedBySeverity(d.Findings) {
		if err := w.Write([]string{
			f.Severity, f.Title, f.CheckID, f.Method, f.URL, f.Description, f.Evidence, f.Remediation, f.CreatedAt.Format(time.RFC3339),
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"severityClass": func(sev string) string {
		switch sev {
		case models.SeverityCritical:
			return "sev-critical"
		case models.SeverityHigh:
			return "sev-high"
		case models.SeverityMedium:
			return "sev-medium"
		case models.SeverityLow:
			return "sev-low"
		default:
			return "sev-info"
		}
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SentryBench report — {{.Workspace.Name}}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
  h1 { font-size: 1.4rem; }
  .meta { color: #666; font-size: 0.85rem; margin-bottom: 2rem; }
  .summary { display: flex; gap: 0.75rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .summary span { border-radius: 6px; padding: 0.3rem 0.7rem; font-size: 0.8rem; font-weight: 600; }
  .finding { border: 1px solid #ccc3; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
  .finding h2 { font-size: 1rem; margin: 0 0 0.4rem; }
  .badge { display: inline-block; border-radius: 999px; padding: 0.15rem 0.6rem; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; margin-right: 0.5rem; }
  .sev-critical { background: #7f1d1d; color: #fff; }
  .sev-high { background: #b91c1c; color: #fff; }
  .sev-medium { background: #b45309; color: #fff; }
  .sev-low { background: #1d4ed8; color: #fff; }
  .sev-info { background: #475569; color: #fff; }
  .field { margin: 0.35rem 0; font-size: 0.9rem; }
  .field b { color: #888; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; display: block; }
  pre { background: #0001; padding: 0.5rem; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
</style>
</head>
<body>
  <h1>SentryBench security report — {{.Workspace.Name}}</h1>
  <div class="meta">Generated {{.GeneratedAt.Format "Jan 2, 2006 15:04 MST"}} · {{len .Findings}} findings</div>

  <div class="summary">
    {{range $sev, $count := .Summary}}<span class="{{severityClass $sev}}">{{$sev}}: {{$count}}</span>{{end}}
  </div>

  {{range .Findings}}
  <div class="finding">
    <h2><span class="badge {{severityClass .Severity}}">{{.Severity}}</span>{{.Title}}</h2>
    <div class="field"><b>Request</b>{{.Method}} {{.URL}}</div>
    <div class="field"><b>Description</b>{{.Description}}</div>
    {{if .Evidence}}<div class="field"><b>Evidence</b><pre>{{.Evidence}}</pre></div>{{end}}
    {{if .Remediation}}<div class="field"><b>Remediation</b>{{.Remediation}}</div>{{end}}
  </div>
  {{else}}
  <p>No findings — nice work, or nothing's been scanned yet.</p>
  {{end}}
</body>
</html>
`))

func GenerateHTML(d Data) ([]byte, error) {
	sorted := sortedBySeverity(d.Findings)
	view := struct {
		Workspace   models.Workspace
		Findings    []models.Finding
		GeneratedAt time.Time
		Summary     map[string]int
	}{d.Workspace, sorted, d.GeneratedAt, severityCounts(d.Findings)}

	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, view); err != nil {
		return nil, fmt.Errorf("render HTML report: %w", err)
	}
	return buf.Bytes(), nil
}

var severityOrder = map[string]int{
	models.SeverityCritical: 0,
	models.SeverityHigh:     1,
	models.SeverityMedium:   2,
	models.SeverityLow:      3,
	models.SeverityInfo:     4,
}

func sortedBySeverity(findings []models.Finding) []models.Finding {
	out := make([]models.Finding, len(findings))
	copy(out, findings)
	// Simple insertion sort — finding counts per scan are small (dozens,
	// not thousands), so this stays readable over pulling in "sort" generics.
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && severityOrder[out[j-1].Severity] > severityOrder[out[j].Severity] {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	return out
}

func severityCounts(findings []models.Finding) map[string]int {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}
