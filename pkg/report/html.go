package report

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/hateraku/bughunt/pkg/models"
)

// sevColor mappa la gravità a un colore per i badge HTML.
var sevColor = map[string]string{
	"critical": "#b00020",
	"high":     "#d9480f",
	"medium":   "#b8860b",
	"low":      "#2b6cb0",
	"info":     "#555",
}

func colorOf(sev string) string {
	if c, ok := sevColor[strings.ToLower(sev)]; ok {
		return c
	}
	return "#555"
}

// HTML genera un report HTML autocontenuto (CSS inline, nessuna dipendenza).
func HTML(sc *models.ScanContext) string {
	vulns := SortVulns(sc.Vulnerabilities)
	anoms := SortAnoms(sc.Anomalies)
	counts := severityCounts(vulns)

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="it"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	b.WriteString(`<title>BugHunt — Report</title>`)
	b.WriteString(`<style>
:root{--bg:#0f1115;--card:#171a21;--fg:#e6e6e6;--muted:#9aa4b2;--line:#262b34}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
.muted{color:var(--muted)}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:120px}
.card .n{font-size:22px;font-weight:700}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:700;text-transform:uppercase}
.finding{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:8px;padding:12px 14px;margin:8px 0}
.finding h3{margin:0 0 6px;font-size:14px}
.finding .row{color:var(--muted);font-size:12px;margin:2px 0;word-break:break-word}
.finding code{background:#0b0d11;border:1px solid var(--line);border-radius:4px;padding:1px 5px;font-size:12px}
.tags span{display:inline-block;background:#0b0d11;border:1px solid var(--line);border-radius:4px;padding:1px 6px;margin:2px 4px 2px 0;font-size:11px;color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}
</style></head><body><div class="wrap">`)

	b.WriteString(`<h1>BugHunt — Report di sicurezza</h1>`)
	b.WriteString(`<div class="muted">Generato il ` + esc(time.Now().Format("2006-01-02 15:04:05")) + `</div>`)

	// Riepilogo
	b.WriteString(`<div class="cards">`)
	card(&b, len(sc.Targets), "Target")
	card(&b, len(sc.Endpoints), "Endpoint")
	card(&b, len(sc.Technologies), "Tecnologie")
	card(&b, len(sc.Vulnerabilities), "Vulnerabilità")
	card(&b, len(sc.Anomalies), "Anomalie")
	b.WriteString(`</div>`)

	// Distribuzione gravità
	b.WriteString(`<div class="cards">`)
	for _, s := range severityOrder {
		if n := counts[s]; n > 0 {
			b.WriteString(fmt.Sprintf(`<div class="card"><div class="n" style="color:%s">%d</div><div class="muted">%s</div></div>`,
				colorOf(s), n, esc(strings.Title(s))))
		}
	}
	b.WriteString(`</div>`)

	// Vulnerabilità
	b.WriteString(`<h2>Vulnerabilità (` + fmt.Sprint(len(vulns)) + `)</h2>`)
	if len(vulns) == 0 {
		b.WriteString(`<div class="muted">Nessuna vulnerabilità.</div>`)
	}
	for _, v := range vulns {
		writeFinding(&b, v)
	}

	// Anomalie
	b.WriteString(`<h2>Anomalie (` + fmt.Sprint(len(anoms)) + `)</h2>`)
	if len(anoms) == 0 {
		b.WriteString(`<div class="muted">Nessuna anomalia.</div>`)
	}
	for _, a := range anoms {
		writeAnomaly(&b, a)
	}

	// Tecnologie
	if len(sc.Technologies) > 0 {
		b.WriteString(`<h2>Tecnologie</h2><div class="tags">`)
		for _, t := range sc.Technologies {
			b.WriteString(`<span>` + esc(t) + `</span>`)
		}
		b.WriteString(`</div>`)
	}

	b.WriteString(`</div></body></html>`)
	return b.String()
}

func card(b *strings.Builder, n int, label string) {
	b.WriteString(fmt.Sprintf(`<div class="card"><div class="n">%d</div><div class="muted">%s</div></div>`, n, esc(label)))
}

func writeFinding(b *strings.Builder, v models.Vulnerability) {
	b.WriteString(fmt.Sprintf(`<div class="finding" style="border-left-color:%s">`, colorOf(v.Severity)))
	b.WriteString(fmt.Sprintf(`<h3><span class="badge" style="background:%s">%s</span> %s</h3>`,
		colorOf(v.Severity), esc(v.Severity), esc(v.Title)))
	if v.URL != "" {
		b.WriteString(`<div class="row">URL: <code>` + esc(v.URL) + `</code></div>`)
	}
	if v.Evidence != "" {
		b.WriteString(`<div class="row">Evidence: <code>` + esc(v.Evidence) + `</code></div>`)
	}
	if cls := meta(v.Metadata, "class"); cls != "" {
		b.WriteString(`<div class="row">Classe: ` + esc(cls) + ` · ` + esc(meta(v.Metadata, "cwe")) + ` · stato: ` + esc(meta(v.Metadata, "status")) + `</div>`)
	}
	if len(v.References) > 0 {
		b.WriteString(`<div class="row">CVE: ` + esc(strings.Join(v.References, ", ")) + `</div>`)
	}
	if v.Remediation != "" {
		b.WriteString(`<div class="row">Rimedio: ` + esc(v.Remediation) + `</div>`)
	}
	if v.FoundBy != "" {
		b.WriteString(`<div class="row">Modulo: ` + esc(v.FoundBy) + `</div>`)
	}
	b.WriteString(`</div>`)
}

func writeAnomaly(b *strings.Builder, a models.Anomaly) {
	b.WriteString(fmt.Sprintf(`<div class="finding" style="border-left-color:%s">`, colorOf(a.Severity)))
	title := a.Description
	if title == "" {
		title = a.Type
	}
	b.WriteString(fmt.Sprintf(`<h3><span class="badge" style="background:%s">%s</span> %s</h3>`,
		colorOf(a.Severity), esc(a.Severity), esc(title)))
	if a.URL != "" {
		b.WriteString(`<div class="row">URL: <code>` + esc(a.URL) + `</code></div>`)
	}
	if a.Parameter != "" {
		b.WriteString(`<div class="row">Punto: <code>` + esc(a.Parameter) + `</code></div>`)
	}
	if a.Evidence != "" {
		b.WriteString(`<div class="row">Evidence: <code>` + esc(a.Evidence) + `</code></div>`)
	}
	if a.Class != "" {
		b.WriteString(`<div class="row">Classe: ` + esc(a.Class) + ` · ` + esc(a.CWE) + `</div>`)
	}
	b.WriteString(`</div>`)
}

// esc effettua l'escape HTML (fondamentale: l'evidence può contenere payload XSS).
func esc(s string) string { return html.EscapeString(s) }
