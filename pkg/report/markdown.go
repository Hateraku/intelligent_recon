package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/hateraku/bughunt/pkg/models"
)

var sevEmoji = map[string]string{
	"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪",
}

func emojiOf(sev string) string {
	if e, ok := sevEmoji[strings.ToLower(sev)]; ok {
		return e
	}
	return "⚪"
}

// Markdown genera un report in Markdown GitHub-compatibile dal ScanContext.
func Markdown(sc *models.ScanContext) string {
	vulns := SortVulns(sc.Vulnerabilities)
	anoms := SortAnoms(sc.Anomalies)
	counts := severityCounts(vulns)

	var b strings.Builder
	b.WriteString("# BugHunt — Report di sicurezza\n\n")
	b.WriteString("_Generato il " + time.Now().Format("2006-01-02 15:04:05") + "_\n\n")

	// Riepilogo
	b.WriteString("## Riepilogo\n\n")
	b.WriteString("| Target | Endpoint | Tecnologie | Vulnerabilità | Anomalie |\n")
	b.WriteString("|---:|---:|---:|---:|---:|\n")
	b.WriteString(fmt.Sprintf("| %d | %d | %d | %d | %d |\n\n",
		len(sc.Targets), len(sc.Endpoints), len(sc.Technologies), len(sc.Vulnerabilities), len(sc.Anomalies)))

	if len(vulns) > 0 {
		b.WriteString("**Per gravità:** ")
		var parts []string
		for _, s := range severityOrder {
			if n := counts[s]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s %s: %d", emojiOf(s), strings.Title(s), n))
			}
		}
		b.WriteString(strings.Join(parts, " · ") + "\n\n")
	}

	// Vulnerabilità
	b.WriteString(fmt.Sprintf("## Vulnerabilità (%d)\n\n", len(vulns)))
	if len(vulns) == 0 {
		b.WriteString("_Nessuna vulnerabilità._\n\n")
	}
	for _, v := range vulns {
		b.WriteString(fmt.Sprintf("### %s %s — %s\n\n", emojiOf(v.Severity), strings.Title(v.Severity), mdInline(v.Title)))
		if v.URL != "" {
			b.WriteString("- **URL:** `" + mdCode(v.URL) + "`\n")
		}
		if cls := meta(v.Metadata, "class"); cls != "" {
			b.WriteString(fmt.Sprintf("- **Classe:** %s · %s · stato: %s\n",
				mdInline(cls), mdInline(meta(v.Metadata, "cwe")), mdInline(meta(v.Metadata, "status"))))
		}
		if len(v.References) > 0 {
			b.WriteString("- **CVE:** " + mdInline(strings.Join(v.References, ", ")) + "\n")
		}
		if v.Evidence != "" {
			b.WriteString("- **Evidence:** `" + mdCode(v.Evidence) + "`\n")
		}
		if v.Remediation != "" {
			b.WriteString("- **Rimedio:** " + mdInline(v.Remediation) + "\n")
		}
		if v.FoundBy != "" {
			b.WriteString("- **Modulo:** " + mdInline(v.FoundBy) + "\n")
		}
		b.WriteString("\n")
	}

	// Anomalie
	b.WriteString(fmt.Sprintf("## Anomalie (%d)\n\n", len(anoms)))
	if len(anoms) == 0 {
		b.WriteString("_Nessuna anomalia._\n\n")
	} else {
		b.WriteString("| Gravità | Tipo | Classe | Punto | URL |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, a := range anoms {
			b.WriteString(fmt.Sprintf("| %s %s | %s | %s | %s | %s |\n",
				emojiOf(a.Severity), mdCell(a.Severity), mdCell(a.Type),
				mdCell(a.Class), mdCell(a.Parameter), mdCell(a.URL)))
		}
		b.WriteString("\n")
	}

	// Tecnologie
	if len(sc.Technologies) > 0 {
		b.WriteString("## Tecnologie\n\n")
		for _, t := range sc.Technologies {
			b.WriteString("- " + mdInline(t) + "\n")
		}
		b.WriteString("\n")
	}

	return b.String()
}

// mdInline neutralizza i caratteri che romperebbero il Markdown inline.
func mdInline(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "|", "\\|")
}

// mdCode rende sicuro un contenuto dentro un code span (niente backtick/newline).
func mdCode(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	return strings.ReplaceAll(s, "\n", " ")
}

// mdCell rende sicuro un contenuto dentro una cella di tabella.
func mdCell(s string) string {
	if s == "" {
		return "-"
	}
	return mdInline(s)
}
