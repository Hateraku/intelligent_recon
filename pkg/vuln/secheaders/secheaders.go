// Package secheaders è una famiglia CROSS-TECH passiva che valuta gli header di
// sicurezza e i flag dei cookie dalla risposta già raccolta dal probe. Nessuna
// richiesta nuova; i finding sono CONFERMATI (l'assenza/presenza è osservata
// direttamente). HSTS è già segnalato dal probe, quindi qui non viene duplicato.
package secheaders

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hateraku/bughunt/pkg/models"
	"github.com/hateraku/bughunt/pkg/vuln/vulnclass"
)

// Module è la famiglia security-headers.
type Module struct{}

// New crea la famiglia.
func New() *Module { return &Module{} }

// Run valuta header e cookie e aggiunge i finding al ScanContext.
func (m *Module) Run(url string, isHTTPS bool, headers http.Header, cookies []*http.Cookie, sc *models.ScanContext) []string {
	var fired []string

	add := func(id, title, severity string, score float64, evidence, remediation, cwe string) {
		sc.AddVulnerability(models.Vulnerability{
			Type:        "security-header",
			Severity:    severity,
			Score:       score,
			Title:       title,
			Description: vulnclass.SecurityMisconfiguration.Description,
			URL:         url,
			Evidence:    evidence,
			Remediation: remediation,
			FoundBy:     "security-headers:" + id,
			Metadata: map[string]string{
				"class":  vulnclass.SecurityMisconfiguration.ID,
				"cwe":    cwe,
				"status": "confirmed",
			},
			DiscoveredAt: time.Now(),
		})
		fired = append(fired, id)
	}

	csp := headers.Get("Content-Security-Policy")
	if csp == "" {
		add("csp-missing", "Content-Security-Policy assente", models.SeverityMedium, 5.0,
			"nessun header Content-Security-Policy", "Definire una CSP restrittiva.", "CWE-693")
	}
	// Clickjacking: X-Frame-Options assente e CSP senza frame-ancestors.
	if headers.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		add("xfo-missing", "X-Frame-Options assente (rischio clickjacking)", models.SeverityMedium, 5.0,
			"nessun X-Frame-Options e nessun frame-ancestors in CSP",
			"Impostare X-Frame-Options: DENY oppure frame-ancestors 'none' in CSP.", "CWE-1021")
	}
	if !strings.EqualFold(headers.Get("X-Content-Type-Options"), "nosniff") {
		add("xcto-missing", "X-Content-Type-Options non impostato a nosniff", models.SeverityLow, 3.0,
			"X-Content-Type-Options: "+orAbsent(headers.Get("X-Content-Type-Options")),
			"Impostare X-Content-Type-Options: nosniff.", "CWE-16")
	}
	if headers.Get("Referrer-Policy") == "" {
		add("referrer-missing", "Referrer-Policy assente", models.SeverityLow, 2.5,
			"nessun Referrer-Policy",
			"Impostare una Referrer-Policy (es. strict-origin-when-cross-origin).", "CWE-200")
	}
	if headers.Get("Permissions-Policy") == "" {
		add("permissions-missing", "Permissions-Policy assente", models.SeverityLow, 2.0,
			"nessun Permissions-Policy",
			"Limitare le feature del browser con Permissions-Policy.", "CWE-16")
	}

	// Sicurezza dei cookie: un finding per cookie, con i flag mancanti.
	for _, c := range cookies {
		var missing []string
		if isHTTPS && !c.Secure {
			missing = append(missing, "Secure")
		}
		if !c.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if c.SameSite != http.SameSiteLaxMode && c.SameSite != http.SameSiteStrictMode && c.SameSite != http.SameSiteNoneMode {
			missing = append(missing, "SameSite")
		}
		if len(missing) == 0 {
			continue
		}
		severity, score := models.SeverityLow, 3.0
		for _, f := range missing {
			if f == "Secure" {
				severity, score = models.SeverityMedium, 5.0
			}
		}
		sc.AddVulnerability(models.Vulnerability{
			Type:        "insecure-cookie",
			Severity:    severity,
			Score:       score,
			Title:       fmt.Sprintf("Cookie %q senza flag: %s", c.Name, strings.Join(missing, ", ")),
			Description: vulnclass.SecurityMisconfiguration.Description,
			URL:         url,
			Evidence:    fmt.Sprintf("cookie %s: flag mancanti %s", c.Name, strings.Join(missing, ", ")),
			Remediation: "Impostare i flag Secure, HttpOnly e SameSite sui cookie (specialmente di sessione).",
			FoundBy:     "security-headers:insecure-cookie",
			Metadata: map[string]string{
				"class":  vulnclass.SecurityMisconfiguration.ID,
				"cwe":    "CWE-614",
				"status": "confirmed",
			},
			DiscoveredAt: time.Now(),
		})
		fired = append(fired, "cookie:"+c.Name)
	}

	return fired
}

func orAbsent(s string) string {
	if s == "" {
		return "(assente)"
	}
	return s
}
