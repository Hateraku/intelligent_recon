// Package secrets è una famiglia CROSS-TECH passiva che cerca segreti (chiavi
// API, token, chiavi private) nel body già scaricato dal probe. Nessuna richiesta
// nuova. I match sono REDATTI nei finding per non ristampare il segreto in chiaro.
//
// I pattern molto specifici (AWS/GitHub/Stripe/chiavi private) hanno alta
// confidenza; il JWT è generico e marcato low (alto tasso di falsi positivi).
package secrets

import (
	"regexp"
	"time"

	"github.com/hateraku/bughunt/pkg/models"
	"github.com/hateraku/bughunt/pkg/vuln/vulnclass"
)

type rule struct {
	id       string
	name     string
	re       *regexp.Regexp
	severity string
	score    float64
}

var rules = []rule{
	{"aws-access-key", "AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), models.SeverityHigh, 8.5},
	{"github-token", "GitHub Token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36}`), models.SeverityHigh, 8.5},
	{"stripe-secret", "Stripe Secret Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`), models.SeverityHigh, 9.0},
	{"private-key", "Blocco di chiave privata", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), models.SeverityHigh, 9.0},
	{"google-api-key", "Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), models.SeverityMedium, 6.0},
	{"slack-token", "Slack Token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`), models.SeverityHigh, 8.0},
	{"jwt", "JSON Web Token", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), models.SeverityLow, 4.0},
}

// Module è la famiglia secrets.
type Module struct{}

// New crea la famiglia.
func New() *Module { return &Module{} }

// Run cerca i segreti nel body e aggiunge i finding (redatti) al ScanContext.
func (m *Module) Run(url, body string, sc *models.ScanContext) []string {
	var fired []string
	seen := make(map[string]bool)

	for _, r := range rules {
		for _, match := range r.re.FindAllString(body, -1) {
			key := r.id + "|" + match
			if seen[key] {
				continue
			}
			seen[key] = true

			sc.AddVulnerability(models.Vulnerability{
				Type:        "exposed-secret",
				Severity:    r.severity,
				Score:       r.score,
				Title:       r.name + " esposto nel contenuto",
				Description: vulnclass.HardcodedSecret.Description,
				URL:         url,
				Evidence:    r.name + ": " + redact(match),
				Remediation: "Rimuovere il segreto dal contenuto servito e ruotarlo immediatamente.",
				FoundBy:     "secrets:" + r.id,
				Metadata: map[string]string{
					"class":  vulnclass.HardcodedSecret.ID,
					"cwe":    vulnclass.HardcodedSecret.CWE,
					"status": "confirmed",
				},
				DiscoveredAt: time.Now(),
			})
			fired = append(fired, r.id)
		}
	}
	return fired
}

// redact maschera il centro del match per non ristampare il segreto in chiaro.
func redact(s string) string {
	if len(s) <= 10 {
		return s[:2] + "***"
	}
	return s[:6] + "***" + s[len(s)-4:]
}
