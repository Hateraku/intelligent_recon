// Package exposure è una famiglia CROSS-TECH (non legata a una tecnologia) che
// classifica l'esposizione di percorsi sensibili già sondati dalla discovery.
//
// È PASSIVA: non fa nuove richieste, legge gli esiti dei probe della discovery.
// Siccome quei probe usano HEAD e molte SPA rispondono 200 a qualunque percorso
// (catch-all), i finding sono marcati `unconfirmed`: segnalano un candidato da
// confermare con una GET del contenuto (verifica deferita ai target autorizzati).
package exposure

import (
	"fmt"
	"strings"
	"time"

	"github.com/hateraku/bughunt/pkg/models"
	"github.com/hateraku/bughunt/pkg/vuln/vulnclass"
)

// PathHit è un percorso sondato dalla discovery con il suo esito.
type PathHit struct {
	Path   string
	Status int
}

// rule associa un percorso esposto a una classificazione.
type rule struct {
	path        string // match esatto sul Path sondato
	class       vulnclass.Class
	typ         string
	severity    string
	score       float64
	title       string
	remediation string
}

// rules: percorsi sensibili → classe/gravità. Le classi sono condivise
// (vulnclass): .env/.git/backup = esposizione file; admin/console/debug =
// misconfig; swagger/graphql = info disclosure.
var rules = []rule{
	{"/.env", vulnclass.SensitiveFileExposure, "secrets-exposure", models.SeverityCritical, 9.5,
		"File .env raggiungibile (possibili credenziali/segreti)",
		"Rimuovere il file dalla webroot e ruotare eventuali segreti esposti."},
	{"/.git", vulnclass.SensitiveFileExposure, "source-exposure", models.SeverityHigh, 9.0,
		"Repository .git raggiungibile (possibile disclosure del sorgente)",
		"Bloccare l'accesso a /.git dalla webroot."},
	{"/backup", vulnclass.SensitiveFileExposure, "backup-exposure", models.SeverityHigh, 7.5,
		"Percorso di backup raggiungibile",
		"Rimuovere i backup dalla webroot o proteggerli con autenticazione."},
	{"/config", vulnclass.SensitiveFileExposure, "config-exposure", models.SeverityMedium, 7.0,
		"Percorso di configurazione raggiungibile",
		"Proteggere i file di configurazione dall'accesso esterno."},
	{"/phpmyadmin", vulnclass.SecurityMisconfiguration, "exposed-admin", models.SeverityHigh, 8.5,
		"phpMyAdmin raggiungibile",
		"Limitare l'accesso (allowlist IP/auth) o rimuovere in produzione."},
	{"/adminer", vulnclass.SecurityMisconfiguration, "exposed-admin", models.SeverityHigh, 8.0,
		"Adminer raggiungibile",
		"Limitare l'accesso o rimuovere in produzione."},
	{"/console", vulnclass.SecurityMisconfiguration, "exposed-console", models.SeverityHigh, 7.5,
		"Console amministrativa raggiungibile",
		"Limitare l'accesso o disabilitare in produzione."},
	{"/debug", vulnclass.SecurityMisconfiguration, "debug-exposed", models.SeverityMedium, 6.0,
		"Endpoint di debug raggiungibile",
		"Disabilitare il debug in produzione."},
	{"/graphql", vulnclass.InfoDisclosure, "graphql-exposed", models.SeverityLow, 3.5,
		"Endpoint GraphQL raggiungibile",
		"Disabilitare l'introspection in produzione; verificare l'autorizzazione (test attivo su target autorizzato)."},
	{"/swagger", vulnclass.InfoDisclosure, "api-docs-exposed", models.SeverityLow, 3.0,
		"Documentazione API (Swagger) raggiungibile",
		"Limitare l'accesso alla documentazione in produzione."},
	{"/swagger-ui", vulnclass.InfoDisclosure, "api-docs-exposed", models.SeverityLow, 3.0,
		"Swagger UI raggiungibile",
		"Limitare l'accesso alla documentazione in produzione."},
	{"/swagger.json", vulnclass.InfoDisclosure, "api-docs-exposed", models.SeverityLow, 3.0,
		"Spec Swagger raggiungibile",
		"Limitare l'accesso alla specifica in produzione."},
	{"/openapi.json", vulnclass.InfoDisclosure, "api-docs-exposed", models.SeverityLow, 3.0,
		"Spec OpenAPI raggiungibile",
		"Limitare l'accesso alla specifica in produzione."},
	{"/api-docs", vulnclass.InfoDisclosure, "api-docs-exposed", models.SeverityLow, 3.0,
		"Documentazione API raggiungibile",
		"Limitare l'accesso alla documentazione in produzione."},
}

// Module è la famiglia exposure.
type Module struct{}

// New crea la famiglia.
func New() *Module { return &Module{} }

// Run classifica i percorsi esposti trovati dalla discovery e aggiunge i finding
// al ScanContext. Ritorna i percorsi segnalati.
func (m *Module) Run(baseURL string, hits []PathHit, sc *models.ScanContext) []string {
	status := make(map[string]int, len(hits))
	for _, h := range hits {
		status[h.Path] = h.Status
	}

	var fired []string
	for _, r := range rules {
		code, ok := status[r.path]
		if !ok {
			continue
		}
		sc.AddVulnerability(models.Vulnerability{
			Type:        r.typ,
			Severity:    r.severity,
			Score:       r.score,
			Title:       r.title,
			Description: r.class.Description,
			URL:         strings.TrimSuffix(baseURL, "/") + r.path,
			Evidence:    fmt.Sprintf("Percorso %s raggiungibile (HTTP %d via HEAD); contenuto non verificato", r.path, code),
			Remediation: r.remediation,
			FoundBy:     "exposure:" + r.typ,
			Metadata: map[string]string{
				"class":        r.class.ID,
				"cwe":          r.class.CWE,
				"status":       "unconfirmed",
				"verification": "confermare il contenuto con una GET (possibile catch-all 200 su SPA)",
			},
			DiscoveredAt: time.Now(),
		})
		fired = append(fired, r.path)
	}
	return fired
}
