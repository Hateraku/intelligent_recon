// Package react è la famiglia di detection per l'ecosistema React/Next.js.
//
// Principio di design: ogni Check rileva una SUPERFICIE/manifestazione durevole
// e punta a una CLASSE condivisa (pkg/vuln/vulnclass), non a una singola CVE. La
// classe (il meccanismo) non decade; le CVE note sono solo metadata (`KnownCVEs`)
// che si aggiornano come dati. La famiglia raggruppa per TECNOLOGIA perché i
// check condividono lo stesso fingerprint (Evidence), calcolato una volta sola.
//
// Tutti i Check sono PASSIVI: analizzano body/header già raccolti dal probe. La
// verifica attiva (conferma dell'exploit) è rimandata ai target autorizzati —
// vedi ROADMAP.
package react

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/hateraku/bughunt/pkg/models"
	"github.com/hateraku/bughunt/pkg/vuln/vulnclass"
)

// Evidence è il fingerprint condiviso calcolato UNA volta e passato a ogni Check.
type Evidence struct {
	URL         string
	IsNextJS    bool
	RSCEnabled  bool   // React Server Components / App Router attivo
	RSCEvidence string // perché RSCEnabled è true (traccia onesta della fonte)
	BuildID     string
	PoweredBy   string
	fingerprint []string // tracce raccolte (non usato direttamente nei finding)
}

// Check è una singola manifestazione che la famiglia sa cercare. Punta a una
// classe condivisa; il suo Detect è specifico della tecnologia.
type Check struct {
	ID            string          // identità durevole del check (la superficie)
	Class         vulnclass.Class // classe di vulnerabilità condivisa (il meccanismo)
	Type          string          // models vuln type (RCE, InfoDisclosure, ...)
	Severity      string
	Score         float64
	Title         string
	Manifestation string   // come la classe appare in QUESTA tecnologia
	Affected      string   // range versioni note (dato aggiornabile)
	Remediation   string
	KnownCVEs     []string // CVE note OGGI — metadata disposable
	Unconfirmed   bool     // true = indicatore passivo, non conferma dell'exploit
	Detect        func(ev *Evidence) (match bool, evidence string)
}

// toVuln costruisce il finding componendo classe condivisa + manifestazione.
func (c *Check) toVuln(url, evidence string) models.Vulnerability {
	md := map[string]string{
		"class": c.Class.ID,
		"cwe":   c.Class.CWE,
	}
	if c.Affected != "" {
		md["affected"] = c.Affected
	}
	if len(c.KnownCVEs) > 0 {
		md["known_cves"] = strings.Join(c.KnownCVEs, ", ")
	}
	if c.Unconfirmed {
		md["status"] = "unconfirmed"
		md["verification"] = "richiede test attivo su target autorizzato"
	} else {
		md["status"] = "confirmed"
	}

	description := c.Class.Description
	if c.Manifestation != "" {
		description += " " + c.Manifestation
	}

	return models.Vulnerability{
		Type:         c.Type,
		Severity:     c.Severity,
		Score:        c.Score,
		Title:        c.Title,
		Description:  description,
		URL:          url,
		Evidence:     evidence,
		Remediation:  c.Remediation,
		References:   c.KnownCVEs,
		FoundBy:      "react-family:" + c.ID,
		Metadata:     md,
		DiscoveredAt: time.Now(),
	}
}

// buildIDRe estrae il segmento dopo /_next/static/ dagli asset.
var buildIDRe = regexp.MustCompile(`/_next/static/([^/"']+)/`)

// reservedNextSegments sono i segmenti standard di /_next/static/ che NON sono
// buildId (così non estraiamo "chunks"/"immutable"/... come se lo fossero).
var reservedNextSegments = map[string]bool{
	"chunks": true, "css": true, "media": true, "immutable": true, "development": true,
}

// extractBuildID ritorna il primo segmento plausibile come buildId, saltando i
// segmenti riservati. "" se non trovato.
func extractBuildID(s string) string {
	for _, mm := range buildIDRe.FindAllStringSubmatch(s, -1) {
		if seg := mm[1]; !reservedNextSegments[strings.ToLower(seg)] {
			return seg
		}
	}
	return ""
}

// Module è la famiglia React/Next.js.
type Module struct{}

// New crea la famiglia.
func New() *Module { return &Module{} }

// Analyze costruisce l'Evidence condivisa dal materiale già raccolto (body/header
// del probe + URL scoperti dalla discovery): nessuna nuova richiesta di rete.
// Gli URL arricchiscono l'evidenza — es. un chunk App Router rivela RSC anche
// quando la home (SSG) non contiene il flight data.
func (m *Module) Analyze(url, body string, headers http.Header, urls []string) *Evidence {
	ev := &Evidence{URL: url}
	bodyLower := strings.ToLower(body)

	if pb := headers.Get("X-Powered-By"); strings.Contains(strings.ToLower(pb), "next.js") {
		ev.IsNextJS = true
		ev.PoweredBy = pb
		ev.fingerprint = append(ev.fingerprint, "X-Powered-By: "+pb)
	}
	for _, h := range []string{"X-Nextjs-Cache", "X-Nextjs-Prerender", "X-Nextjs-Stale-Time"} {
		if v := headers.Get(h); v != "" {
			ev.IsNextJS = true
			ev.fingerprint = append(ev.fingerprint, h+": "+v)
		}
	}
	if strings.Contains(bodyLower, "/_next/") || strings.Contains(body, "__NEXT_DATA__") {
		ev.IsNextJS = true
		ev.fingerprint = append(ev.fingerprint, "riferimenti /_next/ o __NEXT_DATA__ nel body")
	}
	if strings.Contains(body, "__next_f") || strings.Contains(body, "self.__next_f") {
		ev.IsNextJS = true
		ev.RSCEnabled = true
		ev.RSCEvidence = "flight data RSC (__next_f) presente nel body"
	}
	ev.BuildID = extractBuildID(body)

	// Evidenza aggiuntiva dagli URL scoperti (links + JS), senza nuove richieste.
	var nextURLSeen, appRouterSeen bool
	for _, u := range urls {
		lu := strings.ToLower(u)
		if strings.Contains(lu, "/_next/") {
			nextURLSeen = true
		}
		// I chunk sotto chunks/app/ indicano l'App Router → RSC attivo.
		if strings.Contains(lu, "/_next/static/chunks/app/") {
			appRouterSeen = true
		}
		if ev.BuildID == "" {
			ev.BuildID = extractBuildID(u)
		}
	}
	if nextURLSeen {
		ev.IsNextJS = true
		ev.fingerprint = append(ev.fingerprint, "risorse /_next/ tra gli URL scoperti")
	}
	if appRouterSeen {
		ev.IsNextJS = true
		ev.RSCEnabled = true
		if ev.RSCEvidence == "" {
			ev.RSCEvidence = "chunk App Router (/_next/static/chunks/app/) tra gli URL scoperti → RSC attivo"
		}
	}

	return ev
}

// Run esegue tutti i Check applicabili e aggiunge i finding al ScanContext.
// Ritorna gli ID dei check scattati.
func (m *Module) Run(ev *Evidence, sc *models.ScanContext) []string {
	if ev == nil || !ev.IsNextJS {
		return nil
	}
	sc.AddTechnology("Next.js")

	var fired []string
	for i := range Checks {
		c := &Checks[i]
		if ok, evidence := c.Detect(ev); ok {
			sc.AddVulnerability(c.toVuln(ev.URL, evidence))
			fired = append(fired, c.ID)
		}
	}
	return fired
}
