// Package wordpress è una famiglia tech-specific APPROFONDITA per WordPress.
//
// Due livelli:
//   - PASSIVO (Analyze): rileva WP, versione (meta generator) ed enumera
//     plugin/temi dal body e dagli URL già raccolti — nessuna richiesta nuova.
//   - RICOGNIZIONE MIRATA: ogni controllo è un Check strutturato (vedi checks.go)
//     che punta a una classe condivisa (vulnclass) e può portare CVE note
//     (KnownCVEs). I check attivi fanno GET benigne su endpoint noti di WordPress
//     (readme, wp-json/users, xmlrpc, debug.log, backup di wp-config, uploads):
//     NON inviano payload, è ricognizione come la discovery coi path comuni.
//
// Le CVE versione-specifiche (core/plugin) non sono cablate: la versione e
// l'inventario plugin/temi sono la chiave che il feed CVE (Phase 3.1) userà.
package wordpress

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/hateraku/bughunt/pkg/models"
)

// Module è la famiglia WordPress.
type Module struct {
	client *http.Client
}

// New crea la famiglia con il client HTTP condiviso.
func New(client *http.Client) *Module { return &Module{client: client} }

// Evidence è il fingerprint WP passivo, calcolato una volta e passato ai Check.
type Evidence struct {
	IsWordPress bool
	Version     string            // versione WP core (meta generator)
	Plugins     map[string]string // slug → versione (vuota se ignota)
	Themes      map[string]string // slug → versione
	Signals     []string          // tracce di rilevamento
}

var (
	reGenerator  = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s*([0-9][0-9.]*)`)
	rePluginVer  = regexp.MustCompile(`/wp-content/plugins/([a-zA-Z0-9._-]+)/[^"'\s]*?[?&]ver=([0-9][0-9.]+)`)
	rePluginSlug = regexp.MustCompile(`/wp-content/plugins/([a-zA-Z0-9._-]+)`)
	reThemeVer   = regexp.MustCompile(`/wp-content/themes/([a-zA-Z0-9._-]+)/[^"'\s]*?[?&]ver=([0-9][0-9.]+)`)
	reThemeSlug  = regexp.MustCompile(`/wp-content/themes/([a-zA-Z0-9._-]+)`)
	reUserSlug   = regexp.MustCompile(`"slug"\s*:\s*"([^"]+)"`)
	reReadmeVer  = regexp.MustCompile(`(?i)Version\s+([0-9][0-9.]+)`)
	reAuthor     = regexp.MustCompile(`/author/([^/"'<>\s]+)/?`)
	reNamespaces = regexp.MustCompile(`"namespaces"\s*:\s*\[([^\]]*)\]`)
	reQuoted     = regexp.MustCompile(`"([^"]+)"`)
)

// Analyze rileva WordPress in modo PASSIVO da body, header e URL scoperti.
func (m *Module) Analyze(body string, headers http.Header, urls []string) *Evidence {
	ev := &Evidence{Plugins: map[string]string{}, Themes: map[string]string{}}
	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, "/wp-content/") || strings.Contains(bodyLower, "/wp-includes/") {
		ev.IsWordPress = true
		ev.Signals = append(ev.Signals, "percorsi /wp-content/ o /wp-includes/ nel body")
	}
	if headers.Get("X-Pingback") != "" {
		ev.IsWordPress = true
		ev.Signals = append(ev.Signals, "header X-Pingback: "+headers.Get("X-Pingback"))
	}
	if strings.Contains(bodyLower, "/wp-json") {
		ev.IsWordPress = true
		ev.Signals = append(ev.Signals, "riferimento /wp-json (REST API)")
	}
	if mm := reGenerator.FindStringSubmatch(body); len(mm) == 2 {
		ev.IsWordPress = true
		ev.Version = mm[1]
		ev.Signals = append(ev.Signals, "meta generator: WordPress "+mm[1])
	}

	corpus := body + "\n" + strings.Join(urls, "\n")
	collect(corpus, rePluginVer, rePluginSlug, ev.Plugins)
	collect(corpus, reThemeVer, reThemeSlug, ev.Themes)
	if len(ev.Plugins) > 0 || len(ev.Themes) > 0 {
		ev.IsWordPress = true
	}

	return ev
}

// collect popola slug→versione: prima i match con versione, poi gli slug nudi.
func collect(corpus string, reVer, reSlug *regexp.Regexp, out map[string]string) {
	for _, mm := range reVer.FindAllStringSubmatch(corpus, -1) {
		out[mm[1]] = mm[2]
	}
	for _, mm := range reSlug.FindAllStringSubmatch(corpus, -1) {
		if _, ok := out[mm[1]]; !ok {
			out[mm[1]] = ""
		}
	}
}

// Run esegue tutti i Check della famiglia e aggiunge i finding al ScanContext.
// Ritorna gli ID dei check scattati. Non fa nulla se il target non è WordPress.
func (m *Module) Run(ctx context.Context, baseURL string, ev *Evidence, sc *models.ScanContext) []string {
	if ev == nil || !ev.IsWordPress {
		return nil
	}
	sc.AddTechnology("WordPress")

	// Inventario come tecnologie (non vulnerabilità): utile per correlazione CVE.
	for slug, ver := range ev.Plugins {
		sc.AddTechnology("WP plugin: " + slug + verSuffix(ver))
	}
	for slug, ver := range ev.Themes {
		sc.AddTechnology("WP theme: " + slug + verSuffix(ver))
	}

	base := strings.TrimSuffix(baseURL, "/")

	var fired []string
	for i := range Checks {
		c := &Checks[i]
		hit := c.Probe(ctx, base, ev, m)
		if hit == nil {
			continue
		}
		sc.AddVulnerability(c.toVuln(hit))
		fired = append(fired, c.ID)
	}
	return fired
}

// get esegue una GET benigna (segue i redirect) e ritorna status + body (64KB).
func (m *Module) get(ctx context.Context, url string) (int, string) {
	client := m.client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BugHunt/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, string(b)
}

// getNoFollow esegue una GET SENZA seguire i redirect e ritorna status, header
// Location e body: serve a leggere il target del redirect (es. ?author=1 →
// /author/<username>/), che altrimenti verrebbe seguito e perso.
func (m *Module) getNoFollow(ctx context.Context, url string) (int, string, string) {
	var transport http.RoundTripper = http.DefaultTransport
	if m.client != nil && m.client.Transport != nil {
		transport = m.client.Transport
	}
	client := &http.Client{
		Transport:     transport,
		Timeout:       7 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, "", ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BugHunt/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	return resp.StatusCode, resp.Header.Get("Location"), string(b)
}

func verSuffix(ver string) string {
	if ver == "" {
		return ""
	}
	return " " + ver
}

func summarizeComponents(plugins, themes map[string]string) string {
	var parts []string
	for slug, ver := range plugins {
		parts = append(parts, "plugin "+slug+verSuffix(ver))
	}
	for slug, ver := range themes {
		parts = append(parts, "theme "+slug+verSuffix(ver))
	}
	s := strings.Join(parts, "; ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// nowVuln helper usato da Check.toVuln (timestamp).
func nowVuln() time.Time { return time.Now() }
