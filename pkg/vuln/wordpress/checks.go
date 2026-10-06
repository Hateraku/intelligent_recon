package wordpress

import (
	"context"
	"fmt"
	"strings"

	"github.com/hateraku/bughunt/pkg/models"
	"github.com/hateraku/bughunt/pkg/vuln/vulnclass"
)

// Hit è l'esito di un Check scattato: i dettagli dinamici del finding.
type Hit struct {
	Title     string // sovrascrive Check.Title se valorizzato
	URL       string
	Evidence  string
	Status    string // "confirmed" (default) | "unconfirmed"
	Severity  string // sovrascrive Check.Severity se valorizzato
	Score     float64
	extraMeta map[string]string
}

// Check è un controllo WordPress: punta a una classe condivisa (vulnclass), può
// portare CVE note (KnownCVEs), e ha un Probe che — passivo o con GET mirate —
// ritorna un Hit se scatta.
type Check struct {
	ID          string
	Class       vulnclass.Class
	Severity    string
	Score       float64
	Title       string
	Remediation string
	KnownCVEs   []string // metadata, pronta per la correlazione CVE (Phase 3.1)
	Probe       func(ctx context.Context, base string, ev *Evidence, m *Module) *Hit
}

// toVuln costruisce il finding dal Check + l'Hit trovato.
func (c *Check) toVuln(h *Hit) models.Vulnerability {
	status := h.Status
	if status == "" {
		status = "confirmed"
	}
	severity := c.Severity
	if h.Severity != "" {
		severity = h.Severity
	}
	score := c.Score
	if h.Score != 0 {
		score = h.Score
	}
	title := c.Title
	if h.Title != "" {
		title = h.Title
	}

	md := map[string]string{"class": c.Class.ID, "cwe": c.Class.CWE, "status": status}
	if len(c.KnownCVEs) > 0 {
		md["known_cves"] = strings.Join(c.KnownCVEs, ", ")
	}
	for k, v := range h.extraMeta {
		md[k] = v
	}

	return models.Vulnerability{
		Type:         c.ID,
		Severity:     severity,
		Score:        score,
		Title:        title,
		Description:  c.Class.Description,
		URL:          h.URL,
		Evidence:     h.Evidence,
		Remediation:  c.Remediation,
		References:   c.KnownCVEs,
		FoundBy:      "wordpress:" + c.ID,
		Metadata:     md,
		DiscoveredAt: nowVuln(),
	}
}

// Checks: le superfici WordPress che la famiglia sa cercare. Ogni Check punta a
// una classe condivisa; KnownCVEs è pronta ma vuota (le CVE core/plugin sono
// version-specific → verranno dal feed di correlazione).
var Checks = []Check{
	// Passivo: versione WP core divulgata (meta generator).
	{
		ID: "version-disclosure", Class: vulnclass.InfoDisclosure,
		Severity: models.SeverityLow, Score: 3.0,
		Title:       "Versione di WordPress divulgata",
		Remediation: "Rimuovere il meta generator (remove_action('wp_head','wp_generator')).",
		Probe: func(ctx context.Context, base string, ev *Evidence, m *Module) *Hit {
			if ev.Version == "" {
				return nil
			}
			return &Hit{
				Title:     "Versione di WordPress divulgata: " + ev.Version,
				URL:       base,
				Evidence:  "meta generator espone WordPress " + ev.Version,
				extraMeta: map[string]string{"wp_version": ev.Version},
			}
		},
	},

	// Passivo: inventario plugin/temi enumerati.
	{
		ID: "component-enum", Class: vulnclass.InfoDisclosure,
		Severity: models.SeverityLow, Score: 3.5,
		Title:       "Plugin/temi WordPress enumerati",
		Remediation: "Le versioni esposte facilitano la correlazione con CVE note: tenere i componenti aggiornati.",
		Probe: func(ctx context.Context, base string, ev *Evidence, m *Module) *Hit {
			if len(ev.Plugins)+len(ev.Themes) == 0 {
				return nil
			}
			return &Hit{
				Title:    fmt.Sprintf("Enumerati %d plugin e %d temi WordPress", len(ev.Plugins), len(ev.Themes)),
				URL:      base,
				Evidence: summarizeComponents(ev.Plugins, ev.Themes),
			}
		},
	},

	// Attivo: /readme.html rivela spesso la versione esatta.
	{
		ID: "readme-exposed", Class: vulnclass.InfoDisclosure,
		Severity: models.SeverityLow, Score: 3.5,
		Title:       "readme.html di WordPress accessibile",
		Remediation: "Bloccare l'accesso a /readme.html.",
		Probe: func(ctx context.Context, base string, ev *Evidence, m *Module) *Hit {
			url := base + "/readme.html"
			code, body := m.get(ctx, url)
			if code != 200 || !strings.Contains(strings.ToLower(body), "wordpress") {
				return nil
			}
			ver := ev.Version
			if mm := reReadmeVer.FindStringSubmatch(body); len(mm) == 2 {
				ver = mm[1]
			}
			return &Hit{
				Title:    "readme.html di WordPress accessibile" + verSuffix(ver),
				URL:      url,
				Evidence: "GET /readme.html → 200 con contenuto WordPress",
			}
		},
	},

	// Attivo: /wp-json/wp/v2/users espone username/slug.
	{
		ID: "user-enumeration", Class: vulnclass.InfoDisclosure,
		Severity: models.SeverityMedium, Score: 5.5,
		Title:       "Enumerazione utenti via REST API",
		Remediation: "Limitare o disabilitare l'endpoint users della REST API per utenti non autenticati.",
		Probe: func(ctx context.Context, base string, ev *Evidence, m *Module) *Hit {
			url := base + "/wp-json/wp/v2/users"
			code, body := m.get(ctx, url)
			if code != 200 || !strings.Contains(body, "\"slug\"") {
				return nil
			}
			var slugs []string
			for _, mm := range reUserSlug.FindAllStringSubmatch(body, -1) {
				slugs = append(slugs, mm[1])
			}
			sample := slugs
			if len(sample) > 5 {
				sample = sample[:5]
			}
			return &Hit{
				Title:    fmt.Sprintf("Enumerazione utenti via REST API (%d utenti)", len(slugs)),
				URL:      url,
				Evidence: "slug esposti: " + strings.Join(sample, ", "),
			}
		},
	},

	// Attivo: /xmlrpc.php abilitato (amplificazione brute-force, SSRF pingback).
	{
		ID: "xmlrpc-enabled", Class: vulnclass.SecurityMisconfiguration,
		Severity: models.SeverityMedium, Score: 5.0,
		Title:       "xmlrpc.php abilitato",
		Remediation: "Disabilitare XML-RPC se non necessario (system.multicall brute-force, pingback SSRF).",
		Probe: func(ctx context.Context, base string, ev *Evidence, m *Module) *Hit {
			url := base + "/xmlrpc.php"
			code, body := m.get(ctx, url)
			if !strings.Contains(body, "XML-RPC server") && code != 405 {
				return nil
			}
			return &Hit{
				URL:      url,
				Evidence: fmt.Sprintf("GET /xmlrpc.php → HTTP %d (interfaccia XML-RPC attiva)", code),
			}
		},
	},

	// Attivo: /wp-content/debug.log esposto.
	{
		ID: "debug-log-exposed", Class: vulnclass.SensitiveFileExposure,
		Severity: models.SeverityHigh, Score: 7.5,
		Title:       "debug.log di WordPress esposto",
		Remediation: "Rimuovere il file e disabilitare WP_DEBUG_LOG in produzione.",
		Probe: func(ctx context.Context, base string, ev *Evidence, m *Module) *Hit {
			url := base + "/wp-content/debug.log"
			code, body := m.get(ctx, url)
			if code != 200 {
				return nil
			}
			low := strings.ToLower(body)
			if !strings.Contains(low, "php ") && !strings.Contains(low, "stack trace") && !strings.Contains(low, "warning") {
				return nil // probabile catch-all 200, non un vero log
			}
			return &Hit{
				URL:      url,
				Evidence: "GET /wp-content/debug.log → 200 con contenuto di log PHP",
			}
		},
	},

	// Attivo: backup di wp-config.php leggibili (credenziali DB).
	{
		ID: "wp-config-backup", Class: vulnclass.SensitiveFileExposure,
		Severity: models.SeverityCritical, Score: 9.5,
		Title:       "Backup di wp-config.php leggibile (credenziali DB)",
		Remediation: "Rimuovere immediatamente il backup e ruotare le credenziali del database.",
		Probe: func(ctx context.Context, base string, ev *Evidence, m *Module) *Hit {
			for _, suffix := range []string{".bak", "~", ".save", ".old", ".txt"} {
				url := base + "/wp-config.php" + suffix
				code, body := m.get(ctx, url)
				if code != 200 {
					continue
				}
				if !strings.Contains(body, "DB_") && !strings.Contains(body, "<?php") {
					continue // 200 senza contenuto di config → probabile catch-all
				}
				return &Hit{
					URL:      url,
					Evidence: "GET /wp-config.php" + suffix + " → 200 con direttive di configurazione",
				}
			}
			return nil
		},
	},

	// Attivo: directory listing su /wp-content/uploads/.
	{
		ID: "uploads-listing", Class: vulnclass.SecurityMisconfiguration,
		Severity: models.SeverityMedium, Score: 5.0,
		Title:       "Directory listing attivo su /wp-content/uploads/",
		Remediation: "Disabilitare l'autoindex del server per le directory dei contenuti.",
		Probe: func(ctx context.Context, base string, ev *Evidence, m *Module) *Hit {
			url := base + "/wp-content/uploads/"
			code, body := m.get(ctx, url)
			if code != 200 || !strings.Contains(strings.ToLower(body), "index of /") {
				return nil
			}
			return &Hit{
				URL:      url,
				Evidence: "GET /wp-content/uploads/ → pagina 'Index of /'",
			}
		},
	},

	// Attivo: /?author=1 → redirect a /author/<username>/ (user enumeration).
	// Vettore diverso dalla REST API: funziona anche con REST ristretta.
	{
		ID: "author-enumeration", Class: vulnclass.InfoDisclosure,
		Severity: models.SeverityMedium, Score: 5.5,
		Title:       "Enumerazione utenti via ?author=1",
		Remediation: "Disabilitare gli author archive o il redirect del parametro author.",
		Probe: func(ctx context.Context, base string, ev *Evidence, m *Module) *Hit {
			code, loc, body := m.getNoFollow(ctx, base+"/?author=1")
			user := ""
			if (code == 301 || code == 302) && loc != "" {
				if mm := reAuthor.FindStringSubmatch(loc); len(mm) == 2 {
					user = mm[1]
				}
			}
			if user == "" {
				if mm := reAuthor.FindStringSubmatch(body); len(mm) == 2 {
					user = mm[1]
				}
			}
			if user == "" {
				return nil
			}
			return &Hit{
				Title:    "Enumerazione utenti via ?author=1 (utente: " + user + ")",
				URL:      base + "/?author=1",
				Evidence: "redirect/canonical verso /author/" + user + "/",
			}
		},
	},

	// Attivo: /wp-json/ elenca i namespace REST registrati (i plugin ne espongono
	// di propri → segnale d'inventario e superficie d'attacco).
	{
		ID: "rest-namespace-discovery", Class: vulnclass.InfoDisclosure,
		Severity: models.SeverityLow, Score: 3.5,
		Title:       "Namespace REST API enumerati",
		Remediation: "Limitare l'esposizione dell'indice REST (/wp-json/) se non necessario.",
		Probe: func(ctx context.Context, base string, ev *Evidence, m *Module) *Hit {
			url := base + "/wp-json/"
			code, body := m.get(ctx, url)
			if code != 200 {
				return nil
			}
			sub := reNamespaces.FindStringSubmatch(body)
			if len(sub) != 2 {
				return nil
			}
			var ns []string
			for _, q := range reQuoted.FindAllStringSubmatch(sub[1], -1) {
				ns = append(ns, q[1])
			}
			if len(ns) == 0 {
				return nil
			}
			core := map[string]bool{"wp/v2": true, "oembed/1.0": true, "wp-site-health/v1": true, "wp-block-editor/v1": true}
			var nonCore []string
			for _, n := range ns {
				if !core[n] {
					nonCore = append(nonCore, n)
				}
			}
			title := fmt.Sprintf("Namespace REST API enumerati (%d)", len(ns))
			if len(nonCore) > 0 {
				title = fmt.Sprintf("Namespace REST API enumerati (%d, %d non-core)", len(ns), len(nonCore))
			}
			return &Hit{
				Title:    title,
				URL:      url,
				Evidence: "namespaces: " + strings.Join(ns, ", "),
			}
		},
	},
}
