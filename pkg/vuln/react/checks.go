package react

import (
	"strings"

	"github.com/hateraku/bughunt/pkg/models"
	"github.com/hateraku/bughunt/pkg/vuln/vulnclass"
)

// Checks elenca le superfici che la famiglia React/Next sa cercare. Ogni Check
// punta a una CLASSE condivisa (vulnclass) e porta le CVE note come metadata.
var Checks = []Check{
	// Classe condivisa: deserializzazione non fidata (CWE-502).
	// Manifestazione React: il flight protocol dei React Server Components.
	// Un futuro check Java per ObjectInputStream punterà alla STESSA classe.
	{
		ID:       "rsc-deserialization-surface",
		Class:    vulnclass.UntrustedDeserialization,
		Type:     "RCE",
		Severity: models.SeverityCritical,
		Score:    10.0,
		Title:    "Superficie di deserializzazione RSC esposta (potenziale RCE, non confermata)",
		Manifestation: "In React/Next l'App Router espone il flight protocol dei React Server " +
			"Components: il server deserializza payload provenienti dal client (catena React2Shell: " +
			"deserializzazione → prototype pollution → RCE). Indicatore PASSIVO di esposizione, non " +
			"conferma: lo sfruttamento dipende dalle versioni e va verificato attivamente solo su " +
			"target autorizzati.",
		Affected:    "React 19.x / Next.js 15.x–16.x (App Router) con RSC",
		Remediation: "Aggiornare React e Next.js alle versioni corrette; consultare gli advisory ufficiali.",
		KnownCVEs:   []string{"CVE-2025-55182", "CVE-2025-66478"},
		Unconfirmed: true,
		Detect: func(ev *Evidence) (bool, string) {
			if ev.RSCEnabled {
				return true, ev.RSCEvidence // evidenza onesta sulla fonte del segnale
			}
			return false, ""
		},
	},

	// Classe condivisa: divulgazione di informazioni (CWE-200).
	// Manifestazione React/Next: header X-Powered-By e/o buildId esposti.
	{
		ID:            "tech-version-disclosure",
		Class:         vulnclass.InfoDisclosure,
		Type:          "InfoDisclosure",
		Severity:      models.SeverityLow,
		Score:         2.5,
		Title:         "Divulgazione di framework/build Next.js",
		Manifestation: "L'app rivela il framework (X-Powered-By) e/o l'identificativo di build Next.js.",
		Remediation:   "Rimuovere/oscurare l'header X-Powered-By ed evitare l'esposizione non necessaria del buildId.",
		Unconfirmed:   false,
		Detect: func(ev *Evidence) (bool, string) {
			var parts []string
			if ev.PoweredBy != "" {
				parts = append(parts, "X-Powered-By: "+ev.PoweredBy)
			}
			if ev.BuildID != "" {
				parts = append(parts, "buildId: "+ev.BuildID)
			}
			if len(parts) == 0 {
				return false, ""
			}
			return true, strings.Join(parts, "; ")
		},
	},
}
