package anomaly

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hateraku/bughunt/pkg/vuln/vulnclass"
)

// respCtx è il contesto passato a ogni detector: la risposta a un payload più
// la baseline, per i confronti differenziali (timing/size).
type respCtx struct {
	label    string // etichetta del punto d'iniezione
	payload  string
	body     string
	dur      time.Duration
	baseBody string
	baseDur  time.Duration
}

// detector esamina una risposta e ritorna le anomalie trovate (0 o più), già
// classificate con la loro vulnclass.
type detector func(r respCtx) []Anomaly

// technique è un'unità di fuzzing: un set di payload + i detector applicati alle
// sue risposte. Aggiungere una tecnica = aggiungere una voce in plan().
type technique struct {
	id        string
	payloads  []string
	detectors []detector
}

// runDetectors applica una lista di detector a una risposta e accumula gli esiti.
func runDetectors(dets []detector, r respCtx, result *AnomalyResult) {
	for _, d := range dets {
		result.Anomalies = append(result.Anomalies, d(r)...)
	}
}

// classified crea un'anomalia etichettata con una classe condivisa.
func classified(c vulnclass.Class, typ, severity string, score float64, r respCtx, evidence string) Anomaly {
	return Anomaly{
		Type:        typ,
		Class:       c.Name,
		CWE:         c.CWE,
		Severity:    severity,
		Parameter:   r.label,
		Payload:     r.payload,
		Evidence:    evidence,
		Description: c.Description,
		RiskScore:   score,
	}
}

// --- Detector specifici per tecnica --------------------------------------

// reflectionDetector: input riflesso non codificato → classe XSS.
func reflectionDetector(r respCtx) []Anomaly {
	if r.payload != "" && strings.Contains(r.body, r.payload) {
		return []Anomaly{classified(vulnclass.XSS, "reflection", "medium", 6.5, r,
			"Payload riflesso nella risposta senza codifica")}
	}
	return nil
}

// timingDetector: risposta nettamente più lenta della baseline → blind SQLi.
// Euristica conservativa (soglia assoluta + rapporto) contro il rumore di rete.
func timingDetector(r respCtx) []Anomaly {
	const absoluteThreshold = 3 * time.Second
	if r.dur <= absoluteThreshold {
		return nil
	}
	base := r.baseDur
	if base <= 0 {
		base = time.Millisecond
	}
	if r.dur < base*3 {
		return nil
	}
	ev := fmt.Sprintf("Tempo di risposta %v vs baseline %v", r.dur.Round(time.Millisecond), base.Round(time.Millisecond))
	return []Anomaly{classified(vulnclass.SQLInjection, "timing", "high", 7.0, r, ev)}
}

// passwdRe riconosce una riga di /etc/passwd (segnale forte di path traversal/LFI).
var passwdRe = regexp.MustCompile(`root:[^:]*:0:0:`)

// traversalDetector: firma di file di sistema nella risposta → path traversal.
func traversalDetector(r respCtx) []Anomaly {
	if passwdRe.MatchString(r.body) {
		return []Anomaly{classified(vulnclass.PathTraversal, "path_traversal", "high", 8.5, r,
			"Contenuto di /etc/passwd nella risposta")}
	}
	if strings.Contains(strings.ToLower(r.body), "for 16-bit app support") {
		return []Anomaly{classified(vulnclass.PathTraversal, "path_traversal", "high", 8.5, r,
			"Contenuto di win.ini nella risposta")}
	}
	return nil
}

// sizeDetector: variazione significativa di dimensione rispetto alla baseline.
// È un'EURISTICA (nessuna classe): da sola non prova una vulnerabilità.
func sizeDetector(r respCtx) []Anomaly {
	baseSize := len(r.baseBody)
	if baseSize == 0 {
		return nil // niente baseline con cui confrontare (evita divisione per zero)
	}
	diff := float64(abs(len(r.body)-baseSize)) / float64(baseSize)
	if diff <= 0.5 {
		return nil
	}
	return []Anomaly{{
		Type:        "size_anomaly",
		Severity:    "low",
		Parameter:   r.label,
		Payload:     r.payload,
		Evidence:    fmt.Sprintf("Dimensione risposta variata del %.1f%% (baseline: %d, test: %d)", diff*100, baseSize, len(r.body)),
		Description: "Variazione di dimensione della risposta significativa",
		RiskScore:   3.0,
	}}
}

// patternDetector costruisce un detector che cerca una lista di ErrorPattern e
// li etichetta con una classe condivisa, mantenendo severità/score del pattern.
func patternDetector(patterns []ErrorPattern, class vulnclass.Class, typ string, maxEvidence int) detector {
	return func(r respCtx) []Anomaly {
		var out []Anomaly
		for _, p := range patterns {
			if !p.Pattern.MatchString(r.body) {
				continue
			}
			ev := p.Pattern.FindString(r.body)
			if len(ev) > maxEvidence {
				ev = ev[:maxEvidence] + "..."
			}
			out = append(out, Anomaly{
				Type:        typ,
				Class:       class.Name,
				CWE:         class.CWE,
				Severity:    p.Severity,
				Parameter:   r.label,
				Payload:     r.payload,
				Evidence:    ev,
				Description: fmt.Sprintf("%s: %s", p.Technology, p.Description),
				RiskScore:   p.RiskScore,
			})
		}
		return out
	}
}

// plan costruisce, in base alla config, le signature trasversali (applicate a
// OGNI risposta, baseline inclusa) e le tecniche (payload + detector specifici).
func (m *Module) plan() (signatures []detector, techniques []technique) {
	// Signature trasversali: pattern di risposta, indipendenti dal payload.
	if m.config.EnableErrorPage {
		signatures = append(signatures, patternDetector(sqlErrorPatterns, vulnclass.SQLInjection, "sql_error", 200))
	}
	if m.config.EnableStacktrace {
		signatures = append(signatures, patternDetector(stacktracePatterns, vulnclass.InfoDisclosure, "stacktrace", 200))
	}
	// Info sensibili: sempre attivo (nessun toggle dedicato).
	signatures = append(signatures, patternDetector(sensitiveInfoPatterns, vulnclass.InfoDisclosure, "sensitive_info", 100))

	// Tecniche.
	sqli := technique{id: "sqli", payloads: sqlPayloads, detectors: []detector{sizeDetector}}
	if m.config.EnableTimingAttack {
		sqli.detectors = append([]detector{timingDetector}, sqli.detectors...)
	}
	techniques = append(techniques, sqli)

	if m.config.EnableReflection {
		techniques = append(techniques, technique{
			id:        "xss",
			payloads:  xssPayloads,
			detectors: []detector{reflectionDetector},
		})
	}

	techniques = append(techniques,
		technique{id: "path-traversal", payloads: pathTraversalPayloads, detectors: []detector{traversalDetector, sizeDetector}},
		technique{id: "cmd-injection", payloads: cmdInjectionPayloads, detectors: []detector{sizeDetector}},
	)

	return signatures, techniques
}
