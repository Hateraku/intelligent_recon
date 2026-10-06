package anomaly

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	httpPkg "github.com/hateraku/bughunt/pkg/http"
	"github.com/hateraku/bughunt/pkg/models"
)

// fuzzHeaders è il set di header iniettati quando EnableHeaderInjection è attivo.
// Sono header comunemente riflessi/fidati lato server.
var fuzzHeaders = []string{"X-Forwarded-For", "X-Forwarded-Host", "Referer", "User-Agent"}

// Module handles anomaly detection through payload testing
type Module struct {
	client *http.Client
	config *Config
}

// Config for anomaly detection
type Config struct {
	EnableStacktrace      bool
	EnableErrorPage       bool
	EnableTimingAttack    bool
	EnableReflection      bool
	EnablePathInjection   bool
	EnableHeaderInjection bool
	TimeoutMs             int
	MaxPayloadsPerParam   int
}

// AnomalyResult contains detected anomalies
type AnomalyResult struct {
	URL         string
	Method      string
	Anomalies   []Anomaly
	RiskScore   float64
	TestedCount int
	DetectedAt  time.Time
}

// Anomaly represents a single detected anomaly
type Anomaly struct {
	Type        string  // "stacktrace", "error", "timing", "reflection", "sensitive_info"
	Class       string  // nome della classe di vulnerabilità (vulnclass); vuoto per euristiche
	CWE         string  // riferimento CWE della classe
	Severity    string  // "low", "medium", "high", "critical"
	Parameter   string
	Payload     string
	Evidence    string
	Description string
	RiskScore   float64
}

// ErrorPattern represents a known error pattern
type ErrorPattern struct {
	Pattern     *regexp.Regexp
	Technology  string
	Severity    string
	Description string
	RiskScore   float64
}

var (
	// SQL Error Patterns
	sqlErrorPatterns = []ErrorPattern{
		{
			Pattern:     regexp.MustCompile(`(?i)SQL syntax.*MySQL`),
			Technology:  "MySQL",
			Severity:    "high",
			Description: "MySQL SQL syntax error",
			RiskScore:   8.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)Warning.*mysql_`),
			Technology:  "MySQL",
			Severity:    "high",
			Description: "MySQL function warning",
			RiskScore:   7.5,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)pg_query\(\)|PostgreSQL.*ERROR`),
			Technology:  "PostgreSQL",
			Severity:    "high",
			Description: "PostgreSQL error",
			RiskScore:   8.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)Microsoft.*ODBC.*Driver|SQL Server`),
			Technology:  "MSSQL",
			Severity:    "high",
			Description: "Microsoft SQL Server error",
			RiskScore:   8.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)ORA-[0-9]{5}`),
			Technology:  "Oracle",
			Severity:    "high",
			Description: "Oracle database error",
			RiskScore:   8.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)SQLite.*error`),
			Technology:  "SQLite",
			Severity:    "high",
			Description: "SQLite error",
			RiskScore:   7.5,
		},
	}

	// Stacktrace Patterns
	stacktracePatterns = []ErrorPattern{
		{
			Pattern:     regexp.MustCompile(`(?i)Traceback \(most recent call last\)`),
			Technology:  "Python",
			Severity:    "medium",
			Description: "Python stacktrace",
			RiskScore:   6.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)at\s+[\w\.]+\([^)]+\.java:\d+\)`),
			Technology:  "Java",
			Severity:    "medium",
			Description: "Java stacktrace",
			RiskScore:   6.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)Fatal error:.*in /.*\.php on line`),
			Technology:  "PHP",
			Severity:    "medium",
			Description: "PHP fatal error with file path",
			RiskScore:   7.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)Warning:.*in /.*\.php on line`),
			Technology:  "PHP",
			Severity:    "low",
			Description: "PHP warning with file path",
			RiskScore:   5.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)Stack trace:|at\s+System\.`),
			Technology:  ".NET",
			Severity:    "medium",
			Description: ".NET stacktrace",
			RiskScore:   6.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)Error:.*at\s+.*\(.*:\d+:\d+\)`),
			Technology:  "Node.js",
			Severity:    "medium",
			Description: "Node.js error with stack",
			RiskScore:   6.0,
		},
	}

	// Sensitive Information Patterns
	sensitiveInfoPatterns = []ErrorPattern{
		{
			Pattern:     regexp.MustCompile(`(?i)/home/[\w/]+|/var/www/[\w/]+|C:\\\\[\w\\\\]+`),
			Technology:  "Generic",
			Severity:    "medium",
			Description: "Absolute file path disclosure",
			RiskScore:   5.5,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)root@|admin@[\w\.\-]+`),
			Technology:  "Generic",
			Severity:    "low",
			Description: "Email disclosure",
			RiskScore:   3.0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)database|DB_HOST|DB_USER|DB_PASS`),
			Technology:  "Generic",
			Severity:    "high",
			Description: "Database credentials exposure",
			RiskScore:   8.5,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)secret|token|api[_-]?key|password`),
			Technology:  "Generic",
			Severity:    "high",
			Description: "Potential secret/token disclosure",
			RiskScore:   8.0,
		},
	}

	// Common test payloads
	sqlPayloads = []string{
		"'",
		"\"",
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"' OR 1=1--",
		"admin'--",
		"' UNION SELECT NULL--",
		"1' AND 1=0 UNION SELECT NULL, NULL--",
	}

	xssPayloads = []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"'><script>alert(1)</script>",
		"\"><script>alert(1)</script>",
		"javascript:alert(1)",
	}

	pathTraversalPayloads = []string{
		"../",
		"..\\",
		"../../etc/passwd",
		"..\\..\\windows\\win.ini",
		"....//....//etc/passwd",
	}

	cmdInjectionPayloads = []string{
		"; ls",
		"| ls",
		"& ls",
		"`ls`",
		"$(ls)",
	}
)

// New creates a new anomaly detection module
func New(client *http.Client, config *Config) *Module {
	if config == nil {
		config = &Config{
			EnableStacktrace:      true,
			EnableErrorPage:       true,
			EnableTimingAttack:    true,
			EnableReflection:      true,
			EnablePathInjection:   true,
			EnableHeaderInjection: true,
			TimeoutMs:             5000,
			MaxPayloadsPerParam:   5,
		}
	}
	return &Module{
		client: client,
		config: config,
	}
}

// Detect performs anomaly detection on an endpoint
func (m *Module) Detect(ctx context.Context, endpoint *models.Endpoint) (*AnomalyResult, error) {
	result := &AnomalyResult{
		URL:        endpoint.URL,
		Method:     endpoint.Method,
		Anomalies:  []Anomaly{},
		DetectedAt: time.Now(),
	}

	if endpoint.Method == "" {
		endpoint.Method = "GET"
	}

	// Piano di detection costruito dalla config: tecniche (payload + detector)
	// e signature trasversali (pattern applicati a OGNI risposta).
	signatures, techniques := m.plan()

	// 1. Test baseline (richiesta normale, senza payload)
	_, baselineBody, baselineDur, err := m.sendOne(ctx, endpoint, injection{}, "")
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}

	// 2. Signature sulla risposta baseline (errori/stacktrace già presenti)
	runDetectors(signatures, respCtx{body: baselineBody}, result)

	// 3. Inietta i payload di ogni tecnica in ogni punto d'iniezione
	payloadLimit := m.config.MaxPayloadsPerParam
	if payloadLimit == 0 {
		payloadLimit = 5
	}
	for _, inj := range m.injectionPoints(endpoint) {
		for _, t := range techniques {
			for _, payload := range t.payloads[:min(payloadLimit, len(t.payloads))] {
				_, body, dur, err := m.sendOne(ctx, endpoint, inj, payload)
				if err != nil {
					continue
				}
				r := respCtx{
					label:    inj.label(),
					payload:  payload,
					body:     body,
					dur:      dur,
					baseBody: baselineBody,
					baseDur:  baselineDur,
				}
				// Signature trasversali + detector specifici della tecnica.
				runDetectors(signatures, r, result)
				runDetectors(t.detectors, r, result)
			}
		}
		result.TestedCount++
	}

	// 4. Risk score complessivo
	result.RiskScore = m.calculateRiskScore(result)

	return result, nil
}

// injection descrive un singolo punto d'iniezione di un endpoint.
type injection struct {
	kind string // "query", "body", "path", "header", "cookie"; "" = baseline (nessun payload)
	name string // nome parametro/header (non usato per "path")
	idx  int    // indice del segmento di path (solo per kind "path")
}

// label è l'etichetta leggibile usata come "Parameter" nelle anomalie.
func (inj injection) label() string {
	if inj.kind == "path" {
		return fmt.Sprintf("path[%d]", inj.idx)
	}
	return inj.kind + ":" + inj.name
}

// injectionPoints enumera tutti i punti su cui provare i payload per un endpoint.
func (m *Module) injectionPoints(ep *models.Endpoint) []injection {
	var pts []injection

	for _, p := range ep.Parameters {
		pts = append(pts, injection{kind: paramKind(p, ep.Method), name: p.Name})
	}

	if m.config.EnablePathInjection {
		if u, err := url.Parse(ep.URL); err == nil {
			segs := strings.Split(u.Path, "/")
			for i, s := range segs {
				if s != "" {
					pts = append(pts, injection{kind: "path", idx: i})
				}
			}
		}
	}

	if m.config.EnableHeaderInjection {
		for _, h := range fuzzHeaders {
			pts = append(pts, injection{kind: "header", name: h})
		}
	}

	return pts
}

// paramKind decide dove vive un parametro: usa il Type dichiarato,
// altrimenti ripiega su body per metodi non-GET, query per GET.
func paramKind(p models.Parameter, method string) string {
	switch strings.ToLower(p.Type) {
	case "query", "body", "header", "cookie":
		return strings.ToLower(p.Type)
	}
	if method != "" && !strings.EqualFold(method, "GET") {
		return "body"
	}
	return "query"
}

// sendOne costruisce e invia una richiesta applicando il payload al punto
// d'iniezione indicato (inj.kind == "" ⇒ richiesta baseline). Ritorna la
// risposta, il body e la durata reale della richiesta.
func (m *Module) sendOne(ctx context.Context, ep *models.Endpoint, inj injection, payload string) (*http.Response, string, time.Duration, error) {
	req, err := m.buildRequest(ctx, ep, inj, payload)
	if err != nil {
		return nil, "", 0, err
	}
	return m.doRequest(req)
}

// buildRequest crea la *http.Request con metodo, URL, body e header corretti.
// I parametri non iniettati mantengono il loro valore di baseline.
func (m *Module) buildRequest(ctx context.Context, ep *models.Endpoint, inj injection, payload string) (*http.Request, error) {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return nil, err
	}

	method := ep.Method
	if method == "" {
		method = "GET"
	}

	// Iniezione nel path: sostituisce il segmento (valore decodificato,
	// ri-codificato da u.String()).
	if inj.kind == "path" {
		segs := strings.Split(u.Path, "/")
		if inj.idx >= 0 && inj.idx < len(segs) {
			segs[inj.idx] = payload
		}
		u.Path = strings.Join(segs, "/")
		u.RawPath = ""
	}

	// Ripartizione dei parametri tra query string e body form.
	query := u.Query()
	form := url.Values{}
	for _, p := range ep.Parameters {
		val := p.Value
		if val == "" {
			val = "test"
		}
		switch paramKind(p, method) {
		case "query":
			if inj.kind == "query" && inj.name == p.Name {
				query.Set(p.Name, payload)
			} else if query.Get(p.Name) == "" {
				query.Set(p.Name, val)
			}
		case "body":
			if inj.kind == "body" && inj.name == p.Name {
				form.Set(p.Name, payload)
			} else {
				form.Set(p.Name, val)
			}
		}
	}
	u.RawQuery = query.Encode()

	// Se ci sono parametri body, inviali come form urlencoded (serve un metodo
	// con body: usa quello dell'endpoint se non è GET, altrimenti POST).
	var bodyReader io.Reader
	hasBody := len(form) > 0
	if hasBody {
		if strings.EqualFold(method, "GET") {
			method = "POST"
		}
		bodyReader = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	if hasBody {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", httpPkg.RandomUserAgent())

	// Parametri header/cookie (valori di baseline, payload se iniettato lì).
	for _, p := range ep.Parameters {
		val := p.Value
		if val == "" {
			val = "test"
		}
		switch paramKind(p, method) {
		case "header":
			if inj.kind == "header" && inj.name == p.Name {
				val = sanitizeHeader(payload)
			}
			req.Header.Set(p.Name, val)
		case "cookie":
			if inj.kind == "cookie" && inj.name == p.Name {
				val = sanitizeHeader(payload)
			}
			req.AddCookie(&http.Cookie{Name: p.Name, Value: val})
		}
	}

	// Iniezione negli header del set di default (anche se non è un parametro noto).
	if inj.kind == "header" {
		req.Header.Set(inj.name, sanitizeHeader(payload))
	}

	return req, nil
}

// doRequest esegue la richiesta e legge il body (limitato a 1 MB).
func (m *Module) doRequest(req *http.Request) (*http.Response, string, time.Duration, error) {
	client := m.client
	if client == nil {
		client = httpPkg.Client
	}

	start := time.Now()
	resp, err := client.Do(req)
	dur := time.Since(start)
	if err != nil {
		return nil, "", dur, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, string(body), dur, nil
}

// sanitizeHeader rimuove CR/LF dal valore per evitare header injection nel
// nostro stesso client (e richieste rifiutate da net/http).
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// calculateRiskScore calculates overall risk score
func (m *Module) calculateRiskScore(result *AnomalyResult) float64 {
	if len(result.Anomalies) == 0 {
		return 0.0
	}

	var totalScore float64
	for _, anomaly := range result.Anomalies {
		totalScore += anomaly.RiskScore
	}

	// Average but cap at 10.0
	avgScore := totalScore / float64(len(result.Anomalies))
	if avgScore > 10.0 {
		return 10.0
	}
	return avgScore
}

// ToScanContext adds anomalies to scan context
func (r *AnomalyResult) ToScanContext(sc *models.ScanContext) {
	for _, anomaly := range r.Anomalies {
		sc.AddAnomaly(models.Anomaly{
			Type:        anomaly.Type,
			Class:       anomaly.Class,
			CWE:         anomaly.CWE,
			Severity:    anomaly.Severity,
			URL:         r.URL,
			Method:      r.Method,
			Parameter:   anomaly.Parameter,
			Payload:     anomaly.Payload,
			Evidence:    anomaly.Evidence,
			Description: anomaly.Description,
			RiskScore:   anomaly.RiskScore,
			DetectedAt:  r.DetectedAt,
		})
	}
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
