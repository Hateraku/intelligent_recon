// bughunt è l'orchestratore end-to-end del framework.
//
// Collega i moduli core (DNS → HTTP probe → fingerprint → discovery → anomaly)
// facendo passare un unico ScanContext condiviso tra tutti gli stadi, così che
// ogni modulo arricchisca l'intelligence accumulata sul target.
//
// Esempio:
//
//	bughunt example.com test.example.org
//	bughunt -list targets.txt -depth 3 -json report.json
//	bughunt -active example.com        # abilita i test attivi (anomaly detection)
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hateraku/bughunt/configs/workflows"
	"github.com/hateraku/bughunt/internal/workflow"
	"github.com/hateraku/bughunt/pkg/core/anomaly"
	"github.com/hateraku/bughunt/pkg/core/discovery"
	"github.com/hateraku/bughunt/pkg/core/dns"
	"github.com/hateraku/bughunt/pkg/core/fingerprint"
	httpPkg "github.com/hateraku/bughunt/pkg/http"
	"github.com/hateraku/bughunt/pkg/models"
	"github.com/hateraku/bughunt/pkg/report"
	"github.com/hateraku/bughunt/pkg/vuln/exposure"
	"github.com/hateraku/bughunt/pkg/vuln/react"
	"github.com/hateraku/bughunt/pkg/vuln/secheaders"
	"github.com/hateraku/bughunt/pkg/vuln/secrets"
	"github.com/hateraku/bughunt/pkg/vuln/wordpress"
)

type options struct {
	listFile    string
	depth       int
	concurrency int
	timeout     time.Duration
	active      bool
	maxAnomaly  int
	jsonPath    string
	htmlPath    string
	mdPath      string
	workflow    string
}

func main() {
	opts := &options{}

	flag.StringVar(&opts.listFile, "list", "", "file con un target per riga (in alternativa agli argomenti posizionali)")
	flag.IntVar(&opts.depth, "depth", 2, "profondità di crawling per il modulo discovery")
	flag.IntVar(&opts.concurrency, "c", 4, "numero di target processati in parallelo")
	flag.DurationVar(&opts.timeout, "timeout", 60*time.Second, "timeout complessivo per singolo target")
	flag.BoolVar(&opts.active, "active", false, "abilita i test attivi (anomaly detection: invia payload al target)")
	flag.IntVar(&opts.maxAnomaly, "max-anomaly", 10, "numero massimo di endpoint su cui eseguire anomaly detection")
	flag.StringVar(&opts.jsonPath, "json", "", "scrive il report finale in JSON sul percorso indicato ('-' per stdout)")
	flag.StringVar(&opts.htmlPath, "html", "", "scrive un report HTML sul percorso indicato")
	flag.StringVar(&opts.mdPath, "md", "", "scrive un report Markdown sul percorso indicato")
	flag.StringVar(&opts.workflow, "workflow", "full", "workflow da eseguire: nome preset (full, quick, api) o percorso a un file .yaml")
	flag.Parse()

	targets, err := collectTargets(flag.Args(), opts.listFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "❌ nessun target fornito. Uso: bughunt [flag] <dominio> [dominio...]")
		flag.Usage()
		os.Exit(1)
	}

	spec, src, err := loadWorkflow(opts.workflow)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ workflow %q: %v\n", opts.workflow, err)
		os.Exit(1)
	}

	scanCtx := models.NewScanContext()

	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("🎯 BugHunt — scansione di %d target (concorrenza %d, active=%v)\n", len(targets), opts.concurrency, opts.active)
	fmt.Printf("🧩 workflow: %s — %s  [%s]\n", spec.Name, spec.Description, src)
	fmt.Println(strings.Repeat("=", 70))

	runWorkerPool(targets, opts, spec, scanCtx)

	printSummary(scanCtx)

	if opts.jsonPath != "" {
		if err := writeJSON(scanCtx, opts.jsonPath); err != nil {
			fmt.Fprintf(os.Stderr, "❌ errore scrittura JSON: %v\n", err)
			os.Exit(1)
		}
		if opts.jsonPath != "-" {
			fmt.Printf("\n💾 Report JSON scritto in %s\n", opts.jsonPath)
		}
	}
	if opts.htmlPath != "" {
		if err := os.WriteFile(opts.htmlPath, []byte(report.HTML(scanCtx)), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "❌ errore scrittura HTML: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("💾 Report HTML scritto in %s\n", opts.htmlPath)
	}
	if opts.mdPath != "" {
		if err := os.WriteFile(opts.mdPath, []byte(report.Markdown(scanCtx)), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "❌ errore scrittura Markdown: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("💾 Report Markdown scritto in %s\n", opts.mdPath)
	}
}

// loadWorkflow carica uno spec da un preset integrato (nome) o da un file .yaml.
func loadWorkflow(nameOrPath string) (*workflow.WorkflowSpec, string, error) {
	var data []byte
	var src string

	isPath := strings.ContainsRune(nameOrPath, '/') ||
		strings.HasSuffix(nameOrPath, ".yaml") ||
		strings.HasSuffix(nameOrPath, ".yml")

	if isPath {
		b, err := os.ReadFile(nameOrPath)
		if err != nil {
			return nil, "", err
		}
		data = b
		src = "file " + nameOrPath
	} else {
		b, err := workflows.FS.ReadFile(nameOrPath + ".yaml")
		if err != nil {
			return nil, "", fmt.Errorf("preset sconosciuto (disponibili: full, quick, api; oppure un percorso .yaml)")
		}
		data = b
		src = "preset integrato"
	}

	spec, err := workflow.LoadSpec(data)
	if err != nil {
		return nil, "", err
	}
	return spec, src, nil
}

// collectTargets raccoglie i target dagli argomenti e/o da un file.
func collectTargets(args []string, listFile string) ([]string, error) {
	seen := make(map[string]bool)
	var targets []string

	add := func(raw string) {
		t := normalizeTarget(raw)
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		targets = append(targets, t)
	}

	for _, a := range args {
		add(a)
	}

	if listFile != "" {
		f, err := os.Open(listFile)
		if err != nil {
			return nil, fmt.Errorf("impossibile aprire -list %q: %w", listFile, err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			add(line)
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("errore lettura -list: %w", err)
		}
	}

	return targets, nil
}

// normalizeTarget rimuove schema e path, lasciando il solo hostname:
// i moduli (dns, probe) si aspettano un dominio nudo.
func normalizeTarget(raw string) string {
	t := strings.TrimSpace(raw)
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimPrefix(t, "http://")
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	return strings.TrimSpace(t)
}

// runWorkerPool processa i target in parallelo con un pool di worker limitato.
func runWorkerPool(targets []string, opts *options, spec *workflow.WorkflowSpec, scanCtx *models.ScanContext) {
	jobs := make(chan string)
	var wg sync.WaitGroup

	workers := opts.concurrency
	if workers < 1 {
		workers = 1
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				scanTarget(domain, opts, spec, scanCtx)
			}
		}()
	}

	for _, t := range targets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()
}

// buildCtx raccoglie lo stato condiviso tra i nodi di un singolo target:
// opzioni, dominio e handoff tipizzato prodotto dal probe.
type buildCtx struct {
	domain         string
	opts           *options
	probeRes       *httpPkg.ProbeResult
	baseURL        string
	discoveredURLs []string           // links + JS + API dalla discovery (evidenza per le famiglie)
	exposedPaths   []exposure.PathHit // percorsi sensibili sondati dalla discovery (Found)
}

// moduleRegistry mappa i nomi dei moduli (usati nei file di workflow) alle loro
// RunFunc, legate allo stato del target corrente tramite bc.
func moduleRegistry(bc *buildCtx) map[string]workflow.RunFunc {
	return map[string]workflow.RunFunc{
		// DNS — radice, indipendente dal probe.
		"dns": func(ctx context.Context, sc *models.ScanContext) error {
			res, err := dns.New().Lookup(ctx, bc.domain)
			if err != nil {
				return err
			}
			mergeDNS(sc, res)
			ips := append(append([]string{}, res.ARecords...), res.AAAARecords...)
			fmt.Printf("   🌐 [%s] DNS: %d IP, cloud=%s\n", bc.domain, len(ips), emptyDash(res.CloudProvider))
			return nil
		},

		// HTTP probe — radice; produce l'endpoint e il materiale per gli stadi dopo.
		"probe": func(ctx context.Context, sc *models.ScanContext) error {
			pr, err := httpPkg.ProbeWithContext(ctx, bc.domain)
			if err != nil {
				return err
			}
			bc.probeRes = pr
			bc.baseURL = pr.FinalURL
			if bc.baseURL == "" {
				bc.baseURL = pr.URL
			}
			pr.ToScanContext(sc)
			fmt.Printf("   📡 [%s] HTTP: %d %s (%s)\n", bc.domain, pr.StatusCode, emptyDash(pr.Title), pr.FinalURL)
			return nil
		},

		// Fingerprint — richiede il probe (body + headers).
		"fingerprint": func(ctx context.Context, sc *models.ScanContext) error {
			fr := fingerprint.New(httpPkg.Client).Fingerprint(ctx, bc.baseURL, bc.probeRes.Body, bc.probeRes.Headers)
			fr.ToScanContext(sc)
			return nil
		},

		// Discovery — richiede il probe (URL finale).
		"discovery": func(ctx context.Context, sc *models.ScanContext) error {
			disc := discovery.New(httpPkg.Client, &discovery.Config{
				MaxDepth:  bc.opts.depth,
				UserAgent: httpPkg.RandomUserAgent(),
			})
			res, err := disc.Discover(ctx, bc.baseURL)
			if err != nil {
				return err
			}
			res.ToScanContext(sc)
			// Conserva gli URL scoperti come evidenza per le famiglie (es. react).
			bc.discoveredURLs = append(append(append([]string{}, res.Links...), res.JSFiles...), res.APIEndpoints...)
			// Conserva i percorsi sensibili raggiungibili per la famiglia exposure.
			for _, p := range res.CommonPaths {
				if p.Found {
					bc.exposedPaths = append(bc.exposedPaths, exposure.PathHit{Path: p.Path, Status: p.StatusCode})
				}
			}
			fmt.Printf("   🔎 [%s] discovery: %d link, %d form, %d API, %d JS\n",
				bc.domain, len(res.Links), len(res.Forms), len(res.APIEndpoints), len(res.JSFiles))
			return nil
		},

		// Anomaly — richiede la discovery (endpoint con parametri).
		"anomaly": func(ctx context.Context, sc *models.ScanContext) error {
			runAnomaly(ctx, sc, bc.opts.maxAnomaly)
			return nil
		},

		// Famiglia React/Next.js — passiva, analizza il materiale del probe.
		// Pensata per 'when: tech:Next.js' (parte se il fingerprint trova Next.js).
		"react-family": func(ctx context.Context, sc *models.ScanContext) error {
			if bc.probeRes == nil {
				return nil
			}
			fam := react.New()
			ev := fam.Analyze(bc.baseURL, bc.probeRes.Body, bc.probeRes.Headers, bc.discoveredURLs)
			fired := fam.Run(ev, sc)
			if ev.IsNextJS {
				fmt.Printf("   🧬 [%s] react-family: Next.js — check scattati: %v\n", bc.domain, fired)
			} else {
				fmt.Printf("   🧬 [%s] react-family: nessuna superficie React/Next\n", bc.domain)
			}
			return nil
		},

		// Famiglia exposure — cross-tech, passiva: classifica i percorsi sensibili
		// che la discovery ha trovato raggiungibili (/.env, /.git, admin, ...).
		"exposure": func(ctx context.Context, sc *models.ScanContext) error {
			fired := exposure.New().Run(bc.baseURL, bc.exposedPaths, sc)
			if len(fired) > 0 {
				fmt.Printf("   🔓 [%s] exposure: %d percorsi sensibili raggiungibili %v\n", bc.domain, len(fired), fired)
			} else {
				fmt.Printf("   🔓 [%s] exposure: nessun percorso sensibile raggiungibile\n", bc.domain)
			}
			return nil
		},

		// Famiglia security-headers — cross-tech, passiva: header di sicurezza
		// e flag dei cookie dalla risposta del probe.
		"security-headers": func(ctx context.Context, sc *models.ScanContext) error {
			if bc.probeRes == nil {
				return nil
			}
			fired := secheaders.New().Run(bc.baseURL, bc.probeRes.IsHTTPS, bc.probeRes.Headers, bc.probeRes.Cookies, sc)
			fmt.Printf("   🛡️  [%s] security-headers: %d problemi\n", bc.domain, len(fired))
			return nil
		},

		// Famiglia secrets — cross-tech, passiva: segreti nel body (redatti).
		"secrets": func(ctx context.Context, sc *models.ScanContext) error {
			if bc.probeRes == nil {
				return nil
			}
			fired := secrets.New().Run(bc.baseURL, bc.probeRes.Body, sc)
			if len(fired) > 0 {
				fmt.Printf("   🔑 [%s] secrets: %d potenziali segreti %v\n", bc.domain, len(fired), fired)
			} else {
				fmt.Printf("   🔑 [%s] secrets: nessuno\n", bc.domain)
			}
			return nil
		},

		// Famiglia WordPress — tech-specific, approfondita: detection passiva +
		// ricognizione mirata (GET benigne) su endpoint noti di WordPress.
		"wordpress": func(ctx context.Context, sc *models.ScanContext) error {
			if bc.probeRes == nil {
				return nil
			}
			wp := wordpress.New(httpPkg.Client)
			ev := wp.Analyze(bc.probeRes.Body, bc.probeRes.Headers, bc.discoveredURLs)
			if !ev.IsWordPress {
				fmt.Printf("   🇼  [%s] wordpress: non rilevato\n", bc.domain)
				return nil
			}
			fired := wp.Run(ctx, bc.baseURL, ev, sc)
			fmt.Printf("   🇼  [%s] wordpress: v%s, %d plugin, %d temi — check: %v\n",
				bc.domain, emptyDash(ev.Version), len(ev.Plugins), len(ev.Themes), fired)
			return nil
		},
	}
}

// condResolver traduce la stringa 'when' di uno step YAML in una condizione.
// Supporta "active" (flag -active) e "tech:<nome>" (tecnologia già rilevata).
func condResolver(bc *buildCtx) workflow.CondResolver {
	return func(expr string) (workflow.CondFunc, error) {
		switch {
		case expr == "active":
			return func(sc *models.ScanContext) bool { return bc.opts.active }, nil
		case strings.HasPrefix(expr, "tech:"):
			name := strings.TrimPrefix(expr, "tech:")
			return func(sc *models.ScanContext) bool { return sc.HasTechnology(name) }, nil
		default:
			return nil, fmt.Errorf("condizione sconosciuta %q (supportate: active, tech:<nome>)", expr)
		}
	}
}

// scanTarget costruisce il grafo dei moduli a partire dallo spec del workflow e
// lo esegue tramite il workflow engine, accumulando tutto nel ScanContext.
func scanTarget(domain string, opts *options, spec *workflow.WorkflowSpec, scanCtx *models.ScanContext) {
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	fmt.Printf("\n▶️  %s\n", domain)

	bc := &buildCtx{domain: domain, opts: opts}
	g, err := workflow.BuildGraph(spec, moduleRegistry(bc), condResolver(bc))
	if err != nil {
		fmt.Printf("   ❌ [%s] workflow non valido: %v\n", domain, err)
		return
	}

	exec := &workflow.Executor{Concurrency: 4}
	results, err := exec.Run(ctx, g, scanCtx)
	if err != nil {
		fmt.Printf("   ❌ [%s] errore grafo: %v\n", domain, err)
		return
	}

	// Riporta fallimenti e skip (i nodi riusciti stampano già la propria riga).
	for _, r := range results {
		switch r.Status {
		case workflow.StatusFailed:
			fmt.Printf("   ⚠️  [%s] %s fallito: %v\n", domain, r.Node, r.Err)
		case workflow.StatusSkipped:
			if r.Node == "anomaly" && !opts.active {
				continue // atteso: anomaly disattivato senza -active
			}
			fmt.Printf("   ⏭️  [%s] %s saltato (%s)\n", domain, r.Node, r.Reason)
		}
	}
}

// mergeDNS riversa un DNSResult nel ScanContext condiviso.
// (DNSResult.ToScanContext crea un context nuovo, inadatto alla pipeline.)
func mergeDNS(scanCtx *models.ScanContext, r *dns.DNSResult) {
	scanCtx.AddTarget(models.Target{
		Domain:    r.Domain,
		IPs:       append(append([]string{}, r.ARecords...), r.AAAARecords...),
		Scope:     "in-scope",
		CreatedAt: time.Now(),
	})

	if r.CloudProvider != "" && r.CloudProvider != "Unknown" {
		scanCtx.AddCloudProvider(r.CloudProvider)
	}

	if r.AXFRPossible {
		scanCtx.AddAnomaly(models.Anomaly{
			Type:        "dns_misconfiguration",
			URL:         r.Domain,
			Description: "Zone Transfer (AXFR) is possible",
			Severity:    models.SeverityHigh,
			DetectedAt:  time.Now(),
		})
	}
	if r.IsWildcard {
		scanCtx.AddAnomaly(models.Anomaly{
			Type:        "dns_wildcard",
			URL:         r.Domain,
			Description: "Wildcard DNS detected",
			Severity:    models.SeverityInfo,
			DetectedAt:  time.Now(),
		})
	}
}

// runAnomaly esegue l'anomaly detection sugli endpoint con parametri
// già scoperti e presenti nel ScanContext, fino a un massimo di `max`.
func runAnomaly(ctx context.Context, scanCtx *models.ScanContext, max int) {
	module := anomaly.New(httpPkg.Client, &anomaly.Config{
		EnableStacktrace:      true,
		EnableErrorPage:       true,
		EnableTimingAttack:    true,
		EnableReflection:      true,
		EnablePathInjection:   true,
		EnableHeaderInjection: true,
		TimeoutMs:             5000,
		MaxPayloadsPerParam:   3,
	})

	candidates := endpointsWithParams(scanCtx, max)
	if len(candidates) == 0 {
		fmt.Printf("   🧪 anomaly: nessun endpoint con parametri da testare\n")
		return
	}

	tested := 0
	for i := range candidates {
		ep := candidates[i]
		res, err := module.Detect(ctx, &ep)
		if err != nil {
			continue
		}
		res.ToScanContext(scanCtx)
		tested++
	}
	fmt.Printf("   🧪 anomaly: testati %d endpoint\n", tested)
}

// endpointsWithParams ritorna fino a `max` endpoint che hanno almeno un
// parametro (gli unici su cui l'anomaly detection ha senso).
func endpointsWithParams(scanCtx *models.ScanContext, max int) []models.Endpoint {
	all := scanCtx.GetEndpointsByRisk()
	var out []models.Endpoint
	for _, ep := range all {
		if len(ep.Parameters) == 0 {
			continue
		}
		out = append(out, ep)
		if len(out) >= max {
			break
		}
	}
	return out
}

// printSummary stampa il riepilogo finale dell'intelligence raccolta.
func printSummary(scanCtx *models.ScanContext) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("📊 Riepilogo scansione")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Target:          %d\n", len(scanCtx.Targets))
	fmt.Printf("Endpoint:        %d\n", len(scanCtx.Endpoints))
	fmt.Printf("Tecnologie:      %d  %s\n", len(scanCtx.Technologies), strings.Join(scanCtx.Technologies, ", "))
	fmt.Printf("Cloud provider:  %d  %s\n", len(scanCtx.CloudProviders), strings.Join(scanCtx.CloudProviders, ", "))
	fmt.Printf("Anomalie:        %d\n", len(scanCtx.Anomalies))
	fmt.Printf("Vulnerabilità:   %d\n", len(scanCtx.Vulnerabilities))

	if len(scanCtx.Anomalies) > 0 {
		fmt.Println("\n🚨 Anomalie per severità:")
		bySeverity := map[string]int{}
		for _, a := range scanCtx.Anomalies {
			bySeverity[a.Severity]++
		}
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if n := bySeverity[sev]; n > 0 {
				fmt.Printf("   %-9s %d\n", sev+":", n)
			}
		}
	}

	top := scanCtx.GetEndpointsByRisk()
	if len(top) > 0 {
		fmt.Println("\n🎯 Top endpoint per rischio:")
		limit := 10
		if len(top) < limit {
			limit = len(top)
		}
		for _, ep := range top[:limit] {
			method := ep.Method
			if method == "" {
				method = "GET"
			}
			fmt.Printf("   %4.1f  %d  %-4s %s\n", ep.RiskScore, ep.StatusCode, method, ep.URL)
		}
	}
}

func writeJSON(scanCtx *models.ScanContext, path string) error {
	data, err := json.MarshalIndent(scanCtx, "", "  ")
	if err != nil {
		return err
	}
	if path == "-" {
		fmt.Println()
		fmt.Println(string(data))
		return nil
	}
	return os.WriteFile(path, data, 0644)
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
