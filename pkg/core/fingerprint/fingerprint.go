package fingerprint

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/hateraku/bughunt/pkg/models"
)

// Module is the technology fingerprinting module
type Module struct {
	client *http.Client
}

// New creates a new fingerprinting module
func New(client *http.Client) *Module {
	return &Module{
		client: client,
	}
}

// FingerprintResult contains detected technologies
type FingerprintResult struct {
	URL string

	// Web Servers
	WebServer string

	// Frameworks
	Frameworks []string

	// CMS
	CMS []string

	// JavaScript Frameworks
	JSFrameworks []string

	// Programming Languages
	Languages []string

	// CDN/WAF
	CDN []string
	WAF []string

	// Other Technologies
	Other []string

	// Favicon hash
	FaviconHash string

	// Confidence scores (0.0 - 1.0)
	Confidence map[string]float64
}

// Fingerprint performs comprehensive technology detection
func (m *Module) Fingerprint(ctx context.Context, url string, body string, headers http.Header) *FingerprintResult {
	result := &FingerprintResult{
		URL:          url,
		Frameworks:   []string{},
		CMS:          []string{},
		JSFrameworks: []string{},
		Languages:    []string{},
		CDN:          []string{},
		WAF:          []string{},
		Other:        []string{},
		Confidence:   make(map[string]float64),
	}

	// Detect from headers
	m.detectFromHeaders(headers, result)

	// Detect from body content
	m.detectFromBody(body, result)

	// Detect CMS
	m.detectCMS(body, headers, result)

	// Detect JavaScript frameworks
	m.detectJSFrameworks(body, result)

	// Detect backend frameworks
	m.detectFrameworks(body, headers, result)

	// Detect programming languages
	m.detectLanguages(body, headers, result)

	// Detect CDN/WAF
	m.detectCDN(headers, result)

	// Fetch and hash favicon (if not already done by HTTP probe)
	if url != "" {
		m.detectFavicon(ctx, url, result)
	}

	return result
}

// detectFromHeaders extracts technology info from HTTP headers
func (m *Module) detectFromHeaders(headers http.Header, result *FingerprintResult) {
	// Server header
	if server := headers.Get("Server"); server != "" {
		result.WebServer = server
		serverLower := strings.ToLower(server)

		// Web servers
		if strings.Contains(serverLower, "apache") {
			result.Other = append(result.Other, "Apache")
		}
		if strings.Contains(serverLower, "nginx") {
			result.Other = append(result.Other, "Nginx")
		}
		if strings.Contains(serverLower, "litespeed") {
			result.Other = append(result.Other, "LiteSpeed")
		}
		if strings.Contains(serverLower, "microsoft-iis") {
			result.Other = append(result.Other, "IIS")
		}
		if strings.Contains(serverLower, "cloudflare") {
			result.CDN = append(result.CDN, "Cloudflare")
		}
	}

	// X-Powered-By header
	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		poweredByLower := strings.ToLower(poweredBy)

		if strings.Contains(poweredByLower, "php") {
			result.Languages = append(result.Languages, "PHP")
			// Extract PHP version
			if versionMatch := regexp.MustCompile(`PHP/(\d+\.\d+\.\d+)`).FindStringSubmatch(poweredBy); len(versionMatch) > 1 {
				result.Other = append(result.Other, fmt.Sprintf("PHP %s", versionMatch[1]))
			}
		}
		if strings.Contains(poweredByLower, "asp.net") {
			result.Languages = append(result.Languages, "ASP.NET")
			result.Frameworks = append(result.Frameworks, "ASP.NET")
		}
		if strings.Contains(poweredByLower, "express") {
			result.Frameworks = append(result.Frameworks, "Express")
			result.Languages = append(result.Languages, "Node.js")
		}
	}

	// X-AspNet-Version
	if aspNet := headers.Get("X-AspNet-Version"); aspNet != "" {
		result.Frameworks = append(result.Frameworks, fmt.Sprintf("ASP.NET %s", aspNet))
		result.Languages = append(result.Languages, "ASP.NET")
	}

	// X-AspNetMvc-Version
	if aspMvc := headers.Get("X-AspNetMvc-Version"); aspMvc != "" {
		result.Frameworks = append(result.Frameworks, fmt.Sprintf("ASP.NET MVC %s", aspMvc))
	}

	// X-Framework
	if framework := headers.Get("X-Framework"); framework != "" {
		result.Frameworks = append(result.Frameworks, framework)
	}

	// Set-Cookie for framework detection
	cookies := headers.Values("Set-Cookie")
	for _, cookie := range cookies {
		cookieLower := strings.ToLower(cookie)

		if strings.Contains(cookieLower, "laravel_session") {
			result.Frameworks = append(result.Frameworks, "Laravel")
			result.Languages = append(result.Languages, "PHP")
			result.Confidence["Laravel"] = 0.9
		}
		if strings.Contains(cookieLower, "jsessionid") {
			result.Languages = append(result.Languages, "Java")
			result.Confidence["Java"] = 0.8
		}
		if strings.Contains(cookieLower, "phpsessid") {
			result.Languages = append(result.Languages, "PHP")
			result.Confidence["PHP"] = 0.8
		}
		if strings.Contains(cookieLower, "asp.net_sessionid") {
			result.Languages = append(result.Languages, "ASP.NET")
			result.Confidence["ASP.NET"] = 0.9
		}
		if strings.Contains(cookieLower, "django") || strings.Contains(cookieLower, "csrftoken") {
			result.Frameworks = append(result.Frameworks, "Django")
			result.Languages = append(result.Languages, "Python")
			result.Confidence["Django"] = 0.85
		}
		if strings.Contains(cookieLower, "connect.sid") {
			result.Frameworks = append(result.Frameworks, "Express")
			result.Languages = append(result.Languages, "Node.js")
			result.Confidence["Express"] = 0.8
		}
	}
}

// detectFromBody detects technologies from HTML body content
func (m *Module) detectFromBody(body string, result *FingerprintResult) {
	bodyLower := strings.ToLower(body)

	// Meta tags
	metaRegex := regexp.MustCompile(`<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	if matches := metaRegex.FindStringSubmatch(body); len(matches) > 1 {
		generator := matches[1]
		result.Other = append(result.Other, fmt.Sprintf("Generator: %s", generator))

		generatorLower := strings.ToLower(generator)
		if strings.Contains(generatorLower, "wordpress") {
			result.CMS = append(result.CMS, "WordPress")
			result.Confidence["WordPress"] = 0.95
		}
		if strings.Contains(generatorLower, "joomla") {
			result.CMS = append(result.CMS, "Joomla")
			result.Confidence["Joomla"] = 0.95
		}
		if strings.Contains(generatorLower, "drupal") {
			result.CMS = append(result.CMS, "Drupal")
			result.Confidence["Drupal"] = 0.95
		}
	}

	// Common file paths and patterns
	patterns := map[string]struct {
		tech       string
		category   string
		confidence float64
	}{
		"/wp-content/":          {"WordPress", "CMS", 0.95},
		"/wp-includes/":         {"WordPress", "CMS", 0.95},
		"/wp-json/":             {"WordPress", "CMS", 0.9},
		"wp-embed.min.js":       {"WordPress", "CMS", 0.9},
		"/joomla/":              {"Joomla", "CMS", 0.85},
		"/administrator/":       {"Joomla", "CMS", 0.6},
		"/sites/default/":       {"Drupal", "CMS", 0.9},
		"/core/":                {"Drupal", "CMS", 0.7},
		"/skin/frontend/":       {"Magento", "CMS", 0.9},
		"/app/etc/local.xml":    {"Magento", "CMS", 0.95},
		"/_next/":               {"Next.js", "Framework", 0.95},
		"/__nuxt/":              {"Nuxt.js", "Framework", 0.95},
		"/static/css/":          {"React", "JSFramework", 0.6},
		"react-dom":             {"React", "JSFramework", 0.9},
		"vue.js":                {"Vue.js", "JSFramework", 0.9},
		"angular.js":            {"Angular", "JSFramework", 0.9},
		"@angular/":             {"Angular", "JSFramework", 0.95},
		"laravel":               {"Laravel", "Framework", 0.7},
		"csrf-token":            {"Laravel/Django", "Framework", 0.5},
		"django":                {"Django", "Framework", 0.8},
		"flask":                 {"Flask", "Framework", 0.7},
		"express":               {"Express", "Framework", 0.6},
		"jquery":                {"jQuery", "Library", 0.9},
		"bootstrap":             {"Bootstrap", "Library", 0.8},
		"tailwind":              {"Tailwind CSS", "Library", 0.8},
		"/assets/application-":  {"Rails", "Framework", 0.8},
		"data-turbolinks-track": {"Rails", "Framework", 0.9},
	}

	for pattern, info := range patterns {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			switch info.category {
			case "CMS":
				if !contains(result.CMS, info.tech) {
					result.CMS = append(result.CMS, info.tech)
					result.Confidence[info.tech] = info.confidence
				}
			case "Framework":
				if !contains(result.Frameworks, info.tech) {
					result.Frameworks = append(result.Frameworks, info.tech)
					result.Confidence[info.tech] = info.confidence
				}
			case "JSFramework":
				if !contains(result.JSFrameworks, info.tech) {
					result.JSFrameworks = append(result.JSFrameworks, info.tech)
					result.Confidence[info.tech] = info.confidence
				}
			case "Library":
				if !contains(result.Other, info.tech) {
					result.Other = append(result.Other, info.tech)
					result.Confidence[info.tech] = info.confidence
				}
			}
		}
	}
}

// detectCMS performs CMS-specific detection
func (m *Module) detectCMS(body string, headers http.Header, result *FingerprintResult) {
	bodyLower := strings.ToLower(body)

	// WordPress
	wpIndicators := []string{
		"wp-content",
		"wp-includes",
		"wordpress",
		"wp-json",
		"xmlrpc.php",
	}
	wpScore := 0.0
	for _, indicator := range wpIndicators {
		if strings.Contains(bodyLower, indicator) {
			wpScore += 0.2
		}
	}
	if wpScore >= 0.4 && !contains(result.CMS, "WordPress") {
		result.CMS = append(result.CMS, "WordPress")
		result.Confidence["WordPress"] = wpScore
	}

	// Joomla
	joomlaIndicators := []string{
		"joomla",
		"/components/com_",
		"/modules/mod_",
		"option=com_",
	}
	joomlaScore := 0.0
	for _, indicator := range joomlaIndicators {
		if strings.Contains(bodyLower, indicator) {
			joomlaScore += 0.25
		}
	}
	if joomlaScore >= 0.5 && !contains(result.CMS, "Joomla") {
		result.CMS = append(result.CMS, "Joomla")
		result.Confidence["Joomla"] = joomlaScore
	}

	// Drupal
	drupalIndicators := []string{
		"drupal",
		"/sites/default/",
		"drupal.js",
		"x-drupal-cache",
	}
	drupalScore := 0.0
	for _, indicator := range drupalIndicators {
		if strings.Contains(bodyLower, indicator) || strings.Contains(strings.ToLower(headers.Get("X-Drupal-Cache")), "hit") {
			drupalScore += 0.25
		}
	}
	if drupalScore >= 0.5 && !contains(result.CMS, "Drupal") {
		result.CMS = append(result.CMS, "Drupal")
		result.Confidence["Drupal"] = drupalScore
	}
}

// scoreIndicators valuta la forza dell'evidenza: un marker "forte" (specifico,
// difficile da trovare per caso) dà confidence alta; solo un marker "debole"
// (parola generica, spesso presente come testo) dà confidence bassa. È così che
// si evitano i falsi positivi tipo "svelte"/"angular" citati in una pagina.
func scoreIndicators(body string, strong, weak []string) float64 {
	if matchAny(body, strong) {
		return 0.9
	}
	if matchAny(body, weak) {
		return 0.35
	}
	return 0
}

// detectJSFrameworks detects JavaScript frameworks
func (m *Module) detectJSFrameworks(body string, result *FingerprintResult) {
	bodyLower := strings.ToLower(body)

	// React — marker specifici = alta confidence; "react" nudo = debole.
	if s := scoreIndicators(bodyLower, []string{"react-dom", "data-reactroot", "data-reactid", "__react"}, []string{"react"}); s > 0 && !contains(result.JSFrameworks, "React") {
		result.JSFrameworks = append(result.JSFrameworks, "React")
		result.Confidence["React"] = s
	}

	// Vue.js
	if s := scoreIndicators(bodyLower, []string{"vue.js", "vue.min.js", "data-v-", "__vue__"}, []string{"vue"}); s > 0 && !contains(result.JSFrameworks, "Vue.js") {
		result.JSFrameworks = append(result.JSFrameworks, "Vue.js")
		result.Confidence["Vue.js"] = s
	}

	// Angular — "angular" nudo è testo; ng-app/@angular/ sono marker reali.
	if s := scoreIndicators(bodyLower, []string{"ng-app", "ng-controller", "@angular/", "ng-version"}, []string{"angular"}); s > 0 && !contains(result.JSFrameworks, "Angular") {
		result.JSFrameworks = append(result.JSFrameworks, "Angular")
		result.Confidence["Angular"] = s
	}

	// Next.js — implica React con certezza: imposta la confidence alta anche se
	// una rilevazione debole di React l'aveva già aggiunto con punteggio basso.
	if strings.Contains(bodyLower, "_next") || strings.Contains(bodyLower, "__next") {
		if !contains(result.Frameworks, "Next.js") {
			result.Frameworks = append(result.Frameworks, "Next.js")
		}
		result.Confidence["Next.js"] = 0.95
		if !contains(result.JSFrameworks, "React") {
			result.JSFrameworks = append(result.JSFrameworks, "React")
		}
		result.Confidence["React"] = 0.95
	}

	// Nuxt.js — implica Vue con certezza.
	if strings.Contains(bodyLower, "__nuxt") || strings.Contains(bodyLower, "_nuxt") {
		if !contains(result.Frameworks, "Nuxt.js") {
			result.Frameworks = append(result.Frameworks, "Nuxt.js")
		}
		result.Confidence["Nuxt.js"] = 0.95
		if !contains(result.JSFrameworks, "Vue.js") {
			result.JSFrameworks = append(result.JSFrameworks, "Vue.js")
		}
		result.Confidence["Vue.js"] = 0.95
	}

	// Svelte — marker specifici vs "svelte" nudo (spesso solo testo in pagina).
	if s := scoreIndicators(bodyLower, []string{"svelte-", "__svelte", "svelte/internal"}, []string{"svelte"}); s > 0 && !contains(result.JSFrameworks, "Svelte") {
		result.JSFrameworks = append(result.JSFrameworks, "Svelte")
		result.Confidence["Svelte"] = s
	}
}

// detectFrameworks detects backend frameworks
func (m *Module) detectFrameworks(body string, headers http.Header, result *FingerprintResult) {
	bodyLower := strings.ToLower(body)

	// Laravel
	laravelIndicators := []string{
		"laravel",
		"laravel_session",
		"csrf-token",
		"/vendor/laravel",
	}
	if matchAny(bodyLower, laravelIndicators) && !contains(result.Frameworks, "Laravel") {
		result.Frameworks = append(result.Frameworks, "Laravel")
		result.Languages = appendUnique(result.Languages, "PHP")
		result.Confidence["Laravel"] = 0.8
	}

	// Django
	djangoIndicators := []string{
		"csrfmiddlewaretoken",
		"django",
		"__admin_media_prefix__",
	}
	if matchAny(bodyLower, djangoIndicators) && !contains(result.Frameworks, "Django") {
		result.Frameworks = append(result.Frameworks, "Django")
		result.Languages = appendUnique(result.Languages, "Python")
		result.Confidence["Django"] = 0.85
	}

	// Flask
	if strings.Contains(bodyLower, "flask") || strings.Contains(headers.Get("Server"), "Werkzeug") {
		if !contains(result.Frameworks, "Flask") {
			result.Frameworks = append(result.Frameworks, "Flask")
			result.Languages = appendUnique(result.Languages, "Python")
			result.Confidence["Flask"] = 0.75
		}
	}

	// Ruby on Rails
	railsIndicators := []string{
		"data-turbolinks-track",
		"/assets/application-",
		"rails",
		"x-runtime",
	}
	if matchAny(bodyLower, railsIndicators) || headers.Get("X-Runtime") != "" {
		if !contains(result.Frameworks, "Ruby on Rails") {
			result.Frameworks = append(result.Frameworks, "Ruby on Rails")
			result.Languages = appendUnique(result.Languages, "Ruby")
			result.Confidence["Ruby on Rails"] = 0.85
		}
	}

	// Spring Boot
	springIndicators := []string{
		"spring",
		"whitelabel error page",
	}
	if matchAny(bodyLower, springIndicators) && !contains(result.Frameworks, "Spring Boot") {
		result.Frameworks = append(result.Frameworks, "Spring Boot")
		result.Languages = appendUnique(result.Languages, "Java")
		result.Confidence["Spring Boot"] = 0.7
	}
}

// detectLanguages detects programming languages
func (m *Module) detectLanguages(body string, headers http.Header, result *FingerprintResult) {
	bodyLower := strings.ToLower(body)

	// PHP
	phpIndicators := []string{
		".php",
		"phpsessid",
		"<?php",
	}
	if matchAny(bodyLower, phpIndicators) {
		result.Languages = appendUnique(result.Languages, "PHP")
	}

	// ASP.NET
	aspIndicators := []string{
		".aspx",
		".asp",
		"__viewstate",
		"asp.net",
	}
	if matchAny(bodyLower, aspIndicators) {
		result.Languages = appendUnique(result.Languages, "ASP.NET")
	}

	// Java/JSP
	javaIndicators := []string{
		".jsp",
		".jsf",
		"jsessionid",
		"java",
	}
	if matchAny(bodyLower, javaIndicators) {
		result.Languages = appendUnique(result.Languages, "Java")
	}

	// Python
	pythonIndicators := []string{
		"django",
		"flask",
		"wsgi",
	}
	if matchAny(bodyLower, pythonIndicators) {
		result.Languages = appendUnique(result.Languages, "Python")
	}

	// Node.js
	nodeIndicators := []string{
		"express",
		"node.js",
		"connect.sid",
	}
	if matchAny(bodyLower, nodeIndicators) {
		result.Languages = appendUnique(result.Languages, "Node.js")
	}
}

// detectCDN detects CDN and WAF
func (m *Module) detectCDN(headers http.Header, result *FingerprintResult) {
	cdnHeaders := map[string]string{
		"cf-ray":          "Cloudflare",
		"cf-cache-status": "Cloudflare",
		"x-amz-cf-id":     "Amazon CloudFront",
		"x-azure-ref":     "Azure CDN",
		"akamai-x-cache":  "Akamai",
		"x-fastly-":       "Fastly",
		"x-cdn":           "Generic CDN",
	}

	for header, cdn := range cdnHeaders {
		for key := range headers {
			if strings.Contains(strings.ToLower(key), header) {
				result.CDN = appendUnique(result.CDN, cdn)
			}
		}
	}

	// WAF detection
	wafHeaders := map[string]string{
		"x-sucuri-id":    "Sucuri",
		"x-mod-security": "ModSecurity",
	}

	for header, waf := range wafHeaders {
		if headers.Get(header) != "" {
			result.WAF = appendUnique(result.WAF, waf)
		}
	}
}

// detectFavicon fetches and hashes the favicon
func (m *Module) detectFavicon(ctx context.Context, baseURL string, result *FingerprintResult) {
	// Common favicon paths
	faviconPaths := []string{
		"/favicon.ico",
		"/favicon.png",
	}

	for _, path := range faviconPaths {
		faviconURL := strings.TrimSuffix(baseURL, "/") + path

		req, err := http.NewRequestWithContext(ctx, "GET", faviconURL, nil)
		if err != nil {
			continue
		}

		resp, err := m.client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		// Read favicon and calculate MD5 hash
		faviconData, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Max 1MB
		resp.Body.Close()
		if err != nil {
			continue
		}

		// Calculate MD5 hash
		hash := md5.Sum(faviconData)
		result.FaviconHash = base64.StdEncoding.EncodeToString(hash[:])

		// Calculate MMH3 hash (simplified - for full implementation, use mmh3 library)
		// For now, just use MD5 as placeholder
		break
	}
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func appendUnique(slice []string, item string) []string {
	if !contains(slice, item) {
		return append(slice, item)
	}
	return slice
}

func matchAny(text string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(text, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// confidenceThreshold è la soglia minima per promuovere una tecnologia che ha
// un punteggio di confidence. Sotto la soglia si considera rumore/falso positivo.
const confidenceThreshold = 0.5

// confident indica se una tecnologia va promossa: quelle senza punteggio (es.
// dedotte da header o linguaggi) passano sempre; quelle con punteggio solo se
// raggiungono la soglia.
func (fr *FingerprintResult) confident(tech string) bool {
	c, ok := fr.Confidence[tech]
	if !ok {
		return true
	}
	return c >= confidenceThreshold
}

// ToScanContext adds fingerprinting results to ScanContext
func (fr *FingerprintResult) ToScanContext(ctx *models.ScanContext) {
	// Promuovi solo le tecnologie abbastanza confidenti (filtra i falsi positivi).
	add := func(techs []string) {
		for _, tech := range techs {
			if fr.confident(tech) {
				ctx.AddTechnology(tech)
			}
		}
	}
	add(fr.Frameworks)
	add(fr.CMS)
	add(fr.JSFrameworks)
	add(fr.Languages)
	add(fr.CDN)
	add(fr.WAF)
	add(fr.Other)

	// Store favicon hash in metadata if found
	if fr.FaviconHash != "" {
		ctx.SetMetadata("favicon_hash", fr.FaviconHash)
	}

	// Store confidence scores
	if len(fr.Confidence) > 0 {
		ctx.SetMetadata("tech_confidence", fr.Confidence)
	}
}
