package http

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/hateraku/bughunt/pkg/models"
)

var titleRegex = regexp.MustCompile("(?i)<title>(.*?)</title>")

// ProbeResult contains HTTP probe information
type ProbeResult struct {
	URL           string
	StatusCode    int
	Title         string
	Server        string
	ContentLength int64
	ContentType   string
	Body          string
	Headers       http.Header

	// Enhanced fields
	Redirects       []RedirectInfo
	FinalURL        string
	ResponseTime    time.Duration
	TLSVersion      string
	IsHTTPS         bool
	Cookies         []*http.Cookie
	SecurityHeaders SecurityHeaders

	// Detection flags
	HasWAF          bool
	WAFType         string
	IsAPI           bool
	IsAdmin         bool
	IsLogin         bool
	IsUpload        bool

	Error error
}

// RedirectInfo tracks redirect chain
type RedirectInfo struct {
	From       string
	To         string
	StatusCode int
}

// SecurityHeaders contains security-related headers
type SecurityHeaders struct {
	StrictTransportSecurity string
	ContentSecurityPolicy   string
	XFrameOptions          string
	XContentTypeOptions    string
	XSSProtection          string
	CORSAllowOrigin        string
	CORSAllowCredentials   string
}

// ExtractTitle extracts the title from HTML body
func ExtractTitle(body string) string {
	match := titleRegex.FindStringSubmatch(body)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

// Probe attempts to connect to a target via HTTPS then HTTP
func Probe(target string) (*ProbeResult, error) {
	return ProbeWithContext(context.Background(), target)
}

// ProbeWithContext performs HTTP probing with context support
func ProbeWithContext(ctx context.Context, target string) (*ProbeResult, error) {
	urls := []string{
		"https://" + target,
		"http://" + target,
	}

	var lastErr error
	for _, urlStr := range urls {
		result, err := probeURL(ctx, urlStr, target)
		if err != nil {
			lastErr = err
			continue
		}
		return result, nil
	}

	return nil, fmt.Errorf("no http/https response: %v", lastErr)
}

// probeURL probes a specific URL
func probeURL(ctx context.Context, urlStr string, originalTarget string) (*ProbeResult, error) {
	result := &ProbeResult{
		URL:       urlStr,
		Redirects: []RedirectInfo{},
	}

	// Check if HTTPS
	result.IsHTTPS = strings.HasPrefix(urlStr, "https://")

	// Custom client with redirect tracking
	client := &http.Client{
		Transport: newStealthTransport(),
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}

			// Track redirect
			if len(via) > 0 {
				prevReq := via[len(via)-1]
				fromURL := ""
				if prevReq.URL != nil {
					fromURL = prevReq.URL.String()
				}
				toURL := ""
				if req.URL != nil {
					toURL = req.URL.String()
				}
				statusCode := 0
				if prevReq.Response != nil {
					statusCode = prevReq.Response.StatusCode
				}

				result.Redirects = append(result.Redirects, RedirectInfo{
					From:       fromURL,
					To:         toURL,
					StatusCode: statusCode,
				})
			}

			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("User-Agent", RandomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	// NB: NON impostare Accept-Encoding manualmente. Se lo si imposta, Go
	// disattiva la decompressione automatica e result.Body resta compresso
	// (byte binari) → fingerprint/discovery non trovano nulla. Lasciandolo
	// vuoto, il Transport aggiunge "gzip" e decomprime in modo trasparente.
	req.Header.Set("Connection", "keep-alive")

	// Random delay to avoid rate limiting
	time.Sleep(time.Duration(50+rand.Intn(120)) * time.Millisecond)

	// Measure response time
	startTime := time.Now()
	resp, err := client.Do(req)
	result.ResponseTime = time.Since(startTime)

	if err != nil {
		result.Error = err
		return nil, err
	}
	defer resp.Body.Close()

	// Capture final URL after redirects
	result.FinalURL = resp.Request.URL.String()

	// Read body. Limite ampio (512KB): le pagine moderne (SPA/Next.js) mettono
	// segnali importanti — es. il flight data RSC __next_f — ben oltre i primi
	// 50KB, quindi un taglio troppo basso li nasconde a fingerprint e famiglie.
	const maxBodyBytes = 512 * 1024
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	body := string(bodyBytes)

	// Extract metadata
	result.StatusCode = resp.StatusCode
	result.Title = ExtractTitle(body)
	result.Server = resp.Header.Get("Server")
	result.ContentLength = resp.ContentLength
	result.ContentType = resp.Header.Get("Content-Type")
	result.Body = body
	result.Headers = resp.Header
	result.Cookies = resp.Cookies()

	// Extract security headers
	result.SecurityHeaders = extractSecurityHeaders(resp.Header)

	// Extract TLS version
	if resp.TLS != nil {
		result.TLSVersion = tlsVersionToString(resp.TLS.Version)
	}

	// Detection flags
	result.HasWAF, result.WAFType = detectWAF(resp.Header, body)
	result.IsAPI = detectAPI(urlStr, resp.Header, body)
	result.IsAdmin = detectAdmin(urlStr, body)
	result.IsLogin = detectLogin(urlStr, body)
	result.IsUpload = detectUpload(urlStr, body)

	return result, nil
}

// extractSecurityHeaders extracts security-related headers
func extractSecurityHeaders(headers http.Header) SecurityHeaders {
	return SecurityHeaders{
		StrictTransportSecurity: headers.Get("Strict-Transport-Security"),
		ContentSecurityPolicy:   headers.Get("Content-Security-Policy"),
		XFrameOptions:          headers.Get("X-Frame-Options"),
		XContentTypeOptions:    headers.Get("X-Content-Type-Options"),
		XSSProtection:          headers.Get("X-XSS-Protection"),
		CORSAllowOrigin:        headers.Get("Access-Control-Allow-Origin"),
		CORSAllowCredentials:   headers.Get("Access-Control-Allow-Credentials"),
	}
}

// detectWAF attempts to detect WAF presence
func detectWAF(headers http.Header, body string) (bool, string) {
	// Check headers
	wafHeaders := map[string]string{
		"cf-ray":           "Cloudflare",
		"x-cdn":            "Generic CDN",
		"server":           "",
		"x-sucuri-id":      "Sucuri",
		"x-served-by":      "",
		"x-amz-cf-id":      "CloudFront",
		"x-azure-ref":      "Azure",
		"akamai-x-cache":   "Akamai",
	}

	for header, wafName := range wafHeaders {
		if value := headers.Get(header); value != "" {
			if header == "server" {
				serverLower := strings.ToLower(value)
				if strings.Contains(serverLower, "cloudflare") {
					return true, "Cloudflare"
				}
				if strings.Contains(serverLower, "akamai") {
					return true, "Akamai"
				}
			} else if wafName != "" {
				return true, wafName
			}
		}
	}

	// Check body for WAF indicators
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "cloudflare") {
		return true, "Cloudflare"
	}
	if strings.Contains(bodyLower, "access denied") || strings.Contains(bodyLower, "blocked by") {
		return true, "Unknown WAF"
	}

	return false, ""
}

// detectAPI checks if the endpoint is an API
func detectAPI(urlStr string, headers http.Header, body string) bool {
	// Check URL path
	if strings.Contains(urlStr, "/api/") || strings.Contains(urlStr, "/v1/") ||
		strings.Contains(urlStr, "/v2/") || strings.Contains(urlStr, "/graphql") {
		return true
	}

	// Check content type
	contentType := strings.ToLower(headers.Get("Content-Type"))
	if strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "application/xml") {
		return true
	}

	// Check body structure
	trimmedBody := strings.TrimSpace(body)
	if strings.HasPrefix(trimmedBody, "{") || strings.HasPrefix(trimmedBody, "[") {
		return true
	}

	return false
}

// detectAdmin checks if the page is an admin panel
func detectAdmin(urlStr string, body string) bool {
	urlLower := strings.ToLower(urlStr)
	bodyLower := strings.ToLower(body)

	adminPaths := []string{"/admin", "/administrator", "/wp-admin", "/dashboard", "/panel", "/console"}
	for _, path := range adminPaths {
		if strings.Contains(urlLower, path) {
			return true
		}
	}

	adminKeywords := []string{"admin panel", "administrator", "dashboard", "control panel"}
	for _, keyword := range adminKeywords {
		if strings.Contains(bodyLower, keyword) {
			return true
		}
	}

	return false
}

// detectLogin checks if the page is a login page
func detectLogin(urlStr string, body string) bool {
	urlLower := strings.ToLower(urlStr)
	bodyLower := strings.ToLower(body)

	loginPaths := []string{"/login", "/signin", "/auth"}
	for _, path := range loginPaths {
		if strings.Contains(urlLower, path) {
			return true
		}
	}

	loginKeywords := []string{
		`type="password"`,
		`name="password"`,
		"login",
		"sign in",
		"authentication",
	}
	for _, keyword := range loginKeywords {
		if strings.Contains(bodyLower, keyword) {
			return true
		}
	}

	return false
}

// detectUpload checks if the page has upload functionality
func detectUpload(urlStr string, body string) bool {
	urlLower := strings.ToLower(urlStr)
	bodyLower := strings.ToLower(body)

	if strings.Contains(urlLower, "/upload") {
		return true
	}

	uploadKeywords := []string{
		`type="file"`,
		`input type="file"`,
		"file upload",
		"upload file",
	}
	for _, keyword := range uploadKeywords {
		if strings.Contains(bodyLower, keyword) {
			return true
		}
	}

	return false
}

// tlsVersionToString converts TLS version constant to string
func tlsVersionToString(version uint16) string {
	switch version {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

// ToEndpoint converts ProbeResult to models.Endpoint
func (pr *ProbeResult) ToEndpoint() models.Endpoint {
	finalURL := pr.FinalURL
	if finalURL == "" {
		finalURL = pr.URL
	}

	endpoint := models.Endpoint{
		URL:         finalURL,
		Method:      "GET",
		StatusCode:  pr.StatusCode,
		Title:       pr.Title,
		ContentType: pr.ContentType,
		Headers:     make(map[string]string),
		RiskScore:   0.0,
	}

	// Convert headers to map
	for key, values := range pr.Headers {
		if len(values) > 0 {
			endpoint.Headers[key] = values[0]
		}
	}

	// Calculate basic risk score
	endpoint.RiskScore = calculateBasicRiskScore(pr)

	return endpoint
}

// calculateBasicRiskScore calculates a basic risk score
func calculateBasicRiskScore(pr *ProbeResult) float64 {
	score := 0.0

	// Admin/Login/Upload pages are higher risk
	if pr.IsAdmin {
		score += 3.0
	}
	if pr.IsLogin {
		score += 2.0
	}
	if pr.IsUpload {
		score += 3.5
	}

	// Missing security headers
	if pr.SecurityHeaders.StrictTransportSecurity == "" && pr.IsHTTPS {
		score += 0.5
	}
	if pr.SecurityHeaders.XFrameOptions == "" {
		score += 0.5
	}
	if pr.SecurityHeaders.ContentSecurityPolicy == "" {
		score += 0.3
	}

	// CORS misconfigurations
	if pr.SecurityHeaders.CORSAllowOrigin == "*" {
		score += 2.0
		if pr.SecurityHeaders.CORSAllowCredentials == "true" {
			score += 2.5 // Critical!
		}
	}

	// Error pages can leak information
	if pr.StatusCode == 500 || pr.StatusCode == 403 {
		score += 1.0
	}

	// Debug/development indicators
	bodyLower := strings.ToLower(pr.Body)
	if strings.Contains(bodyLower, "debug") || strings.Contains(bodyLower, "stacktrace") {
		score += 2.0
	}

	// Cap at 10.0
	if score > 10.0 {
		score = 10.0
	}

	return score
}

// ToScanContext adds probe results to ScanContext
func (pr *ProbeResult) ToScanContext(ctx *models.ScanContext) {
	// Add endpoint
	endpoint := pr.ToEndpoint()
	ctx.AddEndpoint(endpoint)

	// Add vulnerabilities for security issues
	if pr.SecurityHeaders.CORSAllowOrigin == "*" && pr.SecurityHeaders.CORSAllowCredentials == "true" {
		ctx.AddVulnerability(models.Vulnerability{
			Type:        models.VulnCORS,
			Severity:    models.SeverityCritical,
			Score:       9.0,
			Title:       "CORS Misconfiguration - Credentials with Wildcard",
			Description: "Access-Control-Allow-Origin is set to * with credentials enabled",
			URL:         pr.FinalURL,
			Evidence:    fmt.Sprintf("CORS-Allow-Origin: %s, Allow-Credentials: %s", pr.SecurityHeaders.CORSAllowOrigin, pr.SecurityHeaders.CORSAllowCredentials),
			FoundBy:     "http.probe",
			DiscoveredAt: time.Now(),
		})
	}

	// Missing security headers
	if pr.SecurityHeaders.StrictTransportSecurity == "" && pr.IsHTTPS {
		ctx.AddAnomaly(models.Anomaly{
			Type:        "missing_security_header",
			URL:         pr.FinalURL,
			Description: "Missing Strict-Transport-Security header on HTTPS site",
			Severity:    models.SeverityLow,
			DetectedAt:  time.Now(),
		})
	}

	// WAF detection
	if pr.HasWAF {
		ctx.SetMetadata("waf_detected", pr.WAFType)
	}

	// Add open redirect if suspicious redirects
	if len(pr.Redirects) > 0 {
		for _, redirect := range pr.Redirects {
			// Check if redirect goes to different domain
			fromURL, _ := url.Parse(redirect.From)
			toURL, _ := url.Parse(redirect.To)

			if fromURL != nil && toURL != nil && fromURL.Host != toURL.Host {
				ctx.AddAnomaly(models.Anomaly{
					Type:        "external_redirect",
					URL:         redirect.From,
					Description: fmt.Sprintf("External redirect to %s", redirect.To),
					Severity:    models.SeverityInfo,
					DetectedAt:  time.Now(),
				})
			}
		}
	}
}
