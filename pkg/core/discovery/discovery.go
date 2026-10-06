package discovery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/hateraku/bughunt/pkg/models"
)

// Module is the endpoint discovery module
type Module struct {
	client      *http.Client
	maxDepth    int
	visited     map[string]bool
	baseURL     *url.URL
	userAgent   string
}

// Config holds discovery configuration
type Config struct {
	MaxDepth     int
	FollowExternal bool
	UserAgent    string
}

// New creates a new discovery module
func New(client *http.Client, config *Config) *Module {
	if config == nil {
		config = &Config{
			MaxDepth:  2,
			UserAgent: "Mozilla/5.0 (compatible; BugHunt/1.0)",
		}
	}

	return &Module{
		client:    client,
		maxDepth:  config.MaxDepth,
		visited:   make(map[string]bool),
		userAgent: config.UserAgent,
	}
}

// DiscoveryResult contains all discovered endpoints
type DiscoveryResult struct {
	BaseURL string

	// Discovered endpoints
	Links      []string
	Forms      []FormInfo
	APIEndpoints []string
	JSFiles    []string
	Sitemaps   []string

	// Parsed files
	RobotsTxt  *RobotsTxt
	SitemapXML []string

	// Common paths found
	CommonPaths []PathProbeResult

	// Statistics
	TotalLinks      int
	TotalForms      int
	TotalAPIEndpoints int
}

// FormInfo represents a discovered form
type FormInfo struct {
	Action   string
	Method   string
	Fields   []FormField
	HasFile  bool
	HasPassword bool
}

// FormField represents a form input field
type FormField struct {
	Name  string
	Type  string
	Value string
}

// RobotsTxt represents parsed robots.txt
type RobotsTxt struct {
	Disallow   []string
	Allow      []string
	Sitemaps   []string
	CrawlDelay int
}

// PathProbeResult represents a probed common path
type PathProbeResult struct {
	Path       string
	StatusCode int
	Found      bool
	Redirect   string
}

// Discover performs comprehensive endpoint discovery
func (m *Module) Discover(ctx context.Context, targetURL string) (*DiscoveryResult, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	m.baseURL = parsedURL
	m.visited = make(map[string]bool) // Reset visited

	result := &DiscoveryResult{
		BaseURL:     targetURL,
		Links:       []string{},
		Forms:       []FormInfo{},
		APIEndpoints: []string{},
		JSFiles:     []string{},
		Sitemaps:    []string{},
		SitemapXML:  []string{},
		CommonPaths: []PathProbeResult{},
	}

	// 1. Parse robots.txt
	if robotsTxt := m.parseRobotsTxt(ctx, targetURL); robotsTxt != nil {
		result.RobotsTxt = robotsTxt
		result.Sitemaps = append(result.Sitemaps, robotsTxt.Sitemaps...)
	}

	// 2. Parse sitemap.xml
	sitemapURLs := m.parseSitemapXML(ctx, targetURL)
	result.SitemapXML = append(result.SitemapXML, sitemapURLs...)

	// 3. Crawl HTML (depth-limited)
	m.crawl(ctx, targetURL, 0, result)

	// 4. Probe common paths
	result.CommonPaths = m.probeCommonPaths(ctx, targetURL)

	// 5. Detect API endpoints
	result.APIEndpoints = m.detectAPIEndpoints(result.Links)

	// Statistics
	result.TotalLinks = len(result.Links)
	result.TotalForms = len(result.Forms)
	result.TotalAPIEndpoints = len(result.APIEndpoints)

	return result, nil
}

// crawl performs recursive HTML crawling
func (m *Module) crawl(ctx context.Context, targetURL string, depth int, result *DiscoveryResult) {
	// Depth limit
	if depth > m.maxDepth {
		return
	}

	// Already visited
	if m.visited[targetURL] {
		return
	}
	m.visited[targetURL] = true

	// Fetch page
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", m.userAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Only process HTML
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "text/html") {
		return
	}

	// Read body (limit to 1MB)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return
	}
	body := string(bodyBytes)

	// Extract links
	links := m.extractLinks(body, targetURL)
	for _, link := range links {
		if !contains(result.Links, link) {
			result.Links = append(result.Links, link)
		}

		// Recursive crawl (same domain only)
		if m.isSameDomain(link) && depth < m.maxDepth {
			m.crawl(ctx, link, depth+1, result)
		}
	}

	// Extract forms
	forms := m.extractForms(body, targetURL)
	result.Forms = append(result.Forms, forms...)

	// Extract JS files
	jsFiles := m.extractJSFiles(body, targetURL)
	for _, jsFile := range jsFiles {
		if !contains(result.JSFiles, jsFile) {
			result.JSFiles = append(result.JSFiles, jsFile)
		}
	}
}

// extractLinks extracts all links from HTML
func (m *Module) extractLinks(body string, baseURL string) []string {
	var links []string

	// Regular expressions for different link types
	patterns := []string{
		`href=["']([^"']+)["']`,       // <a href="">
		`src=["']([^"']+)["']`,        // <img src=""> <script src="">
		`action=["']([^"']+)["']`,     // <form action="">
		`data-url=["']([^"']+)["']`,   // data attributes
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(body, -1)

		for _, match := range matches {
			if len(match) > 1 {
				link := match[1]
				absoluteURL := m.makeAbsolute(link, baseURL)
				if absoluteURL != "" && m.isValidURL(absoluteURL) {
					links = append(links, absoluteURL)
				}
			}
		}
	}

	return unique(links)
}

// extractForms extracts form information from HTML
func (m *Module) extractForms(body string, baseURL string) []FormInfo {
	var forms []FormInfo

	// Simple form extraction (basic regex approach)
	formRegex := regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	formMatches := formRegex.FindAllStringSubmatch(body, -1)

	for _, formMatch := range formMatches {
		if len(formMatch) < 2 {
			continue
		}

		formHTML := formMatch[0]
		formBody := formMatch[1]

		form := FormInfo{
			Method: "GET", // default
			Fields: []FormField{},
		}

		// Extract action
		actionRegex := regexp.MustCompile(`action=["']([^"']+)["']`)
		if actionMatch := actionRegex.FindStringSubmatch(formHTML); len(actionMatch) > 1 {
			form.Action = m.makeAbsolute(actionMatch[1], baseURL)
		} else {
			form.Action = baseURL
		}

		// Extract method
		methodRegex := regexp.MustCompile(`method=["']([^"']+)["']`)
		if methodMatch := methodRegex.FindStringSubmatch(formHTML); len(methodMatch) > 1 {
			form.Method = strings.ToUpper(methodMatch[1])
		}

		// Extract input fields
		inputRegex := regexp.MustCompile(`(?i)<input[^>]*>`)
		inputs := inputRegex.FindAllString(formBody, -1)

		for _, input := range inputs {
			field := FormField{}

			// Extract name
			nameRegex := regexp.MustCompile(`name=["']([^"']+)["']`)
			if nameMatch := nameRegex.FindStringSubmatch(input); len(nameMatch) > 1 {
				field.Name = nameMatch[1]
			}

			// Extract type
			typeRegex := regexp.MustCompile(`type=["']([^"']+)["']`)
			if typeMatch := typeRegex.FindStringSubmatch(input); len(typeMatch) > 1 {
				field.Type = strings.ToLower(typeMatch[1])
			} else {
				field.Type = "text" // default
			}

			// Extract value
			valueRegex := regexp.MustCompile(`value=["']([^"']+)["']`)
			if valueMatch := valueRegex.FindStringSubmatch(input); len(valueMatch) > 1 {
				field.Value = valueMatch[1]
			}

			// Check for file upload
			if field.Type == "file" {
				form.HasFile = true
			}

			// Check for password field
			if field.Type == "password" {
				form.HasPassword = true
			}

			if field.Name != "" {
				form.Fields = append(form.Fields, field)
			}
		}

		if len(form.Fields) > 0 {
			forms = append(forms, form)
		}
	}

	return forms
}

// extractJSFiles extracts JavaScript file URLs
func (m *Module) extractJSFiles(body string, baseURL string) []string {
	var jsFiles []string

	// <script src="">
	scriptRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
	matches := scriptRegex.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		if len(match) > 1 {
			jsURL := m.makeAbsolute(match[1], baseURL)
			if jsURL != "" {
				jsFiles = append(jsFiles, jsURL)
			}
		}
	}

	return unique(jsFiles)
}

// parseRobotsTxt parses robots.txt file
func (m *Module) parseRobotsTxt(ctx context.Context, baseURL string) *RobotsTxt {
	robotsURL := strings.TrimSuffix(baseURL, "/") + "/robots.txt"

	req, err := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", m.userAgent)

	resp, err := m.client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*100)) // 100KB max
	if err != nil {
		return nil
	}

	body := string(bodyBytes)
	robotsTxt := &RobotsTxt{
		Disallow: []string{},
		Allow:    []string{},
		Sitemaps: []string{},
	}

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		directive := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch directive {
		case "disallow":
			if value != "" {
				robotsTxt.Disallow = append(robotsTxt.Disallow, value)
			}
		case "allow":
			if value != "" {
				robotsTxt.Allow = append(robotsTxt.Allow, value)
			}
		case "sitemap":
			robotsTxt.Sitemaps = append(robotsTxt.Sitemaps, value)
		}
	}

	return robotsTxt
}

// parseSitemapXML parses sitemap.xml file
func (m *Module) parseSitemapXML(ctx context.Context, baseURL string) []string {
	sitemapURL := strings.TrimSuffix(baseURL, "/") + "/sitemap.xml"

	req, err := http.NewRequestWithContext(ctx, "GET", sitemapURL, nil)
	if err != nil {
		return []string{}
	}
	req.Header.Set("User-Agent", m.userAgent)

	resp, err := m.client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return []string{}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB max
	if err != nil {
		return []string{}
	}

	body := string(bodyBytes)

	// Extract <loc> tags
	locRegex := regexp.MustCompile(`<loc>([^<]+)</loc>`)
	matches := locRegex.FindAllStringSubmatch(body, -1)

	var urls []string
	for _, match := range matches {
		if len(match) > 1 {
			urls = append(urls, match[1])
		}
	}

	return urls
}

// probeCommonPaths probes common interesting paths
func (m *Module) probeCommonPaths(ctx context.Context, baseURL string) []PathProbeResult {
	commonPaths := []string{
		"/admin",
		"/administrator",
		"/api",
		"/api/v1",
		"/api/v2",
		"/graphql",
		"/debug",
		"/swagger",
		"/swagger.json",
		"/swagger-ui",
		"/openapi.json",
		"/api-docs",
		"/.env",
		"/.git",
		"/.git/config",
		"/backup",
		"/config",
		"/upload",
		"/uploads",
		"/static",
		"/assets",
		"/public",
		"/wp-admin",
		"/wp-login.php",
		"/phpmyadmin",
		"/adminer",
		"/console",
		"/dashboard",
	}

	var results []PathProbeResult
	base, _ := url.Parse(baseURL)

	for _, path := range commonPaths {
		probeURL := base.Scheme + "://" + base.Host + path

		req, err := http.NewRequestWithContext(ctx, "HEAD", probeURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", m.userAgent)

		resp, err := m.client.Do(req)
		if err != nil {
			results = append(results, PathProbeResult{
				Path:  path,
				Found: false,
			})
			continue
		}
		resp.Body.Close()

		result := PathProbeResult{
			Path:       path,
			StatusCode: resp.StatusCode,
			Found:      resp.StatusCode >= 200 && resp.StatusCode < 400,
		}

		// Check for redirect
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			if location := resp.Header.Get("Location"); location != "" {
				result.Redirect = location
			}
		}

		if result.Found {
			results = append(results, result)
		}
	}

	return results
}

// detectAPIEndpoints detects API endpoints from discovered links
func (m *Module) detectAPIEndpoints(links []string) []string {
	var apiEndpoints []string

	apiPatterns := []string{
		"/api/",
		"/v1/",
		"/v2/",
		"/v3/",
		"/rest/",
		"/graphql",
		"/swagger",
		"/openapi",
	}

	for _, link := range links {
		linkLower := strings.ToLower(link)
		for _, pattern := range apiPatterns {
			if strings.Contains(linkLower, pattern) {
				apiEndpoints = append(apiEndpoints, link)
				break
			}
		}
	}

	return unique(apiEndpoints)
}

// Helper functions

func (m *Module) makeAbsolute(link, baseURL string) string {
	if link == "" {
		return ""
	}

	// Already absolute
	if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
		return link
	}

	// Parse base URL
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	// Parse relative link
	relative, err := url.Parse(link)
	if err != nil {
		return ""
	}

	// Resolve
	absolute := base.ResolveReference(relative)
	return absolute.String()
}

func (m *Module) isSameDomain(targetURL string) bool {
	if m.baseURL == nil {
		return false
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	return parsed.Host == m.baseURL.Host
}

func (m *Module) isValidURL(urlStr string) bool {
	// Skip fragments, javascript:, mailto:, etc
	if strings.HasPrefix(urlStr, "#") ||
		strings.HasPrefix(urlStr, "javascript:") ||
		strings.HasPrefix(urlStr, "mailto:") ||
		strings.HasPrefix(urlStr, "tel:") ||
		strings.HasPrefix(urlStr, "data:") {
		return false
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	return parsed.Scheme == "http" || parsed.Scheme == "https"
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if _, exists := keys[item]; !exists {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

// ToScanContext adds discovery results to ScanContext
func (dr *DiscoveryResult) ToScanContext(ctx *models.ScanContext) {
	// Add all discovered endpoints
	for _, link := range dr.Links {
		endpoint := models.Endpoint{
			URL:        link,
			Method:     "GET",
			StatusCode: 0, // Unknown until probed
		}
		ctx.AddEndpoint(endpoint)
	}

	// Add API endpoints with higher risk score
	for _, apiURL := range dr.APIEndpoints {
		endpoint := models.Endpoint{
			URL:        apiURL,
			Method:     "GET",
			StatusCode: 0,
			RiskScore:  3.0, // APIs are higher risk
		}
		ctx.AddEndpoint(endpoint)
	}

	// Add forms as endpoints with extracted parameters
	for _, form := range dr.Forms {
		params := []models.Parameter{}
		for _, field := range form.Fields {
			param := models.Parameter{
				Name:     field.Name,
				Type:     "body",
				DataType: field.Type,
				Value:    field.Value,
			}
			params = append(params, param)
		}

		endpoint := models.Endpoint{
			URL:        form.Action,
			Method:     form.Method,
			Parameters: params,
			RiskScore:  calculateFormRiskScore(form),
		}
		ctx.AddEndpoint(endpoint)
	}

	// Add interesting paths found
	for _, pathResult := range dr.CommonPaths {
		if pathResult.Found {
			endpoint := models.Endpoint{
				URL:        dr.BaseURL + pathResult.Path,
				Method:     "GET",
				StatusCode: pathResult.StatusCode,
				RiskScore:  calculatePathRiskScore(pathResult.Path),
			}
			ctx.AddEndpoint(endpoint)
		}
	}

	// Add metadata
	if dr.RobotsTxt != nil {
		ctx.Metadata["robots_txt_disallow"] = dr.RobotsTxt.Disallow
		ctx.Metadata["robots_txt_sitemaps"] = dr.RobotsTxt.Sitemaps
	}

	if len(dr.SitemapXML) > 0 {
		ctx.Metadata["sitemap_urls"] = dr.SitemapXML
	}
}

// calculateFormRiskScore calculates risk score for a form
func calculateFormRiskScore(form FormInfo) float64 {
	score := 2.0 // Base score for forms

	// File upload forms are high risk
	if form.HasFile {
		score += 3.5
	}

	// Login forms are interesting
	if form.HasPassword {
		score += 2.0
	}

	// POST forms are more interesting than GET
	if form.Method == "POST" {
		score += 1.0
	}

	return score
}

// calculatePathRiskScore calculates risk score based on path
func calculatePathRiskScore(path string) float64 {
	pathLower := strings.ToLower(path)

	highRiskPaths := map[string]float64{
		"/admin":          8.0,
		"/administrator":  8.0,
		"/.env":           9.5,
		"/.git":           9.0,
		"/config":         7.0,
		"/backup":         7.5,
		"/upload":         7.0,
		"/phpmyadmin":     8.5,
		"/console":        7.5,
	}

	for pattern, risk := range highRiskPaths {
		if strings.Contains(pathLower, pattern) {
			return risk
		}
	}

	// API endpoints
	if strings.Contains(pathLower, "/api") || strings.Contains(pathLower, "/graphql") {
		return 5.0
	}

	return 3.0 // Default for interesting paths
}
