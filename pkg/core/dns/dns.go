package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hateraku/bughunt/pkg/models"
)

// Module è il modulo DNS
type Module struct {
	timeout time.Duration
}

// New crea un nuovo modulo DNS
func New() *Module {
	return &Module{
		timeout: 5 * time.Second,
	}
}

// DNSResult contiene i risultati della lookup DNS
type DNSResult struct {
	Domain         string
	ARecords       []string
	AAAARecords    []string
	CNAMERecords   []string
	MXRecords      []string
	NSRecords      []string
	TXTRecords     []string
	IsWildcard     bool
	CloudProvider  string
	AXFRPossible   bool
	Error          error
}

// Lookup esegue una lookup DNS completa
func (m *Module) Lookup(ctx context.Context, domain string) (*DNSResult, error) {
	result := &DNSResult{
		Domain: domain,
	}

	// A Records (IPv4)
	result.ARecords = m.lookupA(domain)

	// AAAA Records (IPv6)
	result.AAAARecords = m.lookupAAAA(domain)

	// CNAME Records
	cname, err := m.lookupCNAME(domain)
	if err == nil && cname != "" {
		result.CNAMERecords = []string{cname}
		// Fingerprinting cloud provider da CNAME
		result.CloudProvider = m.detectCloudProvider(cname)
	}

	// MX Records
	result.MXRecords = m.lookupMX(domain)

	// NS Records
	result.NSRecords = m.lookupNS(domain)

	// TXT Records
	result.TXTRecords = m.lookupTXT(domain)

	// Wildcard detection
	result.IsWildcard = m.detectWildcard(domain)

	// AXFR test (Zone Transfer)
	result.AXFRPossible = m.testAXFR(domain, result.NSRecords)

	return result, nil
}

// lookupA risolve A records (IPv4)
func (m *Module) lookupA(domain string) []string {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return []string{}
	}

	var ipv4 []string
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip.String())
		}
	}
	return ipv4
}

// lookupAAAA risolve AAAA records (IPv6)
func (m *Module) lookupAAAA(domain string) []string {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return []string{}
	}

	var ipv6 []string
	for _, ip := range ips {
		if ip.To4() == nil && ip.To16() != nil {
			ipv6 = append(ipv6, ip.String())
		}
	}
	return ipv6
}

// lookupCNAME risolve CNAME record
func (m *Module) lookupCNAME(domain string) (string, error) {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return "", err
	}
	// Rimuovi trailing dot
	cname = strings.TrimSuffix(cname, ".")
	if cname == domain {
		return "", nil // Non è un CNAME
	}
	return cname, nil
}

// lookupMX risolve MX records
func (m *Module) lookupMX(domain string) []string {
	mxs, err := net.LookupMX(domain)
	if err != nil {
		return []string{}
	}

	var records []string
	for _, mx := range mxs {
		records = append(records, fmt.Sprintf("%s (priority %d)", mx.Host, mx.Pref))
	}
	return records
}

// lookupNS risolve NS records
func (m *Module) lookupNS(domain string) []string {
	nss, err := net.LookupNS(domain)
	if err != nil {
		return []string{}
	}

	var records []string
	for _, ns := range nss {
		records = append(records, strings.TrimSuffix(ns.Host, "."))
	}
	return records
}

// lookupTXT risolve TXT records
func (m *Module) lookupTXT(domain string) []string {
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return []string{}
	}
	return txts
}

// detectWildcard rileva se il dominio ha wildcard DNS
func (m *Module) detectWildcard(domain string) bool {
	// Testa un subdomain random
	randomSub := fmt.Sprintf("nonexistent-random-test-12345.%s", domain)
	ips, err := net.LookupIP(randomSub)

	// Se risolve, probabilmente è wildcard
	return err == nil && len(ips) > 0
}

// detectCloudProvider rileva il cloud provider dal CNAME
func (m *Module) detectCloudProvider(cname string) string {
	cname = strings.ToLower(cname)

	providers := map[string][]string{
		"AWS":              {"amazonaws.com", "cloudfront.net", "elb.amazonaws.com"},
		"Azure":            {"azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"},
		"GCP":              {"googlehosted.com", "appspot.com", "cloudfunctions.net"},
		"Cloudflare":       {"cloudflare.net", "cloudflare.com"},
		"Fastly":           {"fastly.net"},
		"Akamai":           {"akamaiedge.net", "akamaitechnologies.com"},
		"Netlify":          {"netlify.app", "netlify.com"},
		"Vercel":           {"vercel.app", "vercel.com"},
		"Heroku":           {"herokuapp.com", "herokussl.com"},
		"DigitalOcean":     {"digitaloceanspaces.com"},
		"GitHub Pages":     {"github.io"},
	}

	for provider, patterns := range providers {
		for _, pattern := range patterns {
			if strings.Contains(cname, pattern) {
				return provider
			}
		}
	}

	return "Unknown"
}

// testAXFR testa se è possibile un zone transfer (AXFR)
func (m *Module) testAXFR(domain string, nameservers []string) bool {
	// Per semplicità, questo è un placeholder
	// Un vero test AXFR richiederebbe librerie DNS più avanzate
	// come miekg/dns

	// TODO: Implementare vero test AXFR
	// Per ora ritorna false
	return false
}

// ToScanContext converte DNSResult in models per il context
func (result *DNSResult) ToScanContext() *models.ScanContext {
	ctx := models.NewScanContext()

	// Aggiungi target
	target := models.Target{
		Domain:    result.Domain,
		IPs:       append(result.ARecords, result.AAAARecords...),
		Scope:     "in-scope",
		CreatedAt: time.Now(),
	}
	ctx.Targets = append(ctx.Targets, target)

	// Aggiungi cloud provider se rilevato
	if result.CloudProvider != "Unknown" {
		ctx.CloudProviders = append(ctx.CloudProviders, result.CloudProvider)
	}

	// Aggiungi anomalia se AXFR è possibile
	if result.AXFRPossible {
		ctx.AddAnomaly(models.Anomaly{
			Type:        "dns_misconfiguration",
			URL:         result.Domain,
			Description: "Zone Transfer (AXFR) is possible",
			Severity:    models.SeverityHigh,
		})
	}

	// Aggiungi anomalia se wildcard
	if result.IsWildcard {
		ctx.AddAnomaly(models.Anomaly{
			Type:        "dns_wildcard",
			URL:         result.Domain,
			Description: "Wildcard DNS detected",
			Severity:    models.SeverityInfo,
		})
	}

	return ctx
}
