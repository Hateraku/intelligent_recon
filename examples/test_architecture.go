package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hateraku/bughunt/pkg/core/dns"
	"github.com/hateraku/bughunt/pkg/models"
	"github.com/hateraku/bughunt/pkg/plugins"
	"github.com/hateraku/bughunt/pkg/plugins/subfinder"
)

func main() {
	fmt.Println("🚀 BugHunt Framework - Architecture Test")
	fmt.Println("==========================================\n")

	// 1. Crea il contesto globale dello scan
	scanCtx := models.NewScanContext()

	// 2. Inizializza il plugin registry
	registry := plugins.NewRegistry()
	registry.Register(subfinder.New())

	fmt.Println("📦 Plugin registrati:")
	for _, name := range registry.List() {
		plugin, _ := registry.Get(name)
		installed := "❌"
		if plugin.IsInstalled() {
			installed = "✅"
		}
		fmt.Printf("  %s %s (v%s)\n", installed, name, plugin.Version())
	}
	fmt.Println()

	// 3. Test DNS Module
	target := "example.com"
	fmt.Printf("🔍 DNS Lookup: %s\n", target)

	dnsModule := dns.New()
	ctx := context.Background()

	dnsResult, err := dnsModule.Lookup(ctx, target)
	if err != nil {
		fmt.Printf("  ❌ Error: %v\n", err)
	} else {
		fmt.Printf("  ✅ A Records: %v\n", dnsResult.ARecords)
		fmt.Printf("  ✅ AAAA Records: %v\n", dnsResult.AAAARecords)
		fmt.Printf("  ✅ CNAME: %v\n", dnsResult.CNAMERecords)
		fmt.Printf("  ✅ MX: %v\n", dnsResult.MXRecords)
		fmt.Printf("  ✅ NS: %v\n", dnsResult.NSRecords)
		fmt.Printf("  ✅ Cloud Provider: %s\n", dnsResult.CloudProvider)
		fmt.Printf("  ✅ Wildcard: %v\n", dnsResult.IsWildcard)
		fmt.Printf("  ✅ AXFR Possible: %v\n", dnsResult.AXFRPossible)

		// Aggiungi al contesto
		dnsCtx := dnsResult.ToScanContext()
		scanCtx.Targets = append(scanCtx.Targets, dnsCtx.Targets...)
		scanCtx.CloudProviders = append(scanCtx.CloudProviders, dnsCtx.CloudProviders...)
	}
	fmt.Println()

	// 4. Test Plugin Subfinder (se installato)
	fmt.Printf("🔍 Subdomain Enumeration: %s\n", target)
	subfinderPlugin, _ := registry.Get("subfinder")

	if subfinderPlugin.IsInstalled() {
		pluginInput := &plugins.PluginInput{
			Targets: []string{target},
			Options: map[string]interface{}{
				"threads": 10,
			},
			Context: scanCtx,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		output, err := subfinderPlugin.Execute(ctx, pluginInput)
		if err != nil {
			fmt.Printf("  ❌ Error: %v\n", err)
		} else {
			fmt.Printf("  ✅ Found %d subdomains:\n", len(output.Subdomains))
			for i, sub := range output.Subdomains {
				if i < 10 { // Mostra solo i primi 10
					fmt.Printf("     - %s\n", sub)
				}
			}
			if len(output.Subdomains) > 10 {
				fmt.Printf("     ... and %d more\n", len(output.Subdomains)-10)
			}
		}
	} else {
		fmt.Println("  ⚠️  Subfinder not installed, skipping")
	}
	fmt.Println()

	// 5. Aggiungi endpoint di esempio al contesto
	scanCtx.AddEndpoint(models.Endpoint{
		URL:         "https://example.com/api/users?id=1",
		Method:      "GET",
		StatusCode:  200,
		Title:       "User API",
		ContentType: "application/json",
		Parameters: []models.Parameter{
			{Name: "id", Type: "query", DataType: "int", Value: "1"},
		},
		Technologies: []string{"Express", "Node.js"},
		RiskScore:    7.5,
	})

	scanCtx.AddEndpoint(models.Endpoint{
		URL:         "https://example.com/upload",
		Method:      "POST",
		StatusCode:  200,
		Title:       "File Upload",
		ContentType: "text/html",
		Technologies: []string{"PHP"},
		RiskScore:    8.9,
	})

	scanCtx.AddTechnology("Express")
	scanCtx.AddTechnology("PHP")

	// 6. Aggiungi vulnerabilità di esempio
	scanCtx.AddVulnerability(models.Vulnerability{
		ID:          "VULN-001",
		Type:        models.VulnIDOR,
		Severity:    models.SeverityHigh,
		Score:       7.5,
		Title:       "Potential IDOR on /api/users",
		Description: "Parameter 'id' can be manipulated to access other users",
		URL:         "https://example.com/api/users?id=1",
		Parameter:   "id",
		Payload:     "id=2",
		Evidence:    "Different user data returned",
		FoundBy:     "idor_module",
		DiscoveredAt: time.Now(),
	})

	// 7. Mostra contesto finale
	fmt.Println("📊 Scan Context Summary")
	fmt.Println("=======================")
	fmt.Printf("Targets: %d\n", len(scanCtx.Targets))
	fmt.Printf("Endpoints: %d\n", len(scanCtx.Endpoints))
	fmt.Printf("Technologies: %v\n", scanCtx.Technologies)
	fmt.Printf("Cloud Providers: %v\n", scanCtx.CloudProviders)
	fmt.Printf("Vulnerabilities: %d\n", len(scanCtx.Vulnerabilities))
	fmt.Printf("Anomalies: %d\n", len(scanCtx.Anomalies))
	fmt.Println()

	// 8. High-risk endpoints
	fmt.Println("🎯 High-Risk Endpoints (score > 7.0)")
	fmt.Println("====================================")
	highRisk := scanCtx.GetEndpointsByRisk()
	for _, ep := range highRisk {
		if ep.RiskScore > 7.0 {
			fmt.Printf("  [%.1f/10] %s %s\n", ep.RiskScore, ep.Method, ep.URL)
		}
	}
	fmt.Println()

	// 9. Export JSON
	fmt.Println("📄 JSON Export")
	fmt.Println("==============")
	jsonData, _ := json.MarshalIndent(scanCtx, "", "  ")
	fmt.Println(string(jsonData[:500]) + "...")
}
