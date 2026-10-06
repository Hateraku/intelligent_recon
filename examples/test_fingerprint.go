package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hateraku/bughunt/pkg/core/fingerprint"
	httpPkg "github.com/hateraku/bughunt/pkg/http"
	"github.com/hateraku/bughunt/pkg/models"
)

func main() {
	fmt.Println("🔍 Testing Technology Fingerprinting Module")
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println()

	// Test targets with different tech stacks
	targets := []string{
		"example.com",         // Basic site
		"wordpress.org",       // WordPress
		"github.com",          // Modern JS framework
		"stackoverflow.com",   // Complex site
	}

	ctx := context.Background()
	scanContext := models.NewScanContext()

	// Create HTTP client (use the one from http package)
	client := httpPkg.Client

	// Create fingerprint module
	fpModule := fingerprint.New(client)

	for _, target := range targets {
		fmt.Printf("🎯 Target: %s\n", target)
		fmt.Println(repeatChar("-", 60))

		// First, do HTTP probe to get body and headers
		probeResult, err := httpPkg.ProbeWithContext(ctx, target)
		if err != nil {
			log.Printf("❌ Failed to probe %s: %v\n\n", target, err)
			continue
		}

		fmt.Printf("✅ Status: %d\n", probeResult.StatusCode)
		fmt.Printf("🌐 Server: %s\n", probeResult.Server)
		fmt.Printf("📄 Title: %s\n", probeResult.Title)
		fmt.Printf("🔒 HTTPS: %v\n", probeResult.IsHTTPS)
		fmt.Println()

		// Perform fingerprinting
		fpResult := fpModule.Fingerprint(ctx, probeResult.FinalURL, probeResult.Body, probeResult.Headers)

		// Display results
		fmt.Println("🔎 Technology Fingerprinting Results:")
		fmt.Println()

		if fpResult.WebServer != "" {
			fmt.Printf("  🖥️  Web Server: %s\n", fpResult.WebServer)
		}

		if len(fpResult.Languages) > 0 {
			fmt.Printf("  💻 Languages: %v\n", fpResult.Languages)
		}

		if len(fpResult.Frameworks) > 0 {
			fmt.Printf("  🏗️  Frameworks: %v\n", fpResult.Frameworks)
			for _, fw := range fpResult.Frameworks {
				if conf, ok := fpResult.Confidence[fw]; ok {
					fmt.Printf("     └─ %s: %.0f%% confidence\n", fw, conf*100)
				}
			}
		}

		if len(fpResult.CMS) > 0 {
			fmt.Printf("  📦 CMS: %v\n", fpResult.CMS)
			for _, cms := range fpResult.CMS {
				if conf, ok := fpResult.Confidence[cms]; ok {
					fmt.Printf("     └─ %s: %.0f%% confidence\n", cms, conf*100)
				}
			}
		}

		if len(fpResult.JSFrameworks) > 0 {
			fmt.Printf("  ⚛️  JS Frameworks: %v\n", fpResult.JSFrameworks)
		}

		if len(fpResult.CDN) > 0 {
			fmt.Printf("  🌍 CDN: %v\n", fpResult.CDN)
		}

		if len(fpResult.WAF) > 0 {
			fmt.Printf("  🛡️  WAF: %v\n", fpResult.WAF)
		}

		if len(fpResult.Other) > 0 {
			fmt.Printf("  🔧 Other: %v\n", fpResult.Other)
		}

		if fpResult.FaviconHash != "" {
			fmt.Printf("  🎨 Favicon Hash: %s\n", fpResult.FaviconHash[:20]+"...")
		}

		// Add to scan context
		fpResult.ToScanContext(scanContext)
		probeResult.ToScanContext(scanContext)

		fmt.Println()
		fmt.Println()
	}

	// Display ScanContext summary
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("📊 Scan Context Summary")
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Printf("Total Targets: %d\n", len(scanContext.Targets))
	fmt.Printf("Total Endpoints: %d\n", len(scanContext.Endpoints))
	fmt.Printf("Total Technologies Detected: %d\n", len(scanContext.Technologies))
	fmt.Printf("Total Vulnerabilities: %d\n", len(scanContext.Vulnerabilities))
	fmt.Printf("Total Anomalies: %d\n", len(scanContext.Anomalies))
	fmt.Println()

	// Display detected technologies
	if len(scanContext.Technologies) > 0 {
		fmt.Println("🔧 Detected Technologies:")
		techMap := make(map[string]int)
		for _, tech := range scanContext.Technologies {
			techMap[tech]++
		}
		for tech, count := range techMap {
			fmt.Printf("  - %s (found in %d target(s))\n", tech, count)
		}
		fmt.Println()
	}

	// Display high-risk endpoints
	highRisk := scanContext.GetEndpointsByRisk()
	if len(highRisk) > 0 {
		fmt.Println("🎯 High-Risk Endpoints (top 5):")
		count := 5
		if len(highRisk) < count {
			count = len(highRisk)
		}
		for i := 0; i < count; i++ {
			ep := highRisk[i]
			fmt.Printf("  %d. [%.1f] %s - %s\n", i+1, ep.RiskScore, ep.URL, ep.Title)
		}
		fmt.Println()
	}

	// Export to JSON
	fmt.Println("💾 Exporting to JSON...")
	jsonData, err := json.MarshalIndent(scanContext, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	// Display condensed JSON (first 1000 chars)
	if len(jsonData) > 1000 {
		fmt.Printf("%s\n... (truncated, %d total bytes)\n", string(jsonData[:1000]), len(jsonData))
	} else {
		fmt.Println(string(jsonData))
	}

	fmt.Println()
	fmt.Println("✅ Fingerprinting test complete!")
}

func repeatChar(char string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += char
	}
	return result
}
