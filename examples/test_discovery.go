package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hateraku/bughunt/pkg/core/discovery"
	httpPkg "github.com/hateraku/bughunt/pkg/http"
	"github.com/hateraku/bughunt/pkg/models"
)

func main() {
	fmt.Println("🔍 Testing Endpoint Discovery Module")
	fmt.Println(repeatChar("=", 70))
	fmt.Println()

	// Test targets (using sites with more content)
	targets := []string{
		"https://github.com",
	}

	ctx := context.Background()
	scanContext := models.NewScanContext()

	// Create discovery module with config
	config := &discovery.Config{
		MaxDepth:  0, // No recursive crawling for demo
		UserAgent: "Mozilla/5.0 (compatible; BugHunt/1.0)",
	}
	discoveryModule := discovery.New(httpPkg.Client, config)

	for _, target := range targets {
		fmt.Printf("🎯 Target: %s\n", target)
		fmt.Println(repeatChar("-", 70))

		// Perform discovery
		result, err := discoveryModule.Discover(ctx, target)
		if err != nil {
			log.Printf("❌ Failed to discover %s: %v\n\n", target, err)
			continue
		}

		// Display results
		fmt.Println("📊 Discovery Results:")
		fmt.Println()

		// Robots.txt
		if result.RobotsTxt != nil {
			fmt.Println("🤖 robots.txt:")
			if len(result.RobotsTxt.Disallow) > 0 {
				fmt.Printf("   Disallow (%d):\n", len(result.RobotsTxt.Disallow))
				for i, path := range result.RobotsTxt.Disallow {
					if i < 5 { // Show first 5
						fmt.Printf("     - %s\n", path)
					}
				}
				if len(result.RobotsTxt.Disallow) > 5 {
					fmt.Printf("     ... and %d more\n", len(result.RobotsTxt.Disallow)-5)
				}
			}
			if len(result.RobotsTxt.Sitemaps) > 0 {
				fmt.Printf("   Sitemaps: %v\n", result.RobotsTxt.Sitemaps)
			}
			fmt.Println()
		}

		// Sitemap.xml
		if len(result.SitemapXML) > 0 {
			fmt.Printf("🗺️  sitemap.xml: Found %d URLs\n", len(result.SitemapXML))
			for i, url := range result.SitemapXML {
				if i < 5 {
					fmt.Printf("   - %s\n", url)
				}
			}
			if len(result.SitemapXML) > 5 {
				fmt.Printf("   ... and %d more\n", len(result.SitemapXML)-5)
			}
			fmt.Println()
		}

		// Links
		if len(result.Links) > 0 {
			fmt.Printf("🔗 Links: Found %d links\n", result.TotalLinks)
			for i, link := range result.Links {
				if i < 10 {
					fmt.Printf("   - %s\n", link)
				}
			}
			if len(result.Links) > 10 {
				fmt.Printf("   ... and %d more\n", len(result.Links)-10)
			}
			fmt.Println()
		}

		// Forms
		if len(result.Forms) > 0 {
			fmt.Printf("📝 Forms: Found %d forms\n", result.TotalForms)
			for i, form := range result.Forms {
				fmt.Printf("   Form %d:\n", i+1)
				fmt.Printf("     Action: %s\n", form.Action)
				fmt.Printf("     Method: %s\n", form.Method)
				fmt.Printf("     Fields: %d\n", len(form.Fields))
				if form.HasFile {
					fmt.Printf("     🔴 Has file upload!\n")
				}
				if form.HasPassword {
					fmt.Printf("     🔑 Has password field!\n")
				}
				for _, field := range form.Fields {
					fmt.Printf("       - %s (%s)\n", field.Name, field.Type)
				}
			}
			fmt.Println()
		}

		// API Endpoints
		if len(result.APIEndpoints) > 0 {
			fmt.Printf("🔌 API Endpoints: Found %d\n", result.TotalAPIEndpoints)
			for _, api := range result.APIEndpoints {
				fmt.Printf("   - %s\n", api)
			}
			fmt.Println()
		}

		// JS Files
		if len(result.JSFiles) > 0 {
			fmt.Printf("📜 JavaScript Files: Found %d\n", len(result.JSFiles))
			for i, jsFile := range result.JSFiles {
				if i < 5 {
					fmt.Printf("   - %s\n", jsFile)
				}
			}
			if len(result.JSFiles) > 5 {
				fmt.Printf("   ... and %d more\n", len(result.JSFiles)-5)
			}
			fmt.Println()
		}

		// Common Paths
		if len(result.CommonPaths) > 0 {
			fmt.Printf("🎯 Common Paths Found: %d interesting paths\n", len(result.CommonPaths))
			for _, pathResult := range result.CommonPaths {
				status := "✅"
				if pathResult.StatusCode >= 400 {
					status = "❌"
				} else if pathResult.StatusCode >= 300 {
					status = "↪️"
				}
				fmt.Printf("   %s [%d] %s", status, pathResult.StatusCode, pathResult.Path)
				if pathResult.Redirect != "" {
					fmt.Printf(" → %s", pathResult.Redirect)
				}
				fmt.Println()
			}
			fmt.Println()
		}

		// Add to scan context
		result.ToScanContext(scanContext)

		fmt.Println()
	}

	// Display ScanContext summary
	fmt.Println(repeatChar("=", 70))
	fmt.Println("📊 Scan Context Summary")
	fmt.Println(repeatChar("=", 70))
	fmt.Printf("Total Endpoints: %d\n", len(scanContext.Endpoints))
	fmt.Printf("Total Vulnerabilities: %d\n", len(scanContext.Vulnerabilities))
	fmt.Printf("Total Anomalies: %d\n", len(scanContext.Anomalies))
	fmt.Println()

	// High-risk endpoints
	highRisk := scanContext.GetEndpointsByRisk()
	if len(highRisk) > 0 {
		fmt.Println("🎯 High-Risk Endpoints (top 10):")
		count := 10
		if len(highRisk) < count {
			count = len(highRisk)
		}
		for i := 0; i < count; i++ {
			ep := highRisk[i]
			method := ep.Method
			if method == "" {
				method = "GET"
			}
			fmt.Printf("  %d. [%.1f] %s %s", i+1, ep.RiskScore, method, ep.URL)
			if len(ep.Parameters) > 0 {
				fmt.Printf(" (%d params)", len(ep.Parameters))
			}
			fmt.Println()
		}
		fmt.Println()
	}

	// Export sample to JSON
	fmt.Println("💾 Sample JSON Export (first endpoint):")
	if len(scanContext.Endpoints) > 0 {
		jsonData, err := json.MarshalIndent(scanContext.Endpoints[0], "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal JSON: %v", err)
		}
		fmt.Println(string(jsonData))
	}

	fmt.Println()
	fmt.Println("✅ Discovery test complete!")
}

func repeatChar(char string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += char
	}
	return result
}
