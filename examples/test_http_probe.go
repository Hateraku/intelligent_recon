package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hateraku/bughunt/pkg/http"
	"github.com/hateraku/bughunt/pkg/models"
)

func main() {
	fmt.Println("🚀 Testing Enhanced HTTP Probe Module")
	fmt.Println("=" + string(make([]byte, 50)) + "=")
	fmt.Println()

	// Test targets
	targets := []string{
		"example.com",
		"google.com",
		"github.com",
	}

	ctx := context.Background()
	scanContext := models.NewScanContext()

	for _, target := range targets {
		fmt.Printf("🔍 Probing: %s\n", target)
		fmt.Println("-" + string(make([]byte, 50)) + "-")

		result, err := http.ProbeWithContext(ctx, target)
		if err != nil {
			log.Printf("❌ Error probing %s: %v\n\n", target, err)
			continue
		}

		// Display results
		fmt.Printf("✅ Status: %d\n", result.StatusCode)
		fmt.Printf("📄 Title: %s\n", result.Title)
		fmt.Printf("🌐 Server: %s\n", result.Server)
		fmt.Printf("🔒 HTTPS: %v\n", result.IsHTTPS)
		if result.TLSVersion != "" {
			fmt.Printf("🔐 TLS Version: %s\n", result.TLSVersion)
		}
		fmt.Printf("⏱️  Response Time: %v\n", result.ResponseTime)
		fmt.Printf("📊 Content-Type: %s\n", result.ContentType)
		fmt.Printf("📏 Content-Length: %d bytes\n", result.ContentLength)
		fmt.Printf("🎯 Final URL: %s\n", result.FinalURL)

		// Detection flags
		if result.HasWAF {
			fmt.Printf("🛡️  WAF Detected: %s\n", result.WAFType)
		}
		if result.IsAPI {
			fmt.Printf("🔌 API Detected\n")
		}
		if result.IsAdmin {
			fmt.Printf("⚠️  Admin Panel Detected\n")
		}
		if result.IsLogin {
			fmt.Printf("🔑 Login Page Detected\n")
		}
		if result.IsUpload {
			fmt.Printf("📤 Upload Functionality Detected\n")
		}

		// Redirects
		if len(result.Redirects) > 0 {
			fmt.Printf("\n🔀 Redirects (%d):\n", len(result.Redirects))
			for i, redirect := range result.Redirects {
				fmt.Printf("  %d. [%d] %s → %s\n", i+1, redirect.StatusCode, redirect.From, redirect.To)
			}
		}

		// Security Headers
		fmt.Println("\n🔒 Security Headers:")
		if result.SecurityHeaders.StrictTransportSecurity != "" {
			fmt.Printf("  ✅ HSTS: %s\n", result.SecurityHeaders.StrictTransportSecurity)
		} else if result.IsHTTPS {
			fmt.Printf("  ❌ HSTS: Missing\n")
		}
		if result.SecurityHeaders.ContentSecurityPolicy != "" {
			fmt.Printf("  ✅ CSP: Present\n")
		} else {
			fmt.Printf("  ❌ CSP: Missing\n")
		}
		if result.SecurityHeaders.XFrameOptions != "" {
			fmt.Printf("  ✅ X-Frame-Options: %s\n", result.SecurityHeaders.XFrameOptions)
		} else {
			fmt.Printf("  ❌ X-Frame-Options: Missing\n")
		}
		if result.SecurityHeaders.CORSAllowOrigin != "" {
			fmt.Printf("  ⚠️  CORS Allow-Origin: %s\n", result.SecurityHeaders.CORSAllowOrigin)
			if result.SecurityHeaders.CORSAllowCredentials != "" {
				fmt.Printf("  ⚠️  CORS Allow-Credentials: %s\n", result.SecurityHeaders.CORSAllowCredentials)
			}
		}

		// Risk Score
		endpoint := result.ToEndpoint()
		fmt.Printf("\n📊 Risk Score: %.1f/10.0\n", endpoint.RiskScore)

		// Add to scan context
		result.ToScanContext(scanContext)

		fmt.Println()
		fmt.Println()
	}

	// Display ScanContext Summary
	fmt.Println("=" + string(make([]byte, 50)) + "=")
	fmt.Println("📊 Scan Context Summary")
	fmt.Println("=" + string(make([]byte, 50)) + "=")
	fmt.Printf("Total Endpoints: %d\n", len(scanContext.Endpoints))
	fmt.Printf("Total Vulnerabilities: %d\n", len(scanContext.Vulnerabilities))
	fmt.Printf("Total Anomalies: %d\n", len(scanContext.Anomalies))

	// Display vulnerabilities
	if len(scanContext.Vulnerabilities) > 0 {
		fmt.Println("\n🚨 Vulnerabilities Found:")
		for i, vuln := range scanContext.Vulnerabilities {
			fmt.Printf("%d. [%s] %s\n", i+1, vuln.Severity, vuln.Title)
			fmt.Printf("   URL: %s\n", vuln.URL)
			fmt.Printf("   Evidence: %s\n", vuln.Evidence)
		}
	}

	// Display anomalies
	if len(scanContext.Anomalies) > 0 {
		fmt.Println("\n⚠️  Anomalies Found:")
		for i, anomaly := range scanContext.Anomalies {
			fmt.Printf("%d. [%s] %s\n", i+1, anomaly.Type, anomaly.Description)
			fmt.Printf("   URL: %s\n", anomaly.URL)
		}
	}

	// High risk endpoints
	highRisk := scanContext.GetEndpointsByRisk()
	if len(highRisk) > 0 {
		fmt.Println("\n🎯 High-Risk Endpoints (top 5):")
		count := 5
		if len(highRisk) < count {
			count = len(highRisk)
		}
		for i := 0; i < count; i++ {
			ep := highRisk[i]
			fmt.Printf("%d. [%.1f] %s - %s\n", i+1, ep.RiskScore, ep.URL, ep.Title)
		}
	}

	// Export JSON
	fmt.Println("\n💾 Exporting to JSON...")
	jsonData, err := json.MarshalIndent(scanContext, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	fmt.Println("✅ JSON Export:")
	fmt.Println(string(jsonData))
}
