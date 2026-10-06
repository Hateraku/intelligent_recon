package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hateraku/bughunt/pkg/core/anomaly"
	httpPkg "github.com/hateraku/bughunt/pkg/http"
	"github.com/hateraku/bughunt/pkg/models"
)

func main() {
	fmt.Println("🔍 Testing Anomaly Detection Module")
	fmt.Println(repeatChar("=", 70))
	fmt.Println()

	// Test endpoints with potential vulnerabilities
	testEndpoints := []struct {
		URL         string
		Description string
		Parameters  []models.Parameter
	}{
		{
			URL:         "https://example.com/search",
			Description: "Search endpoint with query parameter",
			Parameters: []models.Parameter{
				{Name: "q", Type: "string", Value: "test"},
			},
		},
		{
			URL:         "https://httpbin.org/get",
			Description: "HTTPBin test endpoint (reflection test)",
			Parameters: []models.Parameter{
				{Name: "test", Type: "string", Value: "normal"},
			},
		},
	}

	ctx := context.Background()
	scanContext := models.NewScanContext()

	// Create anomaly detection module with config
	config := &anomaly.Config{
		EnableStacktrace:    true,
		EnableErrorPage:     true,
		EnableTimingAttack:  true,
		EnableReflection:    true,
		TimeoutMs:           5000,
		MaxPayloadsPerParam: 3, // Limit to 3 payloads per parameter for demo
	}
	anomalyModule := anomaly.New(httpPkg.Client, config)

	for _, test := range testEndpoints {
		fmt.Printf("🎯 Target: %s\n", test.URL)
		fmt.Printf("📝 Description: %s\n", test.Description)
		fmt.Println(repeatChar("-", 70))

		// Create endpoint model
		endpoint := &models.Endpoint{
			URL:        test.URL,
			Method:     "GET",
			Parameters: test.Parameters,
		}

		// Perform anomaly detection
		result, err := anomalyModule.Detect(ctx, endpoint)
		if err != nil {
			log.Printf("❌ Failed to detect anomalies on %s: %v\n\n", test.URL, err)
			continue
		}

		// Display results
		fmt.Println("📊 Anomaly Detection Results:")
		fmt.Println()

		if len(result.Anomalies) == 0 {
			fmt.Println("  ✅ No anomalies detected")
		} else {
			fmt.Printf("  🚨 Found %d anomalies:\n\n", len(result.Anomalies))
			for i, anom := range result.Anomalies {
				severityIcon := getSeverityIcon(anom.Severity)
				fmt.Printf("  Anomaly %d:\n", i+1)
				fmt.Printf("    %s Severity: %s\n", severityIcon, anom.Severity)
				fmt.Printf("    🏷️  Type: %s\n", anom.Type)
				if anom.Parameter != "" {
					fmt.Printf("    📌 Parameter: %s\n", anom.Parameter)
				}
				if anom.Payload != "" {
					fmt.Printf("    💉 Payload: %s\n", truncate(anom.Payload, 50))
				}
				fmt.Printf("    📄 Description: %s\n", anom.Description)
				fmt.Printf("    ⚠️  Risk Score: %.1f/10.0\n", anom.RiskScore)
				if anom.Evidence != "" {
					fmt.Printf("    🔍 Evidence: %s\n", truncate(anom.Evidence, 100))
				}
				fmt.Println()
			}
		}

		fmt.Printf("📈 Overall Risk Score: %.1f/10.0\n", result.RiskScore)
		fmt.Printf("🧪 Parameters Tested: %d\n", result.TestedCount)
		fmt.Println()

		// Add to scan context
		result.ToScanContext(scanContext)

		fmt.Println()
	}

	// Display ScanContext summary
	fmt.Println(repeatChar("=", 70))
	fmt.Println("📊 Scan Context Summary")
	fmt.Println(repeatChar("=", 70))
	fmt.Printf("Total Anomalies Detected: %d\n", len(scanContext.Anomalies))
	fmt.Println()

	// Group anomalies by severity
	if len(scanContext.Anomalies) > 0 {
		severityMap := make(map[string][]models.Anomaly)
		for _, anom := range scanContext.Anomalies {
			severityMap[anom.Severity] = append(severityMap[anom.Severity], anom)
		}

		fmt.Println("🎯 Anomalies by Severity:")
		for _, severity := range []string{"critical", "high", "medium", "low"} {
			if anoms, ok := severityMap[severity]; ok {
				icon := getSeverityIcon(severity)
				fmt.Printf("  %s %s: %d\n", icon, severity, len(anoms))
			}
		}
		fmt.Println()

		// Group by type
		typeMap := make(map[string]int)
		for _, anom := range scanContext.Anomalies {
			typeMap[anom.Type]++
		}

		fmt.Println("🔬 Anomalies by Type:")
		for anomType, count := range typeMap {
			fmt.Printf("  - %s: %d\n", anomType, count)
		}
		fmt.Println()
	}

	// Export sample to JSON
	fmt.Println("💾 Sample JSON Export (first anomaly):")
	if len(scanContext.Anomalies) > 0 {
		jsonData, err := json.MarshalIndent(scanContext.Anomalies[0], "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal JSON: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Println("  No anomalies to export")
	}

	fmt.Println()
	fmt.Println("✅ Anomaly detection test complete!")
	fmt.Println()
	fmt.Println("📝 Note: This is a demonstration. Real vulnerabilities require manual validation.")
	fmt.Println("   Anomaly detection highlights suspicious behaviors, not confirmed exploits.")
}

func repeatChar(char string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += char
	}
	return result
}

func getSeverityIcon(severity string) string {
	switch severity {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
