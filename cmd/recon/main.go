package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	httpPkg "github.com/hateraku/bughunt/pkg/http"
	"github.com/hateraku/bughunt/pkg/subdomain"
	"github.com/hateraku/bughunt/pkg/tech"
	"github.com/spf13/cobra"
)

// Job represents a target to process
type Job struct {
	Target string
}

// Result represents the output of a job
type Result struct {
	Target        string   `json:"target"`
	IPs           []string `json:"ips,omitempty"`
	StatusCode    int      `json:"status_code,omitempty"`
	Title         string   `json:"title,omitempty"`
	Server        string   `json:"server,omitempty"`
	ContentLength int64    `json:"content_length,omitempty"`
	Tech          []string `json:"tech,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// Config holds runtime configuration
type Config struct {
	Targets    []string
	Workers    int
	Timeout    int
	OutputJSON bool
	Silent     bool
	Verbose    bool
	InputFile  string
}

var config Config

// worker is a goroutine that reads Jobs from jobsCh and writes Results to resultsCh
func worker(id int, wg *sync.WaitGroup, jobsCh <-chan Job, resultsCh chan<- Result) {
	defer wg.Done()

	for job := range jobsCh {
		// DNS resolution
		ips, dnsErr := subdomain.Lookup(job.Target)

		// HTTP probing
		var status int
		var title, server string
		var clen int64
		var techList []string
		var httpErr error

		probeResult, err := httpPkg.Probe(job.Target)
		if err != nil {
			httpErr = err
		} else {
			status = probeResult.StatusCode
			title = probeResult.Title
			server = probeResult.Server
			clen = probeResult.ContentLength
			techList = tech.Detect(server, probeResult.Headers, probeResult.Body)
		}

		// Combine errors
		var errorMsg string
		if dnsErr != nil && httpErr != nil {
			errorMsg = fmt.Sprintf("DNS: %v; HTTP: %v", dnsErr, httpErr)
		} else if dnsErr != nil {
			errorMsg = fmt.Sprintf("DNS: %v", dnsErr)
		} else if httpErr != nil {
			errorMsg = fmt.Sprintf("HTTP: %v", httpErr)
		}

		resultsCh <- Result{
			Target:        job.Target,
			IPs:           ips,
			StatusCode:    status,
			Title:         title,
			Server:        server,
			ContentLength: clen,
			Tech:          techList,
			Error:         errorMsg,
		}
	}
}

// runEngine orchestrates worker creation, job distribution, and result collection
func runEngine(targets []string, numWorkers int) []Result {
	jobsCh := make(chan Job)
	resultsCh := make(chan Result)

	var wg sync.WaitGroup

	// Start workers
	for i := 1; i <= numWorkers; i++ {
		wg.Add(1)
		go worker(i, &wg, jobsCh, resultsCh)
	}

	// Goroutine to close resultsCh when workers are done
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Send jobs
	go func() {
		for _, t := range targets {
			jobsCh <- Job{Target: t}
		}
		close(jobsCh)
	}()

	// Collect results
	var results []Result
	for res := range resultsCh {
		results = append(results, res)
	}

	return results
}

// loadTargets loads targets from various sources
func loadTargets() ([]string, error) {
	var targets []string

	// From command line args
	if len(config.Targets) > 0 {
		targets = append(targets, config.Targets...)
	}

	// From input file
	if config.InputFile != "" {
		file, err := os.Open(config.InputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open input file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading input file: %v", err)
		}
	}

	// From stdin if no targets yet
	if len(targets) == 0 {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, line)
				}
			}
			if err := scanner.Err(); err != nil {
				return nil, fmt.Errorf("error reading stdin: %v", err)
			}
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}

	return targets, nil
}

// printResults outputs results based on configuration
func printResults(results []Result, elapsed time.Duration) {
	if config.OutputJSON {
		output := map[string]interface{}{
			"results": results,
			"stats": map[string]interface{}{
				"total":   len(results),
				"elapsed": elapsed.String(),
			},
		}
		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
		fmt.Println(string(jsonData))
		return
	}

	// Terminal output
	if !config.Silent {
		fmt.Printf("\n[*] Finished in %s\n\n", elapsed)
	}

	for _, r := range results {
		if r.Error != "" {
			if !config.Silent {
				fmt.Printf("[-] %s -> error: %s\n", r.Target, r.Error)
			}
			continue
		}

		if config.Verbose {
			fmt.Printf("[+] %s\n", r.Target)
			fmt.Printf("    IPs:     %v\n", r.IPs)
			fmt.Printf("    Status:  %d\n", r.StatusCode)
			fmt.Printf("    Title:   %s\n", r.Title)
			fmt.Printf("    Server:  %s\n", r.Server)
			fmt.Printf("    Size:    %d bytes\n", r.ContentLength)
			fmt.Printf("    Tech:    %v\n\n", r.Tech)
		} else {
			fmt.Printf("[+] %s -> Status: %d | Title: %s | Server: %s | Tech: %v\n",
				r.Target, r.StatusCode, r.Title, r.Server, r.Tech)
		}
	}
}

var rootCmd = &cobra.Command{
	Use:   "recon [targets...]",
	Short: "Fast reconnaissance tool for bug hunting",
	Long: `A concurrent reconnaissance module that performs DNS lookups,
HTTP probing, and technology fingerprinting on target domains.`,
	Example: `  # Scan single target
  recon example.com

  # Scan multiple targets
  recon example.com google.com

  # From file
  recon -i targets.txt

  # From stdin
  cat targets.txt | recon

  # JSON output
  recon -j example.com

  # Verbose mode
  recon -v example.com

  # Custom workers
  recon -w 10 -i targets.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		config.Targets = args

		// Load targets
		targets, err := loadTargets()
		if err != nil {
			return err
		}

		if !config.Silent && !config.OutputJSON {
			fmt.Printf("[*] Starting recon on %d targets with %d workers\n", len(targets), config.Workers)
		}

		start := time.Now()
		results := runEngine(targets, config.Workers)
		elapsed := time.Since(start)

		printResults(results, elapsed)
		return nil
	},
}

func init() {
	rootCmd.Flags().IntVarP(&config.Workers, "workers", "w", 4, "Number of concurrent workers")
	rootCmd.Flags().IntVarP(&config.Timeout, "timeout", "t", 7, "HTTP timeout in seconds")
	rootCmd.Flags().BoolVarP(&config.OutputJSON, "json", "j", false, "Output results as JSON")
	rootCmd.Flags().BoolVarP(&config.Silent, "silent", "s", false, "Silent mode (errors only)")
	rootCmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().StringVarP(&config.InputFile, "input", "i", "", "Input file with targets (one per line)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
