package subfinder

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/hateraku/bughunt/pkg/plugins"
)

// SubfinderPlugin wraps subfinder tool
type SubfinderPlugin struct {
	binaryPath string
}

// New crea una nuova istanza del plugin
func New() *SubfinderPlugin {
	return &SubfinderPlugin{
		binaryPath: "subfinder", // Assume subfinder sia in PATH
	}
}

// Name ritorna il nome del plugin
func (s *SubfinderPlugin) Name() string {
	return "subfinder"
}

// Version ritorna la versione di subfinder
func (s *SubfinderPlugin) Version() string {
	cmd := exec.Command(s.binaryPath, "-version")
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// IsInstalled controlla se subfinder è installato
func (s *SubfinderPlugin) IsInstalled() bool {
	_, err := exec.LookPath(s.binaryPath)
	return err == nil
}

// Execute esegue subfinder
func (s *SubfinderPlugin) Execute(ctx context.Context, input *plugins.PluginInput) (*plugins.PluginOutput, error) {
	if len(input.Targets) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}

	// Costruisci comando
	args := []string{
		"-d", input.Targets[0], // Domain
		"-silent",              // Output solo subdomain
		"-all",                 // Usa tutte le source
	}

	// Aggiungi opzioni custom se presenti
	if input.Options != nil {
		if threads, ok := input.Options["threads"].(int); ok {
			args = append(args, "-t", fmt.Sprintf("%d", threads))
		}
		if recursive, ok := input.Options["recursive"].(bool); ok && recursive {
			args = append(args, "-recursive")
		}
	}

	// Esegui subfinder
	cmd := exec.CommandContext(ctx, s.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return &plugins.PluginOutput{
			RawOutput: stdout.String(),
			Error:     fmt.Errorf("subfinder failed: %v, stderr: %s", err, stderr.String()),
		}, err
	}

	// Parsea output (subfinder stampa un subdomain per riga)
	subdomains := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(stdout.Bytes()))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}

	return &plugins.PluginOutput{
		RawOutput:  stdout.String(),
		Subdomains: subdomains,
		Metadata: map[string]interface{}{
			"total_found": len(subdomains),
			"tool":        "subfinder",
		},
	}, nil
}

// Validate valida la configurazione
func (s *SubfinderPlugin) Validate(config map[string]interface{}) error {
	// Valida che le opzioni siano corrette
	if threads, ok := config["threads"]; ok {
		if _, ok := threads.(int); !ok {
			return fmt.Errorf("threads must be an integer")
		}
	}
	return nil
}
