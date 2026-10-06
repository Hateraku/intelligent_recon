package plugins

import (
	"context"

	"github.com/hateraku/bughunt/pkg/models"
)

// Plugin rappresenta un tool esterno integrabile
type Plugin interface {
	// Name ritorna il nome del plugin
	Name() string

	// Version ritorna la versione del tool
	Version() string

	// IsInstalled controlla se il tool è installato nel sistema
	IsInstalled() bool

	// Execute esegue il tool con input e ritorna output
	Execute(ctx context.Context, input *PluginInput) (*PluginOutput, error)

	// Validate valida la configurazione del plugin
	Validate(config map[string]interface{}) error
}

// PluginInput è l'input generico per qualsiasi plugin
type PluginInput struct {
	// Targets da scansionare
	Targets []string `json:"targets"`

	// Opzioni specifiche del plugin
	Options map[string]interface{} `json:"options"`

	// Working directory
	WorkDir string `json:"work_dir"`

	// Contesto dello scan (cosa è stato trovato finora)
	// Questo permette ai plugin di essere "intelligenti"
	Context *models.ScanContext `json:"-"`
}

// PluginOutput è l'output generico da qualsiasi plugin
type PluginOutput struct {
	// Output grezzo del tool (stdout)
	RawOutput string `json:"raw_output"`

	// Output parsato (plugin-specific, può essere qualsiasi struct)
	Parsed interface{} `json:"parsed,omitempty"`

	// Nuovi endpoint scoperti
	Endpoints []string `json:"endpoints,omitempty"`

	// Subdomains scoperti (per plugin come subfinder)
	Subdomains []string `json:"subdomains,omitempty"`

	// Vulnerabilità trovate
	Vulnerabilities []*models.Vulnerability `json:"vulnerabilities,omitempty"`

	// Metadata aggiuntivi
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Errore se presente
	Error error `json:"-"`
}

// PluginRegistry gestisce tutti i plugin disponibili
type PluginRegistry struct {
	plugins map[string]Plugin
}

// NewRegistry crea un nuovo registry
func NewRegistry() *PluginRegistry {
	return &PluginRegistry{
		plugins: make(map[string]Plugin),
	}
}

// Register registra un plugin
func (r *PluginRegistry) Register(p Plugin) {
	r.plugins[p.Name()] = p
}

// Get ottiene un plugin per nome
func (r *PluginRegistry) Get(name string) (Plugin, bool) {
	p, ok := r.plugins[name]
	return p, ok
}

// List ritorna la lista di tutti i plugin registrati
func (r *PluginRegistry) List() []string {
	names := []string{}
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}

// ListInstalled ritorna solo i plugin installati
func (r *PluginRegistry) ListInstalled() []string {
	installed := []string{}
	for name, plugin := range r.plugins {
		if plugin.IsInstalled() {
			installed = append(installed, name)
		}
	}
	return installed
}
