package models

import (
	"sync"
	"time"
)

// ScanContext è il contesto condiviso tra tutti i moduli
// Contiene tutto ciò che è stato scoperto finora
type ScanContext struct {
	mu sync.RWMutex

	// Targets
	Targets []Target `json:"targets"`

	// Endpoints scoperti
	Endpoints []Endpoint `json:"endpoints"`

	// Tecnologie rilevate
	Technologies []string `json:"technologies"`

	// Cloud providers rilevati
	CloudProviders []string `json:"cloud_providers"`

	// Vulnerabilità trovate
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`

	// Anomalie rilevate
	Anomalies []Anomaly `json:"anomalies"`

	// Metadata aggiuntivi
	Metadata map[string]interface{} `json:"metadata"`
}

// Anomaly rappresenta un comportamento anomalo rilevato
type Anomaly struct {
	Type        string    `json:"type"`        // error, stacktrace, timeout, reflection, etc.
	Class       string    `json:"class,omitempty"` // classe di vulnerabilità (vulnclass), es. "Cross-site scripting (XSS)"
	CWE         string    `json:"cwe,omitempty"`   // riferimento CWE della classe, es. "CWE-79"
	Severity    string    `json:"severity"`    // critical, high, medium, low
	URL         string    `json:"url"`
	Method      string    `json:"method,omitempty"`
	Parameter   string    `json:"parameter,omitempty"`
	Payload     string    `json:"payload,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
	Description string    `json:"description"`
	RiskScore   float64   `json:"risk_score"`
	DetectedAt  time.Time `json:"detected_at"`
}

// NewScanContext crea un nuovo contesto
func NewScanContext() *ScanContext {
	return &ScanContext{
		Targets:         []Target{},
		Endpoints:       []Endpoint{},
		Technologies:    []string{},
		CloudProviders:  []string{},
		Vulnerabilities: []Vulnerability{},
		Anomalies:       []Anomaly{},
		Metadata:        make(map[string]interface{}),
	}
}

// AddEndpoint aggiunge un endpoint (thread-safe)
func (c *ScanContext) AddEndpoint(e Endpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Endpoints = append(c.Endpoints, e)
}

// AddTarget aggiunge un target (thread-safe)
func (c *ScanContext) AddTarget(t Target) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Targets = append(c.Targets, t)
}

// AddCloudProvider aggiunge un cloud provider se non esiste già (thread-safe)
func (c *ScanContext) AddCloudProvider(provider string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, p := range c.CloudProviders {
		if p == provider {
			return
		}
	}
	c.CloudProviders = append(c.CloudProviders, provider)
}

// AddVulnerability aggiunge una vulnerabilità (thread-safe)
func (c *ScanContext) AddVulnerability(v Vulnerability) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Vulnerabilities = append(c.Vulnerabilities, v)
}

// AddTechnology aggiunge una tecnologia se non esiste già
func (c *ScanContext) AddTechnology(tech string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, t := range c.Technologies {
		if t == tech {
			return
		}
	}
	c.Technologies = append(c.Technologies, tech)
}

// HasTechnology controlla se una tecnologia è stata rilevata
func (c *ScanContext) HasTechnology(tech string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, t := range c.Technologies {
		if t == tech {
			return true
		}
	}
	return false
}

// AddAnomaly aggiunge un'anomalia
func (c *ScanContext) AddAnomaly(a Anomaly) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Anomalies = append(c.Anomalies, a)
}

// SetMetadata imposta una chiave di metadata (thread-safe)
func (c *ScanContext) SetMetadata(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Metadata == nil {
		c.Metadata = make(map[string]interface{})
	}
	c.Metadata[key] = value
}

// GetEndpointsByRisk ritorna endpoint ordinati per risk score
func (c *ScanContext) GetEndpointsByRisk() []Endpoint {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Deduplica per URL+Method, tenendo l'occorrenza col risk score più alto
	bestByKey := make(map[string]int) // chiave -> indice in endpoints
	var endpoints []Endpoint
	for _, e := range c.Endpoints {
		key := e.Method + " " + e.URL
		if idx, ok := bestByKey[key]; ok {
			if e.RiskScore > endpoints[idx].RiskScore {
				endpoints[idx] = e
			}
			continue
		}
		bestByKey[key] = len(endpoints)
		endpoints = append(endpoints, e)
	}

	// Bubble sort per semplicità
	for i := 0; i < len(endpoints); i++ {
		for j := i + 1; j < len(endpoints); j++ {
			if endpoints[j].RiskScore > endpoints[i].RiskScore {
				endpoints[i], endpoints[j] = endpoints[j], endpoints[i]
			}
		}
	}

	return endpoints
}
