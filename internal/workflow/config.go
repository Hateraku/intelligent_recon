package workflow

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// WorkflowSpec è la descrizione dichiarativa (YAML) di un grafo di moduli.
type WorkflowSpec struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Steps       []StepSpec `yaml:"steps"`
}

// StepSpec è un singolo nodo nel file di workflow.
type StepSpec struct {
	Module    string   `yaml:"module"`          // nome del modulo nel registry
	Name      string   `yaml:"name,omitempty"`  // nome nodo (default: Module)
	DependsOn []string `yaml:"depends_on"`      // nomi dei nodi da cui dipende
	When      string   `yaml:"when,omitempty"`  // condizione (risolta dal chiamante)
}

// LoadSpec deserializza un WorkflowSpec da YAML.
func LoadSpec(data []byte) (*WorkflowSpec, error) {
	var spec WorkflowSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("YAML non valido: %w", err)
	}
	if len(spec.Steps) == 0 {
		return nil, fmt.Errorf("workflow senza step")
	}
	return &spec, nil
}

// CondResolver trasforma la stringa 'when' di uno step in una CondFunc.
// Ritorna errore se la condizione non è riconosciuta.
type CondResolver func(expr string) (CondFunc, error)

// BuildGraph costruisce un Graph da uno spec, collegando ogni step al modulo
// corrispondente nel registry e risolvendo le condizioni 'when' (se presenti).
func BuildGraph(spec *WorkflowSpec, registry map[string]RunFunc, resolveCond CondResolver) (*Graph, error) {
	if spec == nil || len(spec.Steps) == 0 {
		return nil, fmt.Errorf("workflow vuoto")
	}

	g := NewGraph()
	seen := make(map[string]bool)

	for i, step := range spec.Steps {
		if step.Module == "" {
			return nil, fmt.Errorf("step %d: campo 'module' mancante", i)
		}
		run, ok := registry[step.Module]
		if !ok {
			return nil, fmt.Errorf("step %d: modulo sconosciuto %q", i, step.Module)
		}

		name := step.Name
		if name == "" {
			name = step.Module
		}
		if seen[name] {
			return nil, fmt.Errorf("step %d: nome nodo duplicato %q (usa 'name' per distinguerli)", i, name)
		}
		seen[name] = true

		node := &Node{
			Name:      name,
			DependsOn: step.DependsOn,
			Run:       run,
		}

		if step.When != "" {
			if resolveCond == nil {
				return nil, fmt.Errorf("step %q: condizione %q ma nessun resolver configurato", name, step.When)
			}
			cond, err := resolveCond(step.When)
			if err != nil {
				return nil, fmt.Errorf("step %q: %w", name, err)
			}
			node.ShouldRun = cond
		}

		g.Add(node)
	}

	// Validazione anticipata (dipendenze sconosciute, cicli).
	if err := g.validate(); err != nil {
		return nil, err
	}
	return g, nil
}
