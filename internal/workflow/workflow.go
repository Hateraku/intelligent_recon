// Package workflow fornisce un motore di esecuzione a grafo (DAG) per i moduli
// di scansione. Ogni modulo è un Node con le sue dipendenze; l'Executor calcola
// l'ordine di esecuzione, lancia in parallelo i nodi indipendenti e salta i nodi
// la cui condizione non è soddisfatta o le cui dipendenze sono fallite.
//
// I nodi comunicano attraverso lo *models.ScanContext condiviso (thread-safe) e,
// quando serve passarsi dati tipizzati (es. il body del probe al fingerprint),
// tramite variabili catturate in closure dal chiamante che costruisce il grafo.
package workflow

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hateraku/bughunt/pkg/models"
)

// RunFunc è il lavoro svolto da un nodo.
type RunFunc func(ctx context.Context, sc *models.ScanContext) error

// CondFunc decide se un nodo deve essere eseguito. nil = esegui sempre.
type CondFunc func(sc *models.ScanContext) bool

// Node è un modulo nel grafo.
type Node struct {
	Name      string
	DependsOn []string
	Run       RunFunc
	ShouldRun CondFunc // nil ⇒ esegui sempre (se le dipendenze sono ok)
}

// Status è l'esito dell'esecuzione di un nodo.
type Status string

const (
	StatusDone    Status = "done"
	StatusFailed  Status = "failed"
	StatusSkipped Status = "skipped"
)

// Result riporta l'esito di un singolo nodo.
type Result struct {
	Node     string
	Status   Status
	Err      error
	Reason   string // motivo dello skip, se Status == StatusSkipped
	Duration time.Duration
}

// Graph è una collezione di nodi con le relative dipendenze.
type Graph struct {
	nodes map[string]*Node
	order []string // ordine d'inserimento, per determinismo
}

// NewGraph crea un grafo vuoto.
func NewGraph() *Graph {
	return &Graph{nodes: make(map[string]*Node)}
}

// Add registra un nodo. È concatenabile. Panica su nome duplicato o vuoto
// (è un errore di programmazione nella costruzione del grafo).
func (g *Graph) Add(n *Node) *Graph {
	if n == nil || n.Name == "" {
		panic("workflow: nodo nil o senza nome")
	}
	if _, exists := g.nodes[n.Name]; exists {
		panic(fmt.Sprintf("workflow: nodo duplicato %q", n.Name))
	}
	g.nodes[n.Name] = n
	g.order = append(g.order, n.Name)
	return g
}

// validate verifica dipendenze sconosciute e assenza di cicli.
func (g *Graph) validate() error {
	for _, name := range g.order {
		for _, dep := range g.nodes[name].DependsOn {
			if _, ok := g.nodes[dep]; !ok {
				return fmt.Errorf("il nodo %q dipende dal nodo sconosciuto %q", name, dep)
			}
		}
	}

	const (
		white = 0 // non visitato
		gray  = 1 // in visita (sullo stack)
		black = 2 // completato
	)
	color := make(map[string]int, len(g.nodes))

	var visit func(string) error
	visit = func(name string) error {
		color[name] = gray
		for _, dep := range g.nodes[name].DependsOn {
			switch color[dep] {
			case gray:
				return fmt.Errorf("ciclo rilevato: %q → %q", name, dep)
			case white:
				if err := visit(dep); err != nil {
					return err
				}
			}
		}
		color[name] = black
		return nil
	}

	for _, name := range g.order {
		if color[name] == white {
			if err := visit(name); err != nil {
				return err
			}
		}
	}
	return nil
}

// Executor esegue un grafo.
type Executor struct {
	// Concurrency limita i nodi eseguiti in parallelo entro una "ondata".
	// 0 ⇒ nessun limite (tutti i nodi pronti insieme).
	Concurrency int
	// OnEvent, se impostata, viene chiamata al termine di ogni nodo
	// (anche per skip/fallimento). Può essere invocata da goroutine diverse.
	OnEvent func(Result)
}

// Run esegue il grafo propagando sc tra i nodi e ritorna gli esiti nell'ordine
// di completamento delle ondate. Un errore viene ritornato solo per problemi
// strutturali del grafo (dipendenze sconosciute o cicli); i fallimenti dei
// singoli nodi sono riportati nei Result.
func (e *Executor) Run(ctx context.Context, g *Graph, sc *models.ScanContext) ([]Result, error) {
	if err := g.validate(); err != nil {
		return nil, err
	}

	status := make(map[string]Status, len(g.nodes))
	var results []Result
	remaining := len(g.order)

	for remaining > 0 {
		// Trova i nodi "pronti": non ancora processati e con tutte le
		// dipendenze già risolte (done/failed/skipped).
		var ready []*Node
		for _, name := range g.order {
			if _, processed := status[name]; processed {
				continue
			}
			if depsResolved(g.nodes[name], status) {
				ready = append(ready, g.nodes[name])
			}
		}
		if len(ready) == 0 {
			// Non dovrebbe accadere dopo validate(); guardia di sicurezza.
			return results, fmt.Errorf("deadlock nello scheduler: %d nodi non eseguibili", remaining)
		}

		waveResults := e.runWave(ctx, ready, status, sc)
		for _, r := range waveResults {
			status[r.Node] = r.Status
			results = append(results, r)
			remaining--
		}
	}

	return results, nil
}

// runWave esegue in parallelo i nodi pronti di un'ondata.
func (e *Executor) runWave(ctx context.Context, ready []*Node, status map[string]Status, sc *models.ScanContext) []Result {
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out []Result
	)

	// Semaforo per limitare la concorrenza entro l'ondata.
	var sem chan struct{}
	if e.Concurrency > 0 {
		sem = make(chan struct{}, e.Concurrency)
	}

	emit := func(r Result) {
		mu.Lock()
		out = append(out, r)
		mu.Unlock()
		if e.OnEvent != nil {
			e.OnEvent(r)
		}
	}

	for _, n := range ready {
		// Skip se una dipendenza non è andata a buon fine.
		if reason, skip := skipReason(n, status); skip {
			emit(Result{Node: n.Name, Status: StatusSkipped, Reason: reason})
			continue
		}
		// Skip se la condizione del nodo non è soddisfatta.
		if n.ShouldRun != nil && !n.ShouldRun(sc) {
			emit(Result{Node: n.Name, Status: StatusSkipped, Reason: "condizione non soddisfatta"})
			continue
		}

		wg.Add(1)
		go func(n *Node) {
			defer wg.Done()
			if sem != nil {
				sem <- struct{}{}
				defer func() { <-sem }()
			}

			start := time.Now()
			err := n.Run(ctx, sc)
			res := Result{Node: n.Name, Duration: time.Since(start)}
			if err != nil {
				res.Status = StatusFailed
				res.Err = err
			} else {
				res.Status = StatusDone
			}
			emit(res)
		}(n)
	}

	wg.Wait()
	return out
}

// depsResolved indica se tutte le dipendenze del nodo sono già state processate.
func depsResolved(n *Node, status map[string]Status) bool {
	for _, dep := range n.DependsOn {
		if _, ok := status[dep]; !ok {
			return false
		}
	}
	return true
}

// skipReason indica se il nodo va saltato per via di una dipendenza
// fallita o a sua volta saltata.
func skipReason(n *Node, status map[string]Status) (string, bool) {
	for _, dep := range n.DependsOn {
		switch status[dep] {
		case StatusFailed:
			return fmt.Sprintf("dipendenza %q fallita", dep), true
		case StatusSkipped:
			return fmt.Sprintf("dipendenza %q saltata", dep), true
		}
	}
	return "", false
}
