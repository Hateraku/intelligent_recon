// Package report genera report leggibili (HTML, Markdown) dal ScanContext.
// È puramente di presentazione: ordina e formatta i finding già raccolti, senza
// eseguire alcuna logica di scansione. Da usare a scansione conclusa.
package report

import (
	"sort"
	"strings"

	"github.com/hateraku/bughunt/pkg/models"
)

// severityOrder è l'ordine di gravità decrescente usato nei report.
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

var sevRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

func rankOf(s string) int { return sevRank[strings.ToLower(s)] }

// SortVulns ordina le vulnerabilità per gravità decrescente, poi per score.
func SortVulns(in []models.Vulnerability) []models.Vulnerability {
	v := append([]models.Vulnerability(nil), in...)
	sort.SliceStable(v, func(i, j int) bool {
		if ri, rj := rankOf(v[i].Severity), rankOf(v[j].Severity); ri != rj {
			return ri > rj
		}
		return v[i].Score > v[j].Score
	})
	return v
}

// SortAnoms ordina le anomalie per gravità decrescente, poi per risk score.
func SortAnoms(in []models.Anomaly) []models.Anomaly {
	a := append([]models.Anomaly(nil), in...)
	sort.SliceStable(a, func(i, j int) bool {
		if ri, rj := rankOf(a[i].Severity), rankOf(a[j].Severity); ri != rj {
			return ri > rj
		}
		return a[i].RiskScore > a[j].RiskScore
	})
	return a
}

// severityCounts conta i finding per gravità (chiave minuscola).
func severityCounts(v []models.Vulnerability) map[string]int {
	m := map[string]int{}
	for _, x := range v {
		m[strings.ToLower(x.Severity)]++
	}
	return m
}

// meta legge una chiave di metadata in modo sicuro.
func meta(m map[string]string, key string) string {
	if m == nil {
		return ""
	}
	return m[key]
}
