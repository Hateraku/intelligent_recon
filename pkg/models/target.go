package models

import "time"

// Target rappresenta un target da scansionare
type Target struct {
	Domain    string    `json:"domain"`
	IPs       []string  `json:"ips,omitempty"`
	Scope     string    `json:"scope"`      // in-scope, out-of-scope
	CreatedAt time.Time `json:"created_at"`
}

// Endpoint rappresenta un endpoint scoperto
type Endpoint struct {
	URL          string            `json:"url"`
	Method       string            `json:"method"`       // GET, POST, etc.
	StatusCode   int               `json:"status_code"`
	Title        string            `json:"title,omitempty"`
	ContentType  string            `json:"content_type,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Parameters   []Parameter       `json:"parameters,omitempty"`
	Technologies []string          `json:"technologies,omitempty"`
	RiskScore    float64           `json:"risk_score"` // 0.0 - 10.0
}

// Parameter rappresenta un parametro HTTP
type Parameter struct {
	Name     string `json:"name"`
	Type     string `json:"type"`      // query, body, header, cookie
	DataType string `json:"data_type"` // string, int, bool, etc.
	Value    string `json:"value,omitempty"`
}
