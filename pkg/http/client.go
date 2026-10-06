package http

import (
	"crypto/tls"
	"math/rand"
	"net/http"
	"time"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0",
}

// Client is a custom HTTP client configured for reconnaissance
//serve effetitvamente?
var Client = &http.Client{
	Transport: newStealthTransport(),
	Timeout:   7 * time.Second,
}

func RandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func newStealthTransport() *http.Transport {
	return &http.Transport{
		TLSHandshakeTimeout:   5 * time.Second,
		DisableKeepAlives:     false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       20,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableCompression: false,
		ForceAttemptHTTP2:  true,
	}
}
