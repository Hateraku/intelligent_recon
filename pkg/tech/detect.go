package tech

import (
	"net/http"
	"strings"
)

// Detect identifies web technologies from server headers and response body
func Detect(server string, headers http.Header, body string) []string {
	tech := []string{}

	// CDN/WAF Detection
	if strings.Contains(strings.ToLower(server), "cloudflare") ||
	   headers.Get("CF-Ray") != "" ||
	   headers.Get("CF-Cache-Status") != "" {
		tech = append(tech, "Cloudflare")
	}

	// Web Server Detection
	if strings.Contains(strings.ToLower(server), "apache") {
		tech = append(tech, "Apache")
	}

	if strings.Contains(strings.ToLower(server), "nginx") {
		tech = append(tech, "Nginx")
	}

	if strings.Contains(strings.ToLower(server), "litespeed") {
		tech = append(tech, "LiteSpeed")
	}

	// Backend Framework Detection
	if strings.Contains(headers.Get("X-Powered-By"), "PHP") ||
	   strings.Contains(body, "wp-content") ||
	   strings.Contains(body, "index.php") {
		tech = append(tech, "PHP/WordPress")
	}

	if strings.Contains(headers.Get("Set-Cookie"), "laravel_session") {
		tech = append(tech, "Laravel")
	}

	if strings.Contains(headers.Get("set-cookie"), "JSESSIONID") {
		tech = append(tech, "Java/JSP")
	}

	if strings.Contains(headers.Get("set-cookie"), "csrf_token") {
		tech = append(tech, "Django")
	}

	// Frontend Framework Detection
	if strings.Contains(body, "react") || strings.Contains(body, "webpackJsonp") {
		tech = append(tech, "React")
	}

	if strings.Contains(body, "vue.js") {
		tech = append(tech, "Vue")
	}

	if strings.Contains(body, "ng-version") {
		tech = append(tech, "Angular")
	}

	return tech
}
