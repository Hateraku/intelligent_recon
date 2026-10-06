# BugHunt Framework - Architecture

## 🏗️ Overview

BugHunt is an **enterprise-grade intelligent vulnerability discovery platform** that combines:
- 🧠 **Intelligence Layer** - ML-based analysis, heuristics, anomaly detection, risk scoring
- 🔌 **Plugin System** - Context-aware orchestration of external tools
- 📊 **Shared Knowledge** - Thread-safe ScanContext with incremental intelligence
- 🎯 **Discovery-First** - Finds logical vulnerabilities, not just known CVEs
- 🌐 **Browser-Based Recon** - Headless Chrome for JS-heavy applications
- 🔄 **Stateful Scanning** - Resume, diff, and incremental scan capabilities
- 📈 **Attack Surface Graph** - Visual representation of infrastructure relationships
- 🎼 **DAG Workflow Engine** - Parallel, intelligent pipeline execution

---

## 📐 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     BugHunt CLI / API                           │
│          (Target Input, Workflow Selection, Output)             │
└────────────────────────────┬────────────────────────────────────┘
                             │
        ┌────────────────────┴─────────────────────┐
        │   DAG Workflow Orchestrator              │
        │   • Parallel Execution                   │
        │   • Dynamic Graph Generation             │
        │   • Dependency Resolution                │
        │   • Hook System (onStart/Result/Finish)  │
        └────────────────────┬─────────────────────┘
                             │
      ┌──────────────────────┼───────────────────────┐
      │                      │                       │
┌─────▼──────┐     ┌────────▼────────┐    ┌────────▼──────┐
│   CORE     │     │   INTELLIGENCE  │    │   BROWSER     │
│  MODULES   │     │     LAYER       │    │   RECON       │
├────────────┤     ├─────────────────┤    ├───────────────┤
│ • DNS      │     │ • ML Classify   │    │ • ChromeDP    │
│ • HTTP     │     │ • Anomaly Det.  │    │ • Screenshot  │
│ • Fingerpr │     │ • Param Anal.   │    │ • JS Exec     │
│ • Discovery│     │ • Risk Scoring  │    │ • SPA Crawl   │
└─────┬──────┘     └────────┬────────┘    └────────┬──────┘
      │                     │                      │
      │          ┌──────────┴──────────┐           │
      │          │  VULNERABILITY      │           │
      │          │   DISCOVERY         │           │
      │          ├─────────────────────┤           │
      │          │ • IDOR • CORS       │           │
      │          │ • Access • Upload   │           │
      │          │ • Session • Rate    │           │
      │          └──────────┬──────────┘           │
      │                     │                      │
┌─────▼─────────────────────┼──────────────────────▼──────┐
│                    PLUGIN SYSTEM                         │
│   Nuclei • FFUF • Sqlmap • Nmap • Katana                │
│   (Context-aware execution based on findings)            │
└─────────────────────────┬────────────────────────────────┘
                          │
      ┌───────────────────┼────────────────────┐
      │                   │                    │
┌─────▼──────┐   ┌────────▼─────────┐   ┌─────▼──────────┐
│   STATE    │   │  SCAN CONTEXT    │   │  ATTACK GRAPH  │
│ MANAGEMENT │   │ (Shared Intel)   │   │  (Neo4j/Viz)   │
├────────────┤   ├──────────────────┤   ├────────────────┤
│ • SQLite   │   │ • Targets        │   │ • Domain→Sub   │
│ • Resume   │   │ • Endpoints      │   │ • Sub→IP       │
│ • Diff     │   │ • Vulns          │   │ • IP→Ports     │
│ • Increm.  │   │ • Tech Stack     │   │ • Port→Service │
└────────────┘   │ • Sessions       │   │ • Attack Paths │
                 │ • Network Data   │   └────────────────┘
                 └──────────────────┘
                          │
         ┌────────────────┴─────────────────┐
         │         REPORTING ENGINE         │
         │  JSON • HTML • Markdown • Graph  │
         └──────────────────────────────────┘
```

---

## 📦 Module Categories

### 1️⃣ **CORE MODULES** (pkg/core/)
Foundation reconnaissance capabilities.

- ✅ **dns/** - Complete DNS analysis (A, AAAA, CNAME, MX, NS, TXT, wildcard, AXFR, cloud provider detection)
- ✅ **http/** - Enhanced HTTP probing (redirects, security headers, WAF detection, TLS analysis, risk scoring)
- 🚧 **fingerprint/** - Technology detection (frameworks, CMS, favicon hash, JS frameworks, CDN)
- ⏳ **discovery/** - Endpoint discovery (crawling, link extraction, API detection, sitemap, robots.txt)

### 2️⃣ **INTELLIGENCE LAYER** (pkg/heuristics/ & pkg/ml/)
Advanced analysis and machine learning.

**Heuristics:**
- ⏳ **anomaly/** - Anomaly detection (payload testing, stacktrace, error analysis, timing attacks)
- ⏳ **params/** - Parameter analysis (extraction, type classification, sensitive param detection, relationship mapping)
- ⏳ **scoring/** - Advanced risk scoring (technology, endpoint type, parameters, anomalies, security posture)

**Machine Learning:**
- ⏳ **ml/classify/** - ML-based classification (endpoint clustering, response classification, pattern recognition)
- ⏳ **ml/train/** - Model training and versioning (training data collection, model serialization, incremental learning)

### 3️⃣ **BROWSER-BASED RECON** (pkg/recon/)
Headless browser capabilities for modern web apps.

- ⏳ **browser/** - ChromeDP/Rod integration (screenshot, JS execution, SPA crawling, WebSocket detection, storage extraction)
- ⏳ **javascript/** - JS file analysis (endpoint extraction, secrets detection, source map analysis, bundle parsing)

### 4️⃣ **VULNERABILITY DISCOVERY** (pkg/vulns/)
Logical vulnerability detection (not just CVE matching).

- ⏳ **idor/** - IDOR detection (parameter manipulation, response comparison, privilege testing)
- ⏳ **access/** - Access control testing (unauthorized access, role-based testing, authorization bypass)
- ⏳ **cors/** - Advanced CORS testing (origin reflection, null origin, subdomain trust)
- ⏳ **session/** - Session security (cookie analysis, fixation, entropy, token predictability)
- ⏳ **upload/** - Upload weakness (extension bypass, Content-Type manipulation, path traversal)
- ⏳ **ratelimit/** - Rate limit testing (brute-force protection, IP vs token-based limiting)
- ⏳ **traversal/** - Directory traversal (path traversal, file inclusion, encoding bypass)
- ⏳ **redirect/** - Open redirect detection
- ⏳ **ssrf/** - SSRF detection (URL parameter testing, callback detection, cloud metadata)
- ⏳ **methods/** - HTTP method confusion (verb tampering, method override, OPTIONS analysis)
- ⏳ **hostheader/** - Host header injection (cache poisoning, password reset poisoning)
- ⏳ **smuggling/** - Request smuggling hints (CL.TE/TE.CL detection)

### 5️⃣ **SESSION & AUTH** (pkg/session/)
Authentication and session management.

- ⏳ **manager/** - Session manager (cookie jar, session persistence, multi-user support, re-authentication)
- ⏳ **tokens/** - Token extraction (JWT, OAuth, Bearer, API keys, CSRF tokens)
- ⏳ **auth/** - Authentication flows (login detection, custom auth support, Basic/Digest/NTLM)

### 6️⃣ **NETWORK LAYER** (pkg/network/)
Network-level attack surface.

- ⏳ **scanner/** - Port scanning (service detection, version grabbing, banner grabbing, SSL/TLS analysis)
- ⏳ **cve/** - CVE correlation (version→CVE mapping, NVD integration, exploit availability, CVSS scoring)

### 7️⃣ **PROTOCOL SUPPORT** (pkg/protocols/)
Advanced protocol handling.

- ⏳ **websocket/** - WebSocket testing (endpoint detection, message interception, authentication)
- ⏳ **graphql/** - GraphQL support (introspection, query depth, mutation testing)
- ⏳ **grpc/** - gRPC support (service enumeration, method testing)

### 8️⃣ **MOBILE & API** (pkg/mobile/ & pkg/api/)
Mobile app and API reconnaissance.

- ⏳ **mobile/** - APK/IPA analysis (manifest parsing, endpoint extraction, pinning detection, secrets)
- ⏳ **api/** - API spec discovery (OpenAPI/Swagger, WADL, versioning detection)

### 9️⃣ **PLUGIN SYSTEM** (pkg/plugins/)
Context-aware external tool integration.

- ✅ **interface.go** - Enhanced plugin interface with hooks and capabilities
- ✅ **subfinder/** - Subdomain enumeration
- ⏳ **nuclei/** - Smart template selection based on tech detection
- ⏳ **ffuf/** - Context-aware fuzzing with wordlist selection
- ⏳ **sqlmap/** - Suspicious parameter identification and command generation
- ⏳ **nmap/** - Port scanning orchestration
- ⏳ **katana/** - Advanced crawling for JS-heavy apps
- ⏳ **httpx/** - Bulk HTTP probing

### 🔟 **TEMPLATE SYSTEM** (pkg/templates/)
Custom detection rule engine.

- ⏳ **parser/** - YAML template parser
- ⏳ **executor/** - Template execution engine
- ⏳ **matchers/** - Matcher types (word, regex, status, header, body)
- ⏳ **marketplace/** - Community template repository

### 1️⃣1️⃣ **ORCHESTRATION ENGINE** (internal/engine/)
DAG-based workflow system.

- ⏳ **dag/** - DAG scheduler (dependency resolution, parallel execution, dynamic graph generation)
- ⏳ **pipeline/** - Pipeline executor (stage management, error handling, retry strategies)
- ⏳ **scheduler/** - Module scheduling (prioritization, timeout management, hook system)
- ⏳ **workflow/** - YAML workflow parser and executor

### 1️⃣2️⃣ **STATE MANAGEMENT** (internal/state/)
Stateful scanning capabilities.

- ⏳ **sqlite/** - SQLite persistence (scan history, target tracking, deduplication)
- ⏳ **checkpoint/** - Resume capability (checkpoint system, recovery, progress tracking)
- ⏳ **diff/** - Incremental scanning (scan comparison, change detection, new finding highlighting)

### 1️⃣3️⃣ **ATTACK GRAPH** (pkg/graph/)
Visual attack surface representation.

- ⏳ **engine/** - Graph engine (Neo4j/Graphviz integration, relationship mapping, path finding)
- ⏳ **export/** - Visual export (PNG, SVG, HTML interactive graph)
- ⏳ **analysis/** - Graph analysis (critical nodes, attack paths, risk propagation)

### 1️⃣4️⃣ **REPORTING** (pkg/report/)
Multi-format output generation.

- ⏳ **json/** - JSON export (structured data)
- ⏳ **html/** - HTML report (interactive, charts, filtering)
- ⏳ **markdown/** - Markdown report (GitHub-compatible)
- ⏳ **csv/** - CSV export (spreadsheet-compatible)
- ⏳ **surface/** - Attack surface report (executive summary, risk-prioritized, command suggestions)

### 1️⃣5️⃣ **MODELS** (pkg/models/)
Shared data structures.

- ✅ **target.go** - Target, Endpoint, Parameter
- ✅ **vulnerability.go** - Vulnerability, types, severity
- ✅ **context.go** - ScanContext (shared knowledge base)
- ⏳ **Enhanced ScanContext** - Add: Cookies, AuthTokens, SessionID, CookieJar, OpenPorts, Services, CVEs, JSFiles, JSEndpoints, JSSecrets, Graph

---

## 🔌 Plugin System

### Enhanced Plugin Interface

```go
type Plugin interface {
    Name() string
    Version() string
    IsInstalled() bool
    Execute(ctx context.Context, input *PluginInput) (*PluginOutput, error)
    Validate(config map[string]interface{}) error

    // Advanced hooks
    OnStart() error
    OnResult(result interface{}) error
    OnFinish() error

    // Capabilities
    Capabilities() []string

    // Dependencies
    Dependencies() []string
}
```

### Plugin Input/Output

```go
type PluginInput struct {
    Targets []string
    Options map[string]interface{}
    WorkDir string
    Context *models.ScanContext  // 🔥 Intelligence!
}

type PluginOutput struct {
    RawOutput       string
    Parsed          interface{}
    Endpoints       []string
    Subdomains      []string
    Vulnerabilities []*models.Vulnerability
    Metadata        map[string]interface{}
}
```

### Registry

```go
registry := plugins.NewRegistry()
registry.Register(subfinder.New())
registry.Register(nuclei.New())
registry.Register(ffuf.New())

plugin, _ := registry.Get("nuclei")
output, _ := plugin.Execute(ctx, input)
```

---

## 🧠 Enhanced ScanContext (Shared Intelligence)

All modules read from and write to the shared `ScanContext`:

```go
type ScanContext struct {
    // Core reconnaissance
    Targets         []Target
    Endpoints       []Endpoint
    Technologies    []string
    CloudProviders  []string
    Vulnerabilities []Vulnerability
    Anomalies       []Anomaly

    // Session & Auth (NEW)
    Cookies         map[string]string
    AuthTokens      []string
    SessionID       string
    CookieJar       http.CookieJar

    // Network layer (NEW)
    OpenPorts       map[string][]int  // IP -> Ports
    Services        []Service
    CVEs            []CVE

    // JavaScript & Browser (NEW)
    JSFiles         []string
    JSEndpoints     []string
    JSSecrets       []Secret

    // Attack Graph (NEW)
    Graph           *AttackGraph

    // Generic metadata
    Metadata        map[string]interface{}
}
```

### Thread-Safe Operations

```go
ctx.AddEndpoint(endpoint)
ctx.AddVulnerability(vuln)
ctx.AddTechnology("Laravel")
ctx.AddAnomaly(anomaly)

if ctx.HasTechnology("WordPress") {
    // Smart decision based on context
}

highRisk := ctx.GetEndpointsByRisk()
```

---

## 🎯 Workflow Example

```yaml
# configs/workflows/full.yaml

stages:
  # CORE RECON
  - name: "reconnaissance"
    modules:
      - core.dns
      - core.http
      - core.fingerprint
      - core.discovery

  # PLUGIN: SUBDOMAIN
  - name: "subdomain-enum"
    plugins:
      - subfinder

  # HEURISTICS
  - name: "analysis"
    modules:
      - heuristics.anomaly
      - heuristics.params
      - heuristics.scoring

  # CUSTOM VULNS
  - name: "discovery"
    modules:
      - vulns.idor
      - vulns.access
      - vulns.cors

  # PLUGIN: SMART FUZZING
  - name: "fuzzing"
    plugins:
      - ffuf
    condition: "if_api_detected"

  # PLUGIN: CONFIRMATION
  - name: "confirmation"
    plugins:
      - nuclei
    condition: "smart"  # Based on tech detection
```

---

## 🔥 Key Features

### 1. **Context-Aware Plugins**

Il plugin Nuclei può decidere quali template usare basandosi sul context:

```go
if ctx.HasTechnology("WordPress") {
    args = append(args, "-t", "wordpress")
}
if ctx.HasTechnology("Laravel") {
    args = append(args, "-t", "laravel")
}
```

### 2. **Intelligent Fuzzing**

FFUF viene lanciato solo quando ha senso:

```go
if ctx.HasEndpoint("/api/") {
    runPlugin("ffuf", wordlist: "api-paths")
}
if ctx.HasTechnology("WordPress") {
    runPlugin("ffuf", wordlist: "wp-paths")
}
```

### 3. **Risk Scoring**

Ogni endpoint riceve un punteggio 0-10:

```go
endpoint.RiskScore = calculateRisk(
    technology,     // PHP = higher risk
    endpointType,   // /upload = high risk
    parameters,     // numeric params = IDOR candidate
    anomalies,      // errors found
)
```

### 4. **Extensibility**

Aggiungere un nuovo plugin:

```go
type MyToolPlugin struct{}

func (m *MyToolPlugin) Name() string { return "mytool" }
func (m *MyToolPlugin) Execute(...) { /* implementation */ }

registry.Register(mytool.New())
```

---

## 📊 Data Flow

```
Target Input
    ↓
DNS Module → ScanContext (IPs, cloud provider)
    ↓
HTTP Probe → ScanContext (status, title, headers)
    ↓
Tech Detection → ScanContext (technologies)
    ↓
Endpoint Discovery → ScanContext (endpoints, params)
    ↓
Heuristics → ScanContext (anomalies, risk scores)
    ↓
Vuln Modules → ScanContext (vulnerabilities)
    ↓
Plugins (smart execution based on context)
    ↓
Attack Surface Report
```

---

## ✅ Current Status

### Completed
- ✅ Plugin architecture (interface + registry)
- ✅ DNS Module (complete with cloud detection)
- ✅ Subfinder Plugin (working)
- ✅ Models (Target, Endpoint, Vulnerability, Context)
- ✅ Example test (`bin/test-arch`)

### Next Steps
1. HTTP Probe expansion
2. Technology Fingerprint
3. Heuristics modules
4. More plugins (Nuclei, FFUF, Sqlmap, Nmap)
5. Workflow orchestrator

---

## 🚀 Testing

```bash
# Build test
go build -o bin/test-arch examples/test_architecture.go

# Run
./bin/test-arch
```

Output:
```
🚀 BugHunt Framework - Architecture Test
📦 Plugin registrati: subfinder
🔍 DNS Lookup: example.com
🔍 Subdomain Enumeration
📊 Scan Context Summary
🎯 High-Risk Endpoints
📄 JSON Export
```

---

## 🔥 Key Differentiators

### What Makes BugHunt Unique?

1. **🧠 ML-Based Analysis** - No other recon tool has lightweight machine learning
2. **🌐 Browser-Based Recon** - Most tools are HTTP-only, we handle JS-heavy SPAs
3. **📊 Attack Surface Graph** - Visual understanding of infrastructure relationships
4. **🔄 Stateful Scanning** - Resume, diff, and incremental capabilities
5. **🎯 Context-Aware Execution** - Smart decisions, not blind tool chaining
6. **🎼 DAG Workflow Engine** - Proper orchestration with parallel execution
7. **🔐 Session Handling** - Authenticated scanning (Burp-level capability)
8. **🎯 Discovery-First** - Finds logical vulnerabilities, not just CVE matching

## 📝 Philosophy

> **BugHunt is not a wrapper of existing tools.**
>
> It's the **brain** that:
> - 🧠 Understands the target
> - 🎯 Decides what to test
> - 📊 Prioritizes risks
> - 🔌 Uses other tools as "muscles"
> - 🔥 Finds logical vulnerabilities

### Design Principles

1. **Intelligence First** - Every module contributes to shared knowledge
2. **Context-Aware** - Decisions based on accumulated intelligence
3. **Fail-Safe** - Graceful degradation, never crash
4. **Performance** - Concurrent, efficient, scalable
5. **Extensible** - Plugin-first architecture
6. **User-Friendly** - Clear output, helpful errors, good UX
