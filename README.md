# Intelligent Recon

A concurrent reconnaissance and web attack-surface analysis framework written in Go.

Rather than just enumerating hosts or firing isolated HTTP probes, it is built as a modular pipeline: a worker-pool engine feeds pluggable modules (DNS, HTTP probing, technology fingerprinting, content discovery, anomaly/vulnerability checks) that share a single scan context, so results from one stage inform the next. Workflows are described in YAML, so a scan is configuration, not code.

> Built for **authorized** security testing, bug-bounty work and research. See the disclaimer below.

## Highlights

- **Concurrent engine** — custom worker pool with configurable concurrency, timeouts and rate control; resolves and probes hundreds of targets in parallel.
- **Stealth HTTP client** — custom transport, HTTP/2, keep-alive, realistic browser headers, User-Agent rotation and request jitter to reduce noise.
- **Technology fingerprinting** — identifies web servers, CDNs/WAFs, CMSs, backend languages and SPA frameworks from headers, cookies, body patterns and typical files.
- **Content discovery** — HTML crawling with configurable depth, link/form extraction, `robots.txt` and `sitemap.xml` parsing, common-path probing and REST/GraphQL endpoint detection, with automatic risk scoring per endpoint.
- **Vulnerability families** — passive, class-based detectors sharing a CWE taxonomy: sensitive-path exposure, security headers & cookie flags, secrets in responses, a React/Next.js surface check, and a deep WordPress module (version, plugin/theme enumeration, REST user-enum, `?author=` enum, XML-RPC, config backups, debug logs…). Plus an opt-in active anomaly module (SQLi/XSS/path/header injection — authorized targets only).
- **YAML workflows** — presets (`quick`, `full`, `api`) or a custom `.yaml` describe which modules run and how.
- **Reporting** — terminal summary, JSON (to pipe into other tooling), or a self-contained HTML / Markdown report with findings grouped by severity and mapped to vulnerability classes (CWE).

## Architecture

```
cmd/
  recon/      fast recon probe (DNS + HTTP + tech detection)
  bughunt/    full pipeline driven by the workflow engine
pkg/
  core/       dns · discovery · fingerprint · anomaly
  vuln/       exposure · react · wordpress · secheaders · secrets · vulnclass (shared taxonomy)
  http/       stealth client and probe
  report/     HTML + Markdown report generators
  subdomain/  plugins/   models/   tech/
internal/
  workflow/   engine + config (YAML presets)
configs/
  workflows/  quick.yaml · full.yaml · api.yaml

# planned (scaffolding, not yet implemented):
#   cmd/scanner · cmd/fuzzer · internal/integration · internal/database
```

A detailed breakdown lives in [`ARCHITECTURE.md`](ARCHITECTURE.md); planned work is in [`ROADMAP.md`](ROADMAP.md).

## Build

Requires **Go 1.19+**.

```bash
git clone https://github.com/Hateraku/intelligent-recon
cd intelligent-recon

go build -o bin/recon   ./cmd/recon
go build -o bin/bughunt ./cmd/bughunt
```

## Usage

### Fast recon probe

```bash
# single target, JSON output
./bin/recon example.com --json

# many targets from a file, 50 workers
./bin/recon --input targets.txt --workers 50 --json
```

| Flag | | Description |
|------|---|-------------|
| `--input`   | `-i` | File with one target per line |
| `--workers` | `-w` | Concurrent workers (default 4) |
| `--timeout` | `-t` | HTTP timeout in seconds (default 7) |
| `--json`    | `-j` | Output as JSON |
| `--silent`  | `-s` | Errors only |
| `--verbose` | `-v` | Verbose output |

### Full pipeline

> **Flags must come before the target(s).** `bughunt` parses options up to the
> first positional argument, so `--workflow full example.com` works but
> `example.com --workflow full` treats `--workflow` as a target.

```bash
# passive full workflow, report to JSON
./bin/bughunt --workflow full --json report.json example.com

# enable active tests (sends payloads — authorized targets only)
./bin/bughunt --active --workflow full --max-anomaly 10 example.com
```

Key flags: `--workflow` (preset name or path to a `.yaml`), `--depth` (crawl depth), `--active` (enable active anomaly tests), `-c` (parallel targets), `--list` (targets file), `--json` (report path, `-` for stdout), `--html` / `--md` (write an HTML or Markdown report).

## Guide

### 1. Choosing a workflow

A workflow is the set of modules a scan runs and how they depend on each other.
Built-in presets (embedded in the binary):

| Preset | Modules | Use it for |
|--------|---------|------------|
| `quick` | dns → probe → fingerprint | fast triage: is it up, what is it |
| `api`   | probe → discovery → anomaly¹ | endpoint-heavy / API targets |
| `full`  | everything (DNS, probe, fingerprint, discovery, security-headers, secrets, react, wordpress, exposure, anomaly¹) | a complete pass |

¹ `anomaly` only runs with `--active` (see below).

```bash
./bin/bughunt --workflow quick example.com
./bin/bughunt --workflow full  example.com
```

### 2. Targets & concurrency

```bash
# several targets
./bin/bughunt --workflow full example.com test.example.org

# from a file (one host per line, '#' comments allowed), 8 in parallel
./bin/bughunt --workflow full --list targets.txt -c 8
```

Targets are hostnames (scheme/path are stripped automatically). Each target runs
the workflow as a DAG: independent modules run in parallel, and a module is
skipped if one of its dependencies failed.

### 3. Passive vs active

By default a scan is **passive**: it reads what the target already serves
(headers, body, crawl data) and makes benign reconnaissance requests only.

`--active` additionally enables the **anomaly** module, which **sends injection
payloads** (SQLi/XSS/path/header). Use it **only** on systems you are authorized
to test:

```bash
./bin/bughunt --active --workflow full --max-anomaly 10 example.com
```

### 4. Custom workflows

A workflow is a YAML file. Copy one from `configs/workflows/` or write your own
and pass its path to `--workflow`:

```yaml
name: my-scan
description: DNS + probe + WordPress, with active anomaly
steps:
  - module: dns
  - module: probe
  - module: fingerprint
    depends_on: [probe]
  - module: discovery
    depends_on: [probe]
  - module: wordpress
    depends_on: [discovery]
  - module: anomaly
    depends_on: [discovery]
    when: active          # runs only with --active
```

```bash
./bin/bughunt --workflow ./my-scan.yaml example.com
```

**Available modules:** `dns`, `probe`, `fingerprint` (needs `probe`),
`discovery` (needs `probe`), `security-headers` / `secrets` (need `probe`),
`react-family` / `wordpress` / `exposure` (need `discovery`), `anomaly`
(needs `discovery`).

**Conditions (`when:`):** `active` (only with `--active`) or `tech:<Name>`
(only if that technology was detected, e.g. `when: tech:WordPress`). Each module
also self-filters, so a condition is an optimisation, not a correctness gate.

### 5. Understanding the findings

Every finding is mapped to a **vulnerability class** (a CWE-tagged mechanism) and
carries a **status**:

- `confirmed` — directly observed (e.g. a missing security header, an exposed
  secret pattern in the body).
- `unconfirmed` — an exposed *surface* was detected, but exploitation was not
  proven (e.g. an RSC deserialization surface, a path that returned `200` via
  `HEAD`). Treat these as leads to verify, not proven bugs.

Findings also include severity (`critical`→`info`), the module that found them
(`found_by`), any related CVEs (`references`), and remediation advice.

### 6. Reports

```bash
# JSON (full ScanContext), HTML and Markdown in one run
./bin/bughunt --workflow full \
  --json report.json --html report.html --md report.md \
  example.com
```

- `--json` — the complete scan context (pipe into other tooling; `-` = stdout).
- `--html` — a self-contained page, findings grouped by severity.
- `--md` — a GitHub-flavoured report, sorted by severity.

## Example output

```json
{
  "target": "example.com",
  "ips": ["93.184.216.34"],
  "status_code": 200,
  "title": "Example Domain",
  "server": "ECS",
  "content_length": 1256,
  "tech": ["Cloudflare"],
  "error": null
}
```

## Disclaimer

This tool is intended **only** for security research, authorized penetration testing and educational use. The active module sends requests and payloads to the target: run it only against systems you own or have explicit written permission to test. The author is not responsible for misuse.

## Author

Built by **Antonio Coluccia** ([@Hateraku](https://github.com/Hateraku)) — MSc student in AI & Cybersecurity, as an exercise in building a performant, modular security engine in Go.
