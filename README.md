# 🌶 Capsaicin

**Fast, intelligent web directory scanner built for security professionals.**

Capsaicin discovers hidden paths, leaked secrets, and WAF configurations with surgical precision — featuring smart calibration, context-aware retries, and graceful concurrency.

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](/.github/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/Coverage-63%25-yellow)]()

---

## ✨ Highlights

| Feature | Description |
|---------|-------------|
| 🎯 **Smart Calibration** | Automatic 404 baseline to eliminate false positives |
| 🔑 **Secret Detection** | 15 patterns with severity scoring and entropy analysis |
| 🛡 **WAF Detection** | 16 signatures — header, cookie, and body-based |
| 🔄 **Method Fuzzing** | Auto-tests PUT/POST/DELETE/PATCH on 405 responses |
| 🚪 **Bypass Engine** | Header manipulation for 403/401 bypass attempts |
| 🌳 **Recursive Scan** | Configurable depth-limited directory traversal |
| ⚡ **Circuit Breaker** | Automatic backoff for failing targets |
| 📊 **Dual Reports** | JSON (versioned schema 3.0) + Interactive HTML |

---

## 🚀 Quick Start

### Install

```bash
go install github.com/capsaicin/scanner/cmd/capsaicin@latest
```

Or build from source:

```bash
git clone https://github.com/capsaicin/scanner.git
cd scanner
go build -o capsaicin ./cmd/capsaicin
```

### Basic Scan

```bash
capsaicin -u https://target.com -w wordlist.txt
```

### Pipeline Mode

```bash
cat targets.txt | capsaicin -w wordlist.txt -t 100
```

---

## 📖 Usage Examples

### Authenticated Scan with Custom Headers

```bash
capsaicin -u https://api.target.com -w wordlist.txt \
  -H "Authorization: Bearer eyJhbGci..." \
  -H "Cookie: session=abc123"
```

### Recursive Scan with Rate Limiting

```bash
capsaicin -u https://target.com -w wordlist.txt \
  --depth 3 \
  --rate-limit 50 \
  -t 20
```

### Full-Featured Scan with Reports

```bash
capsaicin -u https://target.com -w wordlist.txt \
  -x php,html,js,txt \
  --depth 2 \
  --rate-limit 100 \
  --timeout 15 \
  --retries 3 \
  -o results.json \
  --html report.html \
  -v
```

### Safe Mode (No Bypass Attempts)

```bash
capsaicin -u https://target.com -w wordlist.txt --safe-mode
```

### Environment Variables

```bash
export CAPSAICIN_THREADS=20
export CAPSAICIN_RATE_LIMIT=50
export CAPSAICIN_TIMEOUT=15
export CAPSAICIN_LOG_LEVEL=debug

capsaicin -u https://target.com -w wordlist.txt
```

---

## ⚙️ Configuration

### Required Flags

| Flag | Description |
|------|-------------|
| `-u` | Target URL (or pipe via `stdin`) |
| `-w` | Path to wordlist file |

### Optional Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t` | `50` | Concurrent threads |
| `-x` | — | Extensions (comma-separated: `php,html,txt`) |
| `-H` | — | Custom header (repeatable) |
| `-v` | `false` | Verbose output |
| `-o` | — | JSON output file |
| `--html` | — | HTML report file |
| `--timeout` | `10` | Request timeout (seconds) |
| `--depth` | `0` | Recursive scan depth (0 = disabled) |
| `--rate-limit` | `0` | Max req/s per host (0 = unlimited) |
| `--retries` | `2` | Retry attempts for failed requests |
| `--max-response-mb` | `10` | Max response body size (MB) |
| `--log-level` | `info` | Log level: `debug` `info` `warn` `error` |
| `--dry-run` | `false` | Show scan plan without executing |
| `--safe-mode` | `false` | Disable bypass attempts |
| `--allow` | — | Allowed domain pattern (repeatable) |
| `--deny` | — | Denied domain pattern (repeatable) |

> **Tip:** All numeric flags can also be set via environment variables prefixed with `CAPSAICIN_`.

---

## 🏗 Architecture

```
capsaicin/
├── cmd/capsaicin/            # Entry point + signal handling
├── internal/
│   ├── config/               # Flag parsing, validation, env vars
│   ├── scanner/
│   │   ├── engine.go         # Lifecycle orchestration + context propagation
│   │   ├── worker.go         # Request processing + bypass + method fuzzing
│   │   ├── task.go           # Task & Result types
│   │   └── stats.go          # Atomic metrics
│   ├── detection/
│   │   ├── secrets.go        # 15 patterns + severity + entropy scoring
│   │   ├── waf.go            # 16 WAF signatures + body detection
│   │   └── calibration.go    # Response fingerprinting
│   ├── transport/
│   │   └── client.go         # HTTP client + rate limiter + circuit breaker
│   ├── reporting/
│   │   ├── json.go           # Versioned JSON (schema 3.0)
│   │   └── html.go           # Interactive HTML reports
│   └── ui/
│       └── output.go         # Colorful terminal output
├── .github/workflows/ci.yml  # CI pipeline
└── .golangci.yml             # Linter config
```

### Request Flow

```
CLI Input → Config Validation → Engine.RunContext(ctx)
    ↓
Calibration (per target) → Worker Pool
    ↓
Worker: makeRequest → Calibration Filter → Detection Pipeline
    ↓                                          ↓
405? → Method Fuzzing               Secret Detection (entropy)
403? → Bypass Attempts              WAF Detection (header+body)
    ↓
Results Channel → Reporter (JSON/HTML)
```

---

## 🔑 Detection Capabilities

### Secret Patterns (15)

| Pattern | Severity | Entropy Check |
|---------|----------|:---:|
| AWS Access Key | 🔴 Critical | — |
| AWS Secret Key | 🔴 Critical | — |
| Private Key (RSA/EC/DSA) | 🔴 Critical | — |
| GitHub Token | 🔴 Critical | — |
| Stripe Secret Key | 🔴 Critical | — |
| Database Connection String | 🔴 Critical | — |
| JWT Token | 🟠 High | — |
| Slack Token | 🟠 High | — |
| Google API Key | 🟠 High | — |
| Heroku API Key | 🟠 High | — |
| Mailgun API Key | 🟠 High | — |
| Twilio API Key | 🟠 High | — |
| Generic API Key | 🟡 Medium | ✓ |
| Generic Password | 🟡 Medium | ✓ |
| Stripe Publishable Key | 🟢 Low | — |

### WAF Signatures (16)

Cloudflare · AWS WAF · Akamai · Imperva · F5 BigIP · Sucuri · StackPath · Wordfence · Barracuda · ModSecurity · Fortinet FortiWeb · AWS Shield · DenyAll · Cloudfront · Fastly · Varnish

---

## 🧪 Testing

```bash
# All tests
go test ./... -v

# Race detector
go test ./... -race

# Coverage report
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Benchmarks
go test ./internal/detection -bench=. -benchmem
go test ./internal/transport -bench=. -benchmem

# Fuzz testing
go test ./internal/detection -fuzz=FuzzDetectSecrets -fuzztime=30s
```

---

## ⚠️ Responsible Use

> **This tool is designed for authorized security testing only.**

- ✅ Always obtain written authorization before scanning
- ✅ Use `--rate-limit` to avoid overloading targets
- ✅ Use `--safe-mode` when bypass attempts are not appropriate
- ✅ Report vulnerabilities responsibly through proper channels
- ❌ Never scan systems without explicit permission
- ❌ Never use findings for unauthorized access

### Recommended Rate Limits

| Environment | Rate Limit | Threads |
|-------------|-----------|---------|
| Production | `10–20` | `5–10` |
| Staging | `50–100` | `20–50` |
| Local / Dev | Unlimited | `50–100` |

---

## 📄 License

MIT — Use responsibly and legally. This tool is provided as-is for authorized security testing only.