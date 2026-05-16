# 📄 Product Requirements Document (PRD)
## Recon99 — Automated Reconnaissance & Vulnerability Scanner
**Author:** FMShomit  
**Version:** 1.0.0  
**Date:** 2026-05-16  
**Status:** Final

---

## 1. Executive Summary

Recon99 is a standalone, CLI-based cybersecurity automation tool that performs end-to-end recon → crawl → vulnerability scan → reporting workflows against authorized web targets. Built in Python with a modular architecture, it is designed for penetration testers, bug bounty hunters, and security students who need a fast, elegant, and practical tool without complex setup.

---

## 2. Goals & Non-Goals

### Goals
- Automate the full recon lifecycle in one command
- Produce a professional hacker-themed HTML report
- Be easy to run: `python main.py -t target.com --html`
- Cover ALL assignment requirements + ALL bonus items
- Include AI-assisted findings summary (Claude API)
- Ship with Docker support

### Non-Goals
- Active exploitation / destructive payloads
- DoS/flood attacks
- Scanning unauthorized targets
- GUI (CLI-first; web dashboard is optional bonus)

---

## 3. Target Users

| User | Use Case |
|------|----------|
| Security students | Assignments, CTFs, labs |
| Bug bounty hunters | Rapid attack surface discovery |
| Pentesters | Initial recon phase automation |
| Developers | Self-scanning their own apps |

---

## 4. Feature Specification

### 4.1 Core Modules

#### Module 1: Recon (`modules/recon.py`)
| Feature | Implementation |
|---------|----------------|
| DNS records (A, MX, NS, TXT, CNAME) | `dnspython` |
| Subdomain discovery | crt.sh API + brute-force wordlist |
| WHOIS lookup | `python-whois` |
| Port scanning | `socket` + threading (top 1000 ports) |
| HTTP header analysis | `requests` |
| Technology fingerprinting | Response body + header patterns |
| WAF detection | Header + error response heuristics |
| IP geolocation | ip-api.com |

#### Module 2: Crawler (`modules/crawler.py`)
| Feature | Implementation |
|---------|----------------|
| Recursive BFS crawl | `requests` + `BeautifulSoup4` |
| Configurable depth | `--depth N` flag |
| URL deduplication | Canonical normalization |
| JavaScript file extraction | `<script src>` parsing |
| Secret detection in JS | Regex patterns (API keys, tokens, passwords) |
| Form & parameter discovery | `<form>`, `<input>`, query string parsing |
| Interesting path probing | `/admin`, `/.git`, `/.env`, `/.well-known`, etc. |
| Multi-threaded fetching | `concurrent.futures.ThreadPoolExecutor` |

#### Module 3: Vulnerability Scanner (`modules/vuln_scanner.py`)
**Custom Checks (15+):**
- Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy)
- CORS misconfiguration
- Clickjacking
- Cookie flags (Secure, HttpOnly, SameSite)
- Information disclosure (.env, .git, phpinfo, actuators)
- Dangerous HTTP methods (TRACE, PUT, DELETE, OPTIONS)
- SSL/TLS check
- Directory listing
- Default credential paths
- Open redirect
- SQL injection (error-based)
- Reflected XSS
- XXE injection
- SSRF
- Local File Inclusion (LFI)

**External Integrations:**
- Nikto: `nikto -h <host> -Format txt`
- Nuclei: `nuclei -u <url> -j -severity info,low,medium,high,critical`

#### Module 4: Report Generator (`modules/report_generator.py`)
- JSON report (always generated)
- HTML report (hacker-themed dark cyberpunk design)
- AI executive summary via Claude API (optional)
- Severity badges: Critical / High / Medium / Low / Info
- Sortable findings table
- Timestamp, scan duration, target card

---

### 4.2 Utility Modules

| Utility | Purpose |
|---------|---------|
| `utils/console.py` | Rich colored terminal output with banner, spinners, progress |
| `utils/validator.py` | Target input normalization (domain/IP/URL) |
| `utils/http_client.py` | Shared session with retry, user-agent, timeout |

---

## 5. CLI Interface

```
recon99 -t <TARGET> [OPTIONS]

Required:
  -t, --target          Domain, subdomain, URL, or IP address

Scan Options:
  --ports               Ports to scan (e.g. 80,443 or 1-1000, default: top-100)
  --threads             Concurrent threads (default: 10)
  --depth               Crawl depth (default: 2)
  --timeout             Request timeout in seconds (default: 10)
  --rate-limit          Delay between requests in seconds (default: 0.1)
  --wordlist            Custom subdomain wordlist path

Module Toggles:
  --skip-recon          Skip reconnaissance phase
  --skip-crawl          Skip crawling phase
  --skip-vuln           Skip vulnerability scanning
  --skip-nikto          Skip Nikto scanner
  --skip-nuclei         Skip Nuclei scanner

Output Options:
  --output-dir          Report output directory (default: ./reports)
  --html                Generate HTML report
  --ai-summary          AI-assisted executive summary (needs ANTHROPIC_API_KEY)
  --quiet, -q           Suppress verbose output
  --no-color            Disable ANSI colors
```

---

## 6. Architecture Diagram

```
┌──────────────────────────────────────────────────────────┐
│                        main.py                           │
│  CLI parsing → Target validation → Phase orchestration   │
└────────────────────────┬─────────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    ┌──────────┐  ┌──────────┐  ┌──────────────┐
    │  recon   │  │ crawler  │  │ vuln_scanner │
    │  .py     │  │  .py     │  │    .py       │
    └──────────┘  └──────────┘  └──────────────┘
          │              │              │
          └──────────────┼──────────────┘
                         ▼
              ┌─────────────────────┐
              │  report_generator   │
              │  JSON + HTML + AI   │
              └─────────────────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
         report.json          report.html
                          (cyberpunk theme)
```

---

## 7. Data Models

### Finding Object
```json
{
  "title": "Reflected XSS",
  "severity": "high",
  "description": "User input reflected in response without encoding.",
  "url": "https://example.com/search?q=<script>",
  "evidence": "<script>alert(1)</script>",
  "tool": "custom",
  "cwe": "CWE-79",
  "remediation": "Encode all user-supplied output. Use CSP headers."
}
```

### Scan Result Object
```json
{
  "meta": { "target": {}, "start_time": "", "end_time": "", "duration": "" },
  "recon": { "dns": {}, "subdomains": [], "open_ports": [], "headers": {}, "technologies": [], "whois": {} },
  "crawl": { "urls": [], "js_files": [], "parameters": [], "forms": [], "secrets": [], "interesting_paths": [] },
  "vulns": { "critical": [], "high": [], "medium": [], "low": [], "info": [] },
  "summary": { "total_findings": 0, "risk_score": "" }
}
```

---

## 8. Technical Requirements

| Requirement | Specification |
|-------------|---------------|
| Language | Python 3.10+ |
| Architecture | Modular (4 core modules + 3 utils) |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` |
| Error Handling | Try/except on all I/O + network calls |
| Output | Rich ANSI terminal with spinners |
| Dependencies | See `requirements.txt` |
| Packaging | `setup.py` (pip-installable) |
| Container | `Dockerfile` + `docker-compose.yml` |

---

## 9. Setup Requirements

### Python Dependencies (`requirements.txt`)
```
requests>=2.31.0
beautifulsoup4>=4.12.0
dnspython>=2.4.0
python-whois>=0.9.0
rich>=13.0.0
anthropic>=0.25.0
colorama>=0.4.6
urllib3>=2.0.0
lxml>=4.9.0
```

### External Tools (Optional)
- `nikto` — `sudo apt install nikto`
- `nuclei` — https://github.com/projectdiscovery/nuclei/releases

---

## 10. Security & Ethics

- **Authorization required:** Tool must only scan authorized targets
- **No destructive payloads:** All checks are passive/read-only
- **Rate limiting built-in:** Default 100ms delay; `--rate-limit` for stealth
- **Legal disclaimer:** Displayed in banner on every launch

---

## 11. Deliverables

| Deliverable | Status |
|------------|--------|
| `main.py` | ✅ |
| `modules/recon.py` | ✅ |
| `modules/crawler.py` | ✅ |
| `modules/vuln_scanner.py` | ✅ |
| `modules/report_generator.py` | ✅ |
| `utils/console.py` | ✅ |
| `utils/validator.py` | ✅ |
| `utils/http_client.py` | ✅ |
| `setup.py` | ✅ |
| `requirements.txt` | ✅ |
| `Dockerfile` | ✅ |
| `docker-compose.yml` | ✅ |
| `README.md` | ✅ |
| `PRD.md` | ✅ |
| `.gitignore` | ✅ |

---

## 12. Evaluation Coverage

| Criteria | Marks | Coverage |
|----------|-------|----------|
| Functionality | 30 | All recon, crawl, vuln, report ✅ |
| Recon Automation | 25 | DNS, subdomains, ports, WHOIS, headers, tech ✅ |
| Real-World Practicality | 20 | Nikto, Nuclei, AI summary, Docker ✅ |
| Code Quality | 15 | Modular, commented, error handling ✅ |
| Reporting & Documentation | 10 | JSON + HTML + PRD + README ✅ |
| **Total** | **100** | **100** |
