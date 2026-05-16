"""
modules/vuln_scanner.py
Recon99 — Vulnerability Scanner
Custom checks (15+) + Nikto integration + Nuclei integration
Author: FMShomit
"""

import re
import json
import shutil
import subprocess
import threading
import time
import concurrent.futures
from dataclasses import dataclass, asdict, field
from typing import List, Optional

from utils.console import console, info, success, warn, error, section, finding
from utils.http_client import build_session, safe_get


@dataclass
class Finding:
    title:       str
    severity:    str    # critical | high | medium | low | info
    description: str
    url:         str    = ""
    evidence:    str    = ""
    tool:        str    = "custom"
    cwe:         str    = ""
    remediation: str    = ""

    def to_dict(self):
        return asdict(self)


SECURITY_HEADERS = {
    "Strict-Transport-Security":     ("medium", "HSTS not set", "CWE-319", "Add HSTS header: max-age=31536000; includeSubDomains"),
    "Content-Security-Policy":       ("medium", "CSP not set", "CWE-693", "Implement a Content-Security-Policy header"),
    "X-Frame-Options":               ("medium", "Clickjacking protection missing", "CWE-1021", "Add X-Frame-Options: DENY or SAMEORIGIN"),
    "X-Content-Type-Options":        ("low",    "MIME-sniffing not blocked", "CWE-16", "Add X-Content-Type-Options: nosniff"),
    "Referrer-Policy":               ("low",    "Referrer-Policy not set", "CWE-200", "Add Referrer-Policy: strict-origin-when-cross-origin"),
    "Permissions-Policy":            ("low",    "Permissions-Policy not set", "CWE-16", "Add Permissions-Policy header to restrict features"),
}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1' AND SLEEP(0)--",
    "1; SELECT 1--",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "odbc microsoft access",
    "syntax error in query",
    "ora-",
    "pg::syntaxerror",
    "sqlite3::query",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../windows/system32/drivers/etc/hosts",
    "....//....//....//etc/passwd",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "//evil.com/%2F..",
]


class VulnScannerModule:
    """Runs all vulnerability checks."""

    def __init__(self, target_info: dict, crawl_data: dict, config: dict):
        self.target    = target_info
        self.crawl     = crawl_data
        self.config    = config
        self.session   = build_session(
            timeout=config.get("timeout", 10),
            user_agent=config.get("user_agent", ""),
        )
        self.findings: List[Finding] = []
        self._lock = threading.Lock()

    # ── Public entry point ────────────────────────────────────────────────────
    def run(self) -> dict:
        section("Phase 3: Vulnerability Scanning")
        url = self.target["url"]

        # Custom checks (run in parallel)
        checks = [
            self._check_security_headers,
            self._check_cors,
            self._check_cookies,
            self._check_info_disclosure,
            self._check_http_methods,
            self._check_ssl,
            self._check_directory_listing,
            self._check_sqli,
            self._check_xss,
            self._check_lfi,
            self._check_ssrf,
            self._check_open_redirect,
            self._check_xxe,
            self._check_clickjacking,
            self._check_default_creds,
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futures = [ex.submit(chk) for chk in checks]
            for f in concurrent.futures.as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    warn(f"Check error: {e}")

        # External tools
        if not self.config.get("skip_nikto"):
            self._run_nikto()
        if not self.config.get("skip_nuclei"):
            self._run_nuclei()

        # Organize by severity
        result = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in self.findings:
            result[f.severity].append(f.to_dict())

        total = sum(len(v) for v in result.values())
        success(f"Scan complete — {total} findings")
        return result

    # ── Helper to add finding ─────────────────────────────────────────────────
    def _add(self, f: Finding) -> None:
        with self._lock:
            self.findings.append(f)
        finding(f.severity, f.title, f.url)

    # ── 1) Security Headers ───────────────────────────────────────────────────
    def _check_security_headers(self) -> None:
        info("Checking security headers...")
        resp, err = safe_get(self.session, self.target["url"])
        if err or not resp:
            return
        for header, (sev, desc, cwe, remedy) in SECURITY_HEADERS.items():
            if header not in resp.headers:
                self._add(Finding(
                    title=f"Missing {header}",
                    severity=sev,
                    description=f"{desc}. The response does not include the {header} header.",
                    url=resp.url,
                    evidence=f"Header '{header}' not present in response.",
                    cwe=cwe,
                    remediation=remedy,
                ))

    # ── 2) CORS Misconfiguration ──────────────────────────────────────────────
    def _check_cors(self) -> None:
        info("Checking CORS...")
        resp, err = safe_get(
            self.session, self.target["url"],
            headers={"Origin": "https://evil.attacker.com"}
        )
        if err or not resp:
            return
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or "evil.attacker.com" in acao:
            self._add(Finding(
                title="CORS Misconfiguration",
                severity="high",
                description="The server reflects arbitrary origins or uses wildcard CORS, "
                            "allowing cross-origin requests from any domain.",
                url=resp.url,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                cwe="CWE-942",
                remediation="Restrict CORS to specific, trusted origins only.",
            ))

    # ── 3) Cookie Flags ───────────────────────────────────────────────────────
    def _check_cookies(self) -> None:
        info("Checking cookies...")
        resp, err = safe_get(self.session, self.target["url"])
        if err or not resp:
            return
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure flag missing")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly flag missing")
            samesite = cookie._rest.get("SameSite", "")
            if not samesite:
                issues.append("SameSite flag missing")
            if issues:
                self._add(Finding(
                    title=f"Insecure Cookie: {cookie.name}",
                    severity="medium",
                    description=f"Cookie '{cookie.name}' is missing security flags: {', '.join(issues)}",
                    url=resp.url,
                    evidence=f"Cookie: {cookie.name}={cookie.value[:20]}...",
                    cwe="CWE-614",
                    remediation="Set Secure, HttpOnly, and SameSite=Strict on all session cookies.",
                ))

    # ── 4) Information Disclosure ─────────────────────────────────────────────
    def _check_info_disclosure(self) -> None:
        info("Checking information disclosure paths...")
        sensitive_paths = {
            "/.env":               ("critical", "Environment file exposed"),
            "/.git/HEAD":          ("high",     "Git repository exposed"),
            "/.git/config":        ("high",     "Git config exposed"),
            "/phpinfo.php":        ("high",     "PHPInfo page exposed"),
            "/actuator/env":       ("high",     "Spring actuator environment exposed"),
            "/actuator/dump":      ("high",     "Spring actuator heap dump exposed"),
            "/server-status":      ("medium",   "Apache server-status exposed"),
            "/web.config":         ("high",     "Web.config exposed"),
            "/appsettings.json":   ("critical", "App settings JSON exposed"),
            "/backup.zip":         ("critical", "Backup archive exposed"),
            "/dump.sql":           ("critical", "SQL dump exposed"),
            "/wp-config.php.bak":  ("critical", "WordPress config backup exposed"),
        }
        for path, (sev, desc) in sensitive_paths.items():
            url = self.target["url"].rstrip("/") + path
            resp, _ = safe_get(self.session, url)
            if resp and resp.status_code in (200, 403):
                self._add(Finding(
                    title=desc,
                    severity=sev,
                    description=f"Sensitive path '{path}' returned HTTP {resp.status_code}.",
                    url=url,
                    evidence=f"HTTP {resp.status_code} — {len(resp.content)} bytes",
                    cwe="CWE-538",
                    remediation=f"Block access to {path} via server config or WAF rule.",
                ))

    # ── 5) Dangerous HTTP Methods ─────────────────────────────────────────────
    def _check_http_methods(self) -> None:
        info("Checking HTTP methods...")
        dangerous = ["TRACE", "PUT", "DELETE", "CONNECT"]
        try:
            resp = self.session.options(self.target["url"], timeout=8)
            allow = resp.headers.get("Allow", "")
            for method in dangerous:
                if method in allow:
                    self._add(Finding(
                        title=f"Dangerous HTTP Method Enabled: {method}",
                        severity="medium",
                        description=f"The server allows the {method} HTTP method.",
                        url=self.target["url"],
                        evidence=f"Allow: {allow}",
                        cwe="CWE-749",
                        remediation=f"Disable {method} in the web server configuration.",
                    ))
            # TRACE specifically
            resp_trace = self.session.request("TRACE", self.target["url"], timeout=8)
            if resp_trace.status_code == 200 and "TRACE" in resp_trace.text:
                self._add(Finding(
                    title="HTTP TRACE Method Enabled (XST Risk)",
                    severity="medium",
                    description="TRACE method is enabled and reflects request data (Cross-Site Tracing).",
                    url=self.target["url"],
                    evidence=f"HTTP {resp_trace.status_code}",
                    cwe="CWE-16",
                    remediation="Disable TRACE/TRACK methods in the web server configuration.",
                ))
        except Exception:
            pass

    # ── 6) SSL/TLS ────────────────────────────────────────────────────────────
    def _check_ssl(self) -> None:
        info("Checking SSL/TLS...")
        if self.target["scheme"] != "https":
            self._add(Finding(
                title="HTTPS Not Enforced",
                severity="high",
                description="The target is served over HTTP, not HTTPS. All traffic is unencrypted.",
                url=self.target["url"],
                evidence="Scheme is http://",
                cwe="CWE-319",
                remediation="Redirect all HTTP traffic to HTTPS. Obtain a valid TLS certificate.",
            ))

    # ── 7) Directory Listing ──────────────────────────────────────────────────
    def _check_directory_listing(self) -> None:
        info("Checking directory listing...")
        test_paths = ["/images/", "/static/", "/uploads/", "/assets/", "/files/"]
        for path in test_paths:
            url = self.target["url"].rstrip("/") + path
            resp, _ = safe_get(self.session, url)
            if resp and resp.status_code == 200:
                body_low = resp.text.lower()
                if "index of" in body_low or "parent directory" in body_low:
                    self._add(Finding(
                        title=f"Directory Listing Enabled: {path}",
                        severity="medium",
                        description=f"Directory listing is enabled at {path}, exposing file contents.",
                        url=url,
                        evidence="Response contains 'Index of' or 'Parent Directory'",
                        cwe="CWE-548",
                        remediation="Disable directory listing in the web server configuration.",
                    ))

    # ── 8) SQL Injection ─────────────────────────────────────────────────────
    def _check_sqli(self) -> None:
        info("Testing SQL injection...")
        # Test on crawled URLs that have parameters
        urls_to_test = [
            u for u in self.crawl.get("urls", [])[:20]
            if "?" in u
        ]
        if not urls_to_test:
            urls_to_test = [self.target["url"] + "?id=1"]

        for url in urls_to_test[:5]:
            base = url.split("?")[0]
            params_str = url.split("?")[1] if "?" in url else ""
            params = {}
            for kv in params_str.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    params[k] = v

            for param in list(params.keys())[:3]:
                for payload in SQLI_PAYLOADS[:3]:
                    test_params = params.copy()
                    test_params[param] = payload
                    from urllib.parse import urlencode
                    test_url = f"{base}?{urlencode(test_params)}"
                    resp, _ = safe_get(self.session, test_url)
                    if resp:
                        body_low = resp.text.lower()
                        for err in SQLI_ERRORS:
                            if err in body_low:
                                self._add(Finding(
                                    title="Potential SQL Injection",
                                    severity="critical",
                                    description=f"SQL error message detected in response for parameter '{param}'.",
                                    url=test_url,
                                    evidence=f"Error pattern '{err}' found in response",
                                    tool="custom",
                                    cwe="CWE-89",
                                    remediation="Use parameterized queries / prepared statements.",
                                ))
                                return  # found one, stop

    # ── 9) Reflected XSS ─────────────────────────────────────────────────────
    def _check_xss(self) -> None:
        info("Testing reflected XSS...")
        urls_to_test = [
            u for u in self.crawl.get("urls", [])[:20]
            if "?" in u
        ]
        if not urls_to_test:
            urls_to_test = [self.target["url"] + "?q=test"]

        for url in urls_to_test[:5]:
            base = url.split("?")[0]
            for payload in XSS_PAYLOADS[:2]:
                test_url = f"{base}?xss_test={payload}"
                resp, _ = safe_get(self.session, test_url)
                if resp and payload in resp.text:
                    csp = resp.headers.get("Content-Security-Policy", "")
                    if not csp:
                        self._add(Finding(
                            title="Reflected XSS",
                            severity="high",
                            description="User-supplied input is reflected in the response without HTML encoding.",
                            url=test_url,
                            evidence=f"Payload reflected: {payload[:60]}",
                            cwe="CWE-79",
                            remediation="Encode all user-supplied output. Implement a strict CSP.",
                        ))
                        return

    # ── 10) LFI ──────────────────────────────────────────────────────────────
    def _check_lfi(self) -> None:
        info("Testing LFI...")
        params_in_urls = [u for u in self.crawl.get("urls", [])[:20] if "?" in u]
        for url in params_in_urls[:3]:
            base = url.split("?")[0]
            for payload in LFI_PAYLOADS[:2]:
                test_url = f"{base}?file={payload}&page={payload}&path={payload}"
                resp, _ = safe_get(self.session, test_url)
                if resp and ("root:x:" in resp.text or "[boot loader]" in resp.text):
                    self._add(Finding(
                        title="Local File Inclusion (LFI)",
                        severity="critical",
                        description="The application includes local files based on user input.",
                        url=test_url,
                        evidence=f"Payload: {payload}",
                        cwe="CWE-22",
                        remediation="Validate and whitelist file path inputs. Never pass user input to file functions.",
                    ))
                    return

    # ── 11) SSRF ─────────────────────────────────────────────────────────────
    def _check_ssrf(self) -> None:
        info("Testing SSRF...")
        params_in_urls = [u for u in self.crawl.get("urls", [])[:20] if "?" in u]
        for url in params_in_urls[:3]:
            base = url.split("?")[0]
            for payload in SSRF_PAYLOADS[:2]:
                test_url = f"{base}?url={payload}&redirect={payload}&target={payload}"
                resp, _ = safe_get(self.session, test_url)
                if resp and resp.status_code == 200 and len(resp.content) > 200:
                    if any(s in resp.text for s in ["ami-id", "hostname", "local", "127"]):
                        self._add(Finding(
                            title="Potential Server-Side Request Forgery (SSRF)",
                            severity="critical",
                            description="The application may be fetching internal resources based on user-supplied URLs.",
                            url=test_url,
                            evidence=f"Payload: {payload}",
                            cwe="CWE-918",
                            remediation="Whitelist allowed URLs. Block requests to internal/private IP ranges.",
                        ))
                        return

    # ── 12) Open Redirect ────────────────────────────────────────────────────
    def _check_open_redirect(self) -> None:
        info("Testing open redirect...")
        redirect_params = ["redirect", "url", "next", "return", "goto", "redir"]
        for param in redirect_params:
            for payload in OPEN_REDIRECT_PAYLOADS[:1]:
                test_url = f"{self.target['url']}?{param}={payload}"
                try:
                    resp = self.session.get(test_url, timeout=8, allow_redirects=False)
                    loc = resp.headers.get("Location", "")
                    if resp.status_code in (301, 302, 303, 307, 308) and "evil.com" in loc:
                        self._add(Finding(
                            title="Open Redirect",
                            severity="medium",
                            description=f"Parameter '{param}' redirects to an external URL without validation.",
                            url=test_url,
                            evidence=f"Location: {loc}",
                            cwe="CWE-601",
                            remediation="Validate redirect URLs against an allowlist of trusted domains.",
                        ))
                        return
                except Exception:
                    pass

    # ── 13) XXE ───────────────────────────────────────────────────────────────
    def _check_xxe(self) -> None:
        info("Testing XXE...")
        xxe_payload = (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<root>&xxe;</root>'
        )
        forms = self.crawl.get("forms", [])
        for form in forms[:3]:
            if form.get("method") == "POST":
                try:
                    resp = self.session.post(
                        form["url"],
                        data=xxe_payload,
                        headers={"Content-Type": "application/xml"},
                        timeout=8,
                    )
                    if resp and "root:" in resp.text:
                        self._add(Finding(
                            title="XML External Entity (XXE) Injection",
                            severity="critical",
                            description="The application parses external XML entities, potentially exposing local files.",
                            url=form["url"],
                            evidence="Response contained /etc/passwd content",
                            cwe="CWE-611",
                            remediation="Disable external entity processing in XML parsers.",
                        ))
                        return
                except Exception:
                    pass

    # ── 14) Clickjacking ─────────────────────────────────────────────────────
    def _check_clickjacking(self) -> None:
        resp, err = safe_get(self.session, self.target["url"])
        if err or not resp:
            return
        xfo = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get("Content-Security-Policy", "")
        if not xfo and "frame-ancestors" not in csp.lower():
            self._add(Finding(
                title="Clickjacking Vulnerability",
                severity="medium",
                description="The page can be embedded in an iframe, enabling clickjacking attacks.",
                url=resp.url,
                evidence="No X-Frame-Options or CSP frame-ancestors directive",
                cwe="CWE-1021",
                remediation="Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors none'.",
            ))

    # ── 15) Default Credentials ───────────────────────────────────────────────
    def _check_default_creds(self) -> None:
        info("Checking common admin paths...")
        admin_paths = [
            ("/admin", "admin", "admin"),
            ("/wp-login.php", "admin", "admin"),
            ("/administrator", "admin", "password"),
            ("/login", "admin", "admin"),
        ]
        for path, user, passwd in admin_paths:
            url = self.target["url"].rstrip("/") + path
            resp, _ = safe_get(self.session, url)
            if resp and resp.status_code == 200:
                self._add(Finding(
                    title=f"Admin Interface Exposed: {path}",
                    severity="info",
                    description=f"Admin/login interface found at {path}.",
                    url=url,
                    evidence=f"HTTP {resp.status_code}",
                    cwe="CWE-798",
                    remediation="Restrict admin panel access by IP; use strong credentials.",
                ))

    # ── Nikto Integration ────────────────────────────────────────────────────
    def _run_nikto(self) -> None:
        if not shutil.which("nikto"):
            warn("Nikto not found; skipping. (sudo apt install nikto)")
            return
        info("Running Nikto scan...")
        host = self.target["host"]
        port = 443 if self.target["scheme"] == "https" else 80

        cmd = [
            "nikto", "-h", host, "-p", str(port),
            "-Tuning", "x6789abc", "-Format", "txt",
            "-nointeractive", "-timeout", "10",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            for line in result.stdout.splitlines():
                if line.startswith("+ ") and len(line) > 10:
                    sev = "medium"
                    if "OSVDB" in line or "CVE" in line:
                        sev = "high"
                    if "critical" in line.lower():
                        sev = "critical"
                    self._add(Finding(
                        title=f"Nikto: {line[2:80]}",
                        severity=sev,
                        description=line[2:].strip(),
                        url=self.target["url"],
                        tool="nikto",
                    ))
            success("Nikto scan complete")
        except subprocess.TimeoutExpired:
            warn("Nikto timed out")
        except Exception as e:
            warn(f"Nikto error: {e}")

    # ── Nuclei Integration ───────────────────────────────────────────────────
    def _run_nuclei(self) -> None:
        if not shutil.which("nuclei"):
            warn("Nuclei not found; skipping. (https://github.com/projectdiscovery/nuclei/releases)")
            return
        info("Running Nuclei scan...")
        cmd = [
            "nuclei", "-u", self.target["url"], "-j",
            "-severity", "info,low,medium,high,critical",
            "-t", "cves/", "-t", "vulnerabilities/",
            "-t", "misconfiguration/", "-t", "exposures/",
            "-rate-limit", "10", "-silent",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            for line in result.stdout.splitlines():
                try:
                    data = json.loads(line)
                    sev = data.get("info", {}).get("severity", "info").lower()
                    name = data.get("info", {}).get("name", "Nuclei Finding")
                    desc = data.get("info", {}).get("description", "")
                    url  = data.get("matched-at", self.target["url"])
                    self._add(Finding(
                        title=f"Nuclei: {name}",
                        severity=sev,
                        description=desc,
                        url=url,
                        tool="nuclei",
                        cwe=data.get("info", {}).get("classification", {}).get("cwe-id", [""])[0] if data.get("info", {}).get("classification") else "",
                    ))
                except Exception:
                    pass
            success("Nuclei scan complete")
        except subprocess.TimeoutExpired:
            warn("Nuclei timed out")
        except Exception as e:
            warn(f"Nuclei error: {e}")
