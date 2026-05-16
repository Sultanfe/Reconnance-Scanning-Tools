"""
modules/crawler.py
Recon99 — Recursive web crawler
BFS crawl, JS extraction, secret detection, form/param harvesting, interesting paths
Author: FMShomit
"""

import re
import time
import threading
from collections import deque
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

from bs4 import BeautifulSoup

from utils.console import console, info, success, warn, section
from utils.http_client import build_session, safe_get


# ── Interesting paths to probe ────────────────────────────────────────────────
INTERESTING_PATHS = [
    "/.env", "/.git/HEAD", "/.git/config", "/admin", "/admin.php",
    "/phpinfo.php", "/info.php", "/wp-admin", "/wp-login.php",
    "/api/v1", "/api/v2", "/api/swagger", "/swagger-ui.html",
    "/actuator", "/actuator/health", "/actuator/env",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/backup", "/backup.zip", "/dump.sql", "/db.sql",
    "/server-status", "/server-info", "/.htaccess",
    "/config.php", "/config.json", "/config.yaml", "/config.yml",
    "/web.config", "/appsettings.json", "/secrets.json",
    "/debug", "/console", "/trace", "/status", "/health",
]

# ── Regex patterns to detect secrets in JS / pages ───────────────────────────
SECRET_PATTERNS = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token":         r"ghp_[0-9a-zA-Z]{36}",
    "JWT Token":            r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*",
    "Slack Token":          r"xox[baprs]-[0-9A-Za-z]{10,48}",
    "Generic API Key":      r"(?i)(api[_\-]?key|apikey|api[_\-]?token)['\"\s:=]+['\"]([a-zA-Z0-9_\-]{16,64})['\"]",
    "Private Key":          r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    "Password in code":     r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
    "Basic Auth in URL":    r"https?://[a-zA-Z0-9_\-]+:[^@]{6,}@",
    "Database URL":         r"(?i)(mysql|postgres|mongodb|redis|sqlite)://[^\s'\"]+",
    "Anthropic API Key":    r"sk-ant-[a-zA-Z0-9_\-]{40,}",
    "OpenAI API Key":       r"sk-[a-zA-Z0-9]{32,}",
}


class CrawlerModule:
    """Recursive BFS web crawler."""

    def __init__(self, target_info: dict, config: dict):
        self.target  = target_info
        self.config  = config
        self.session = build_session(
            timeout=config.get("timeout", 10),
            user_agent=config.get("user_agent", ""),
        )
        self.max_depth    = config.get("depth", 2)
        self.threads      = config.get("threads", 10)
        self.rate_limit   = config.get("rate_limit", 0.1)
        self.base_host    = target_info["host"]
        self.base_url     = target_info["url"]

        self.visited:      set = set()
        self.urls:         list = []
        self.js_files:     list = []
        self.parameters:   list = []
        self.forms:        list = []
        self.secrets:      list = []
        self.interesting:  list = []

        self._lock = threading.Lock()

    # ── Public entry point ────────────────────────────────────────────────────
    def run(self) -> dict:
        section("Phase 2: Crawling")
        info(f"Starting BFS crawl (depth={self.max_depth}, threads={self.threads})")

        self._bfs_crawl()
        self._probe_interesting_paths()

        success(
            f"Crawl complete — {len(self.urls)} URLs, "
            f"{len(self.js_files)} JS files, "
            f"{len(self.parameters)} params, "
            f"{len(self.secrets)} potential secrets"
        )

        return {
            "urls":              self.urls,
            "js_files":          list(set(self.js_files)),
            "parameters":        list(set(self.parameters)),
            "forms":             self.forms,
            "secrets":           self.secrets,
            "interesting_paths": self.interesting,
        }

    # ── BFS Crawl ─────────────────────────────────────────────────────────────
    def _bfs_crawl(self) -> None:
        queue = deque([(self.base_url, 0)])
        self.visited.add(self.base_url)

        while queue:
            batch = []
            while queue and len(batch) < self.threads * 2:
                batch.append(queue.popleft())

            with threading.Semaphore(self.threads):
                threads = []
                for url, depth in batch:
                    t = threading.Thread(target=self._process_url, args=(url, depth, queue))
                    threads.append(t)
                    t.start()
                for t in threads:
                    t.join()

    def _process_url(self, url: str, depth: int, queue: deque) -> None:
        time.sleep(self.rate_limit)
        resp, err = safe_get(self.session, url)
        if err or not resp:
            return

        with self._lock:
            if url not in self.urls:
                self.urls.append(url)
                info(f"  [dim]crawled[/] {url[:80]}")

        content_type = resp.headers.get("Content-Type", "")
        if "javascript" in content_type:
            self._analyze_js(url, resp.text)
            return

        if "html" not in content_type:
            return

        soup = BeautifulSoup(resp.text, "lxml")
        self._extract_parameters(url, resp.text)
        self._extract_forms(url, soup)
        self._extract_js(url, soup)

        if depth >= self.max_depth:
            return

        new_links = self._extract_links(url, soup)
        with self._lock:
            for link in new_links:
                if link not in self.visited:
                    self.visited.add(link)
                    queue.append((link, depth + 1))

    # ── Link extraction ───────────────────────────────────────────────────────
    def _extract_links(self, base: str, soup: BeautifulSoup) -> list:
        links = []
        for tag in soup.find_all(["a", "link", "area"], href=True):
            raw = tag["href"].strip()
            full = urljoin(base, raw)
            parsed = urlparse(full)
            # Stay in scope (same host)
            if parsed.netloc and self.base_host not in parsed.netloc:
                continue
            clean = parsed._replace(fragment="").geturl()
            if clean and clean not in self.visited:
                links.append(clean)
        return links

    # ── JS file extraction & analysis ────────────────────────────────────────
    def _extract_js(self, base: str, soup: BeautifulSoup) -> None:
        for tag in soup.find_all("script", src=True):
            src = urljoin(base, tag["src"])
            with self._lock:
                if src not in self.js_files:
                    self.js_files.append(src)
            # Fetch and scan JS for secrets
            resp, _ = safe_get(self.session, src)
            if resp:
                self._analyze_js(src, resp.text)

    def _analyze_js(self, url: str, content: str) -> None:
        for label, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                val = match if isinstance(match, str) else match[-1]
                finding_obj = {
                    "type":    label,
                    "value":   val[:80],
                    "source":  url,
                }
                with self._lock:
                    if finding_obj not in self.secrets:
                        self.secrets.append(finding_obj)
                        warn(f"  [medium]Secret found:[/] {label} in {url[:60]}")

        # Also collect endpoint-like strings from JS
        endpoints = re.findall(r'["\'](/[a-zA-Z0-9_\-/\.?=&%]{3,80})["\']', content)
        with self._lock:
            for ep in endpoints:
                full = urljoin(self.base_url, ep)
                if self.base_host in full and full not in self.urls:
                    self.urls.append(full)

    # ── Parameter discovery ───────────────────────────────────────────────────
    def _extract_parameters(self, url: str, html: str) -> None:
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        with self._lock:
            self.parameters.extend(p for p in params if p not in self.parameters)

        # HTML hidden inputs and data-* attributes
        hidden = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.I)
        with self._lock:
            self.parameters.extend(p for p in hidden if p not in self.parameters)

    # ── Form discovery ────────────────────────────────────────────────────────
    def _extract_forms(self, url: str, soup: BeautifulSoup) -> None:
        for form in soup.find_all("form"):
            action  = form.get("action", url)
            method  = form.get("method", "GET").upper()
            full_action = urljoin(url, action)
            fields  = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                ftype = inp.get("type", "text")
                if name:
                    fields.append({"name": name, "type": ftype})
            form_obj = {"url": full_action, "method": method, "fields": fields}
            with self._lock:
                if form_obj not in self.forms:
                    self.forms.append(form_obj)

    # ── Interesting path probing ──────────────────────────────────────────────
    def _probe_interesting_paths(self) -> None:
        info("Probing interesting paths...")

        def probe(path):
            url = self.base_url.rstrip("/") + path
            resp, _ = safe_get(self.session, url)
            if resp and resp.status_code not in (404, 400, 403, 410):
                entry = {
                    "path":   path,
                    "url":    url,
                    "status": resp.status_code,
                    "size":   len(resp.content),
                }
                with self._lock:
                    self.interesting.append(entry)
                    warn(f"  [medium]Interesting:[/] {path} → HTTP {resp.status_code}")

        with threading.Semaphore(self.threads):
            ts = [threading.Thread(target=probe, args=(p,)) for p in INTERESTING_PATHS]
            for t in ts: t.start()
            for t in ts: t.join()

        if self.interesting:
            success(f"Found {len(self.interesting)} interesting paths")
