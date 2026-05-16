"""
modules/recon.py
Recon99 — Reconnaissance module
Collects: DNS, subdomains, WHOIS, open ports, HTTP headers, technologies, WAF, GeoIP
Author: FMShomit
"""

import socket
import time
import json
import threading
import concurrent.futures
from typing import Optional

import requests
import dns.resolver
import dns.reversename
import whois

from utils.console import console, info, success, warn, error, section, finding
from utils.http_client import build_session, safe_get


# ── Subdomain wordlist (built-in mini list; user can supply --wordlist) ────────
DEFAULT_SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "ns", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
    "test", "ns3", "vpn", "mail2", "new", "mysql", "old", "lists", "support",
    "mobile", "mx", "static", "docs", "beta", "shop", "secure", "api", "dev",
    "staging", "admin", "portal", "blog", "cdn", "git", "status", "auth",
    "dashboard", "app", "v1", "v2", "demo", "prod", "db", "sql", "remote",
]

# ── Technology fingerprint signatures ─────────────────────────────────────────
TECH_SIGNATURES = {
    "WordPress":   ["wp-content", "wp-includes", "WordPress"],
    "Drupal":      ["Drupal", "drupal.org"],
    "Joomla":      ["Joomla", "joomla.org"],
    "Laravel":     ["laravel_session", "Laravel"],
    "Django":      ["csrfmiddlewaretoken", "Django"],
    "Flask":       ["Werkzeug"],
    "React":       ["react-dom", "__REACT"],
    "Angular":     ["ng-version", "angular.js"],
    "Vue.js":      ["vue.js", "__vue__"],
    "jQuery":      ["jquery"],
    "Bootstrap":   ["bootstrap.min.css", "bootstrap.js"],
    "Nginx":       ["nginx"],
    "Apache":      ["Apache"],
    "IIS":         ["Microsoft-IIS", "ASP.NET"],
    "PHP":         ["X-Powered-By: PHP", "php"],
    "Node.js":     ["X-Powered-By: Express", "node.js"],
    "Cloudflare":  ["cloudflare", "cf-ray"],
    "AWS":         ["x-amz-", "amazonaws.com"],
    "Google Cloud":["x-goog-", "googleapis.com"],
}

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
    1080, 1443, 3000, 3306, 3389, 4444, 5000, 5432, 5900, 6379, 8000,
    8008, 8080, 8443, 8888, 9000, 9200, 9300, 27017,
]


class ReconModule:
    """Performs all reconnaissance tasks against a target."""

    def __init__(self, target_info: dict, config: dict):
        self.target = target_info
        self.config  = config
        self.session = build_session(
            timeout=config.get("timeout", 10),
            user_agent=config.get("user_agent", ""),
        )
        self.results = {
            "dns":           {},
            "subdomains":    [],
            "whois":         {},
            "open_ports":    [],
            "headers":       {},
            "technologies":  [],
            "waf":           None,
            "geo":           {},
        }

    # ── Public entry point ────────────────────────────────────────────────────
    def run(self) -> dict:
        host = self.target["host"]
        section("Phase 1: Reconnaissance")
        info(f"Target: [target]{host}[/]")

        self._dns_enum(host)
        self._subdomain_enum(host)
        self._whois_lookup(host)
        self._port_scan(host)
        self._header_analysis()
        self._tech_fingerprint()
        self._waf_detect()
        self._geo_lookup(host)

        success(f"Recon complete — {len(self.results['subdomains'])} subdomains, "
                f"{len(self.results['open_ports'])} open ports")
        return self.results

    # ── DNS Enumeration ───────────────────────────────────────────────────────
    def _dns_enum(self, host: str) -> None:
        info("Running DNS enumeration...")
        dns_data = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in record_types:
            try:
                answers = resolver.resolve(host, rtype)
                dns_data[rtype] = [str(r) for r in answers]
            except Exception:
                dns_data[rtype] = []

        self.results["dns"] = dns_data
        a_records = dns_data.get("A", [])
        if a_records:
            success(f"DNS A records: {', '.join(a_records[:5])}")

    # ── Subdomain Enumeration ─────────────────────────────────────────────────
    def _subdomain_enum(self, host: str) -> None:
        info("Enumerating subdomains (crt.sh + brute-force)...")
        found = set()

        # 1) crt.sh certificate transparency
        try:
            resp, err = safe_get(
                self.session,
                f"https://crt.sh/?q=%.{host}&output=json",
                timeout=15,
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(host) and sub != host:
                            found.add(sub)
        except Exception:
            pass

        # 2) Brute-force wordlist
        wordlist_path = self.config.get("wordlist", "")
        words = DEFAULT_SUBDOMAIN_WORDLIST.copy()
        if wordlist_path:
            try:
                with open(wordlist_path) as f:
                    words = [l.strip() for l in f if l.strip()]
            except Exception:
                pass

        lock = threading.Lock()
        threads = min(self.config.get("threads", 10), 20)

        def check_subdomain(word):
            sub = f"{word}.{host}"
            try:
                socket.getaddrinfo(sub, None, timeout=2)
                with lock:
                    found.add(sub)
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            ex.map(check_subdomain, words)

        self.results["subdomains"] = sorted(found)
        if found:
            success(f"Discovered {len(found)} subdomains")
        else:
            warn("No subdomains found")

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    def _whois_lookup(self, host: str) -> None:
        if self.target["is_ip"]:
            return
        info("Performing WHOIS lookup...")
        try:
            w = whois.whois(host)
            self.results["whois"] = {
                "registrar":       str(w.registrar or ""),
                "creation_date":   str(w.creation_date or ""),
                "expiration_date": str(w.expiration_date or ""),
                "name_servers":    [str(ns) for ns in (w.name_servers or [])],
                "status":          str(w.status or ""),
                "emails":          [str(e) for e in (w.emails or [])],
                "org":             str(w.org or ""),
                "country":         str(w.country or ""),
            }
            success(f"WHOIS: registrar={w.registrar or 'N/A'}")
        except Exception as e:
            warn(f"WHOIS failed: {e}")

    # ── Port Scan ─────────────────────────────────────────────────────────────
    def _port_scan(self, host: str) -> None:
        info("Scanning ports...")
        ports_cfg = self.config.get("ports", "")
        ports = self._parse_ports(ports_cfg)
        threads = min(self.config.get("threads", 10), 50)
        open_ports = []
        lock = threading.Lock()

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((host, port))
                if result == 0:
                    banner = self._grab_banner(sock, port)
                    service = self._guess_service(port)
                    with lock:
                        open_ports.append({
                            "port": port,
                            "service": service,
                            "banner": banner,
                        })
                sock.close()
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            ex.map(scan_port, ports)

        open_ports.sort(key=lambda x: x["port"])
        self.results["open_ports"] = open_ports
        if open_ports:
            ports_str = ", ".join(str(p["port"]) for p in open_ports[:10])
            success(f"Open ports: {ports_str}")
        else:
            warn("No open ports found in scanned range")

    def _grab_banner(self, sock, port: int) -> str:
        try:
            if port in (80, 8080, 8000):
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                return sock.recv(256).decode(errors="ignore").split("\r\n")[0][:100]
            sock.send(b"\r\n")
            return sock.recv(128).decode(errors="ignore").strip()[:100]
        except Exception:
            return ""

    def _guess_service(self, port: int) -> str:
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            465: "SMTPS", 587: "Submission", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            9200: "Elasticsearch", 27017: "MongoDB",
        }
        return services.get(port, "unknown")

    def _parse_ports(self, ports_cfg: str) -> list:
        if not ports_cfg:
            return TOP_PORTS
        ports = set()
        for part in str(ports_cfg).split(","):
            part = part.strip()
            if "-" in part:
                try:
                    lo, hi = part.split("-", 1)
                    ports.update(range(int(lo), int(hi) + 1))
                except Exception:
                    pass
            elif part.isdigit():
                ports.add(int(part))
        return sorted(ports) if ports else TOP_PORTS

    # ── HTTP Header Analysis ──────────────────────────────────────────────────
    def _header_analysis(self) -> None:
        info("Analyzing HTTP headers...")
        resp, err = safe_get(self.session, self.target["url"])
        if err or not resp:
            warn(f"Header fetch failed: {err}")
            return
        headers = dict(resp.headers)
        self.results["headers"] = headers
        self.results["status_code"] = resp.status_code
        self.results["final_url"]   = resp.url
        success(f"HTTP {resp.status_code} — {len(headers)} headers captured")

    # ── Technology Fingerprinting ─────────────────────────────────────────────
    def _tech_fingerprint(self) -> None:
        info("Fingerprinting technologies...")
        techs = set()
        url = self.target["url"]

        resp, _ = safe_get(self.session, url)
        if not resp:
            return

        body    = resp.text.lower()
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

        for tech, patterns in TECH_SIGNATURES.items():
            for pat in patterns:
                if pat.lower() in body or pat.lower() in str(headers):
                    techs.add(tech)
                    break

        # X-Powered-By header direct
        xpb = resp.headers.get("X-Powered-By", "")
        if xpb:
            techs.add(f"Powered-By: {xpb}")

        # Server header
        srv = resp.headers.get("Server", "")
        if srv:
            techs.add(f"Server: {srv}")

        self.results["technologies"] = sorted(techs)
        if techs:
            success(f"Technologies detected: {', '.join(list(techs)[:6])}")

    # ── WAF Detection ─────────────────────────────────────────────────────────
    def _waf_detect(self) -> None:
        info("Detecting WAF/CDN...")
        resp, _ = safe_get(self.session, self.target["url"])
        if not resp:
            return

        waf_signatures = {
            "Cloudflare":   ["cf-ray", "cloudflare"],
            "Sucuri":       ["x-sucuri-id", "sucuri"],
            "Incapsula":    ["x-cdn", "incapsula"],
            "AWS WAF":      ["x-amzn-requestid", "awswaf"],
            "Akamai":       ["akamai-origin-hop", "akamaighost"],
            "Barracuda":    ["barra_counter_session"],
            "ModSecurity":  ["mod_security", "modsecurity"],
        }

        headers_str = str(resp.headers).lower()
        body_str    = resp.text[:2000].lower()

        for waf, sigs in waf_signatures.items():
            for sig in sigs:
                if sig in headers_str or sig in body_str:
                    self.results["waf"] = waf
                    success(f"WAF/CDN detected: {waf}")
                    return

        self.results["waf"] = "None detected"

    # ── GeoIP Lookup ──────────────────────────────────────────────────────────
    def _geo_lookup(self, host: str) -> None:
        try:
            ip = socket.gethostbyname(host)
            resp, _ = safe_get(self.session, f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as")
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    self.results["geo"] = data
                    success(f"GeoIP: {data.get('city','?')}, {data.get('country','?')} — {data.get('isp','?')}")
        except Exception:
            pass
