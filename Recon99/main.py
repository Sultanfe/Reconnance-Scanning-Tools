#!/usr/bin/env python3
"""
main.py
Recon99 — CLI entry point
Author: FMShomit
Usage: python main.py -t example.com --html
"""

import sys
import argparse
import datetime
import time

from utils.console import print_banner, section, info, success, warn, error, summary_table, console
from utils.validator import normalize_target, is_valid_target


def parse_args():
    parser = argparse.ArgumentParser(
        prog="recon99",
        description="Recon99 — Automated Reconnaissance & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -t example.com
  python main.py -t example.com --html --depth 3
  python main.py -t 192.168.1.1 --ports 1-1000 --threads 20
  python main.py -t example.com --html --ai-summary
  python main.py -t example.com --skip-vuln --skip-crawl   # recon only
        """,
    )

    parser.add_argument("-t", "--target", required=True,
                        help="Domain, subdomain, URL, or IP address")

    scan = parser.add_argument_group("Scan Options")
    scan.add_argument("--ports",      default="",    help="Ports: 80,443 or 1-1000 (default: top-100)")
    scan.add_argument("--threads",    type=int, default=10, help="Concurrent threads (default: 10)")
    scan.add_argument("--depth",      type=int, default=2,  help="Crawl depth (default: 2)")
    scan.add_argument("--timeout",    type=int, default=10, help="Request timeout in seconds (default: 10)")
    scan.add_argument("--rate-limit", type=float, default=0.1, help="Delay between requests in seconds (default: 0.1)")
    scan.add_argument("--user-agent", default="",    help="Custom User-Agent string")
    scan.add_argument("--wordlist",   default="",    help="Path to subdomain wordlist file")

    modules = parser.add_argument_group("Module Toggles")
    modules.add_argument("--skip-recon",   action="store_true", help="Skip reconnaissance phase")
    modules.add_argument("--skip-crawl",   action="store_true", help="Skip crawling phase")
    modules.add_argument("--skip-vuln",    action="store_true", help="Skip vulnerability scanning")
    modules.add_argument("--skip-nikto",   action="store_true", help="Skip Nikto scanner")
    modules.add_argument("--skip-nuclei",  action="store_true", help="Skip Nuclei scanner")

    output = parser.add_argument_group("Output Options")
    output.add_argument("--output-dir", default="./reports", help="Output directory (default: ./reports)")
    output.add_argument("--html",       action="store_true",  help="Generate HTML report")
    output.add_argument("--ai-summary", action="store_true",  help="Generate AI executive summary (needs ANTHROPIC_API_KEY)")
    output.add_argument("-q", "--quiet", action="store_true", help="Suppress banner and verbose output")
    output.add_argument("--no-color",   action="store_true",  help="Disable ANSI colors")

    return parser.parse_args()


def main():
    args = parse_args()

    if not args.quiet:
        print_banner()

    # ── Validate target ───────────────────────────────────────────────────────
    try:
        target_info = normalize_target(args.target)
    except ValueError as e:
        error(f"Invalid target: {e}")
        sys.exit(1)

    host = target_info["host"]
    info(f"Validating target: [target]{host}[/]")

    if not is_valid_target(host):
        error(f"Cannot resolve target: {host}. Check hostname / network.")
        sys.exit(1)

    success(f"Target resolved: {host}")

    # ── Build config dict ─────────────────────────────────────────────────────
    config = {
        "ports":        args.ports,
        "threads":      args.threads,
        "depth":        args.depth,
        "timeout":      args.timeout,
        "rate_limit":   args.rate_limit,
        "user_agent":   args.user_agent,
        "wordlist":     args.wordlist,
        "skip_nikto":   args.skip_nikto,
        "skip_nuclei":  args.skip_nuclei,
        "quiet":        args.quiet,
    }

    # ── Scan data structure ───────────────────────────────────────────────────
    start_dt  = datetime.datetime.now()
    scan_data = {
        "meta": {
            "target":     target_info,
            "start_time": start_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "end_time":   "",
            "duration":   "",
            "config":     {k: str(v) for k, v in config.items()},
        },
        "recon":  {},
        "crawl":  {},
        "vulns":  {},
        "ai_summary": "",
    }

    # ── Phase 1: Recon ────────────────────────────────────────────────────────
    if not args.skip_recon:
        try:
            from modules.recon import ReconModule
            recon = ReconModule(target_info, config)
            scan_data["recon"] = recon.run()
        except Exception as e:
            error(f"Recon phase failed: {e}")
            scan_data["recon"] = {}

    # ── Phase 2: Crawl ────────────────────────────────────────────────────────
    if not args.skip_crawl:
        try:
            from modules.crawler import CrawlerModule
            crawler = CrawlerModule(target_info, config)
            scan_data["crawl"] = crawler.run()
        except Exception as e:
            error(f"Crawl phase failed: {e}")
            scan_data["crawl"] = {}

    # ── Phase 3: Vuln scan ────────────────────────────────────────────────────
    if not args.skip_vuln:
        try:
            from modules.vuln_scanner import VulnScannerModule
            scanner = VulnScannerModule(target_info, scan_data.get("crawl", {}), config)
            scan_data["vulns"] = scanner.run()
        except Exception as e:
            error(f"Vuln scan phase failed: {e}")
            scan_data["vulns"] = {}

    # ── Finalize metadata ─────────────────────────────────────────────────────
    end_dt = datetime.datetime.now()
    duration = end_dt - start_dt
    scan_data["meta"]["end_time"] = end_dt.strftime("%Y-%m-%d %H:%M:%S")
    scan_data["meta"]["duration"] = str(duration).split(".")[0]

    # ── Summary ───────────────────────────────────────────────────────────────
    vulns = scan_data.get("vulns", {})
    counts = {sev: len(vulns.get(sev, [])) for sev in ["critical", "high", "medium", "low", "info"]}
    summary_table(counts, host, scan_data["meta"]["duration"])

    # ── Reports ───────────────────────────────────────────────────────────────
    section("Phase 4: Reporting")
    from modules.report_generator import ReportGenerator
    reporter = ReportGenerator(scan_data, output_dir=args.output_dir)

    # AI summary (optional)
    if args.ai_summary:
        reporter.generate_ai_summary()

    # Always save JSON
    json_path = reporter.save_json()

    # HTML (optional)
    html_path = None
    if args.html:
        html_path = reporter.save_html()

    # ── Done ──────────────────────────────────────────────────────────────────
    console.print()
    console.rule("[bold #00ff41] RECON99 COMPLETE [/]", style="#00ff41")
    info(f"JSON report  → [target]{json_path}[/]")
    if html_path:
        info(f"HTML report  → [target]{html_path}[/]")
    console.print()


if __name__ == "__main__":
    main()
