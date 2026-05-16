"""
modules/report_generator.py
Recon99 — Report generator
Outputs: JSON report (always) + HTML hacker-theme report (optional) + AI summary (optional)
Author: FMShomit
"""

import json
import os
import re
import datetime
from pathlib import Path
from typing import Optional

from utils.console import info, success, warn, section


# ── HTML Template (cyberpunk hacker theme) ────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon99 Report — {target}</title>
<style>
  :root {{
    --bg:       #0a0e14;
    --bg2:      #0d1117;
    --bg3:      #161b22;
    --border:   #21262d;
    --green:    #00ff41;
    --cyan:     #00bfff;
    --red:      #ff4444;
    --orange:   #ff6600;
    --yellow:   #ffd700;
    --blue:     #4fa8ff;
    --purple:   #c084fc;
    --text:     #c9d1d9;
    --muted:    #6e7681;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: 'Courier New', Courier, monospace;
    font-size: 14px; line-height: 1.6;
  }}
  /* Scanline overlay */
  body::before {{
    content: '';
    position: fixed; top:0; left:0; right:0; bottom:0;
    background: repeating-linear-gradient(0deg,
      transparent, transparent 2px,
      rgba(0,255,65,0.01) 2px, rgba(0,255,65,0.01) 4px);
    pointer-events: none; z-index: 999;
  }}

  /* ── Header ── */
  .header {{
    background: linear-gradient(135deg, #0a0e14 0%, #0d1a0f 100%);
    border-bottom: 2px solid var(--green);
    padding: 2rem;
    position: relative; overflow: hidden;
  }}
  .header::after {{
    content: 'RECON99';
    position: absolute; right: -10px; top: 50%; transform: translateY(-50%);
    font-size: 8rem; font-weight: 900; color: rgba(0,255,65,0.04);
    letter-spacing: -5px; user-select: none;
  }}
  .header h1 {{
    font-size: 2.2rem; color: var(--green);
    text-shadow: 0 0 20px rgba(0,255,65,0.5);
    letter-spacing: 4px;
  }}
  .header .subtitle {{
    color: var(--cyan); margin-top: .5rem; font-size: 0.9rem;
  }}
  .header .meta {{ color: var(--muted); font-size: 0.8rem; margin-top: .3rem; }}

  /* ── Layout ── */
  .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
  .grid-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; }}
  @media (max-width: 900px) {{
    .grid-2, .grid-3 {{ grid-template-columns: 1fr; }}
  }}

  /* ── Cards ── */
  .card {{
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 8px; overflow: hidden;
    transition: border-color 0.2s;
  }}
  .card:hover {{ border-color: var(--green); }}
  .card-header {{
    padding: .75rem 1rem; background: var(--bg3);
    border-bottom: 1px solid var(--border);
    color: var(--cyan); font-weight: bold; font-size: 0.85rem;
    letter-spacing: 2px; text-transform: uppercase;
    display: flex; align-items: center; gap: .5rem;
  }}
  .card-header .dot {{
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 8px var(--green);
    animation: pulse 2s infinite;
  }}
  .card-body {{ padding: 1rem; }}

  /* ── Stats Bar ── */
  .stats-bar {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 1rem; margin-bottom: 2rem;
  }}
  .stat-card {{
    background: var(--bg2); border-radius: 8px;
    padding: 1.2rem; text-align: center;
    border: 1px solid var(--border);
    transition: all .3s;
  }}
  .stat-card:hover {{ transform: translateY(-3px); }}
  .stat-card.crit  {{ border-top: 3px solid var(--red); }}
  .stat-card.high  {{ border-top: 3px solid var(--orange); }}
  .stat-card.med   {{ border-top: 3px solid var(--yellow); }}
  .stat-card.low   {{ border-top: 3px solid var(--blue); }}
  .stat-card.info  {{ border-top: 3px solid var(--purple); }}
  .stat-num {{
    font-size: 2.5rem; font-weight: 900;
    display: block; line-height: 1;
  }}
  .stat-card.crit .stat-num  {{ color: var(--red); text-shadow: 0 0 20px var(--red); }}
  .stat-card.high .stat-num  {{ color: var(--orange); text-shadow: 0 0 20px var(--orange); }}
  .stat-card.med  .stat-num  {{ color: var(--yellow); text-shadow: 0 0 15px var(--yellow); }}
  .stat-card.low  .stat-num  {{ color: var(--blue); }}
  .stat-card.info .stat-num  {{ color: var(--purple); }}
  .stat-label {{ color: var(--muted); font-size: .75rem; margin-top: .3rem; letter-spacing: 1px; }}

  /* ── Section title ── */
  .section-title {{
    color: var(--green); font-size: 1rem; font-weight: bold;
    letter-spacing: 3px; text-transform: uppercase;
    margin: 2rem 0 1rem;
    padding-left: .75rem;
    border-left: 3px solid var(--green);
  }}

  /* ── Badges ── */
  .badge {{
    display: inline-block; padding: .15rem .5rem;
    border-radius: 4px; font-size: .7rem; font-weight: bold;
    letter-spacing: 1px; text-transform: uppercase;
  }}
  .badge-critical {{ background:#ff444420; color:var(--red); border:1px solid var(--red); }}
  .badge-high     {{ background:#ff660020; color:var(--orange); border:1px solid var(--orange); }}
  .badge-medium   {{ background:#ffd70020; color:var(--yellow); border:1px solid var(--yellow); }}
  .badge-low      {{ background:#4fa8ff20; color:var(--blue); border:1px solid var(--blue); }}
  .badge-info     {{ background:#c084fc20; color:var(--purple); border:1px solid var(--purple); }}
  .badge-tech     {{ background:#00bfff15; color:var(--cyan); border:1px solid var(--cyan); margin:.15rem; }}
  .badge-port     {{ background:#00ff4115; color:var(--green); border:1px solid var(--green); margin:.15rem; }}

  /* ── Findings table ── */
  .findings-table {{ width:100%; border-collapse: collapse; font-size: .85rem; }}
  .findings-table th {{
    background: var(--bg3); color: var(--cyan); padding: .6rem 1rem;
    text-align: left; font-size: .75rem; letter-spacing: 1px;
    border-bottom: 1px solid var(--border);
  }}
  .findings-table td {{
    padding: .6rem 1rem; border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  .findings-table tr:hover td {{ background: rgba(0,255,65,0.03); }}
  .finding-title {{ color: var(--text); font-weight: bold; }}
  .finding-desc {{ color: var(--muted); font-size:.8rem; margin-top:.2rem; }}
  .finding-evidence {{
    font-family: monospace; background: var(--bg3);
    border: 1px solid var(--border); border-radius: 4px;
    padding: .2rem .4rem; font-size: .75rem; color: var(--green);
    display: inline-block; margin-top: .2rem; max-width: 400px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }}
  .finding-remedy {{ color: #68d391; font-size: .8rem; margin-top: .3rem; }}

  /* ── Info list ── */
  .info-list {{ list-style: none; }}
  .info-list li {{
    padding: .4rem 0; border-bottom: 1px solid var(--border);
    color: var(--text); font-size: .85rem;
    display: flex; align-items: flex-start; gap: .5rem;
  }}
  .info-list li::before {{ content: '›'; color: var(--green); flex-shrink: 0; }}
  .info-list li:last-child {{ border: none; }}

  /* ── Code blocks ── */
  .code-block {{
    background: var(--bg3); border: 1px solid var(--border);
    border-radius: 6px; padding: 1rem;
    font-family: 'Courier New', monospace; font-size: .8rem;
    color: var(--green); overflow-x: auto; white-space: pre-wrap;
  }}

  /* ── AI Summary ── */
  .ai-summary {{
    background: linear-gradient(135deg, #0d1a0f 0%, #0a0e14 100%);
    border: 1px solid var(--green); border-radius: 8px;
    padding: 1.5rem; margin: 2rem 0;
    box-shadow: 0 0 30px rgba(0,255,65,0.1);
  }}
  .ai-summary h3 {{ color: var(--green); margin-bottom: 1rem; letter-spacing: 2px; }}
  .ai-summary p {{ color: var(--text); line-height: 1.8; }}

  /* ── Target card ── */
  .target-field {{
    display: flex; justify-content: space-between;
    padding: .4rem 0; border-bottom: 1px solid var(--border);
    font-size: .85rem;
  }}
  .target-field:last-child {{ border: none; }}
  .target-field .key   {{ color: var(--muted); }}
  .target-field .value {{ color: var(--cyan); font-weight: bold; }}

  /* ── Footer ── */
  footer {{
    text-align: center; padding: 2rem;
    color: var(--muted); font-size: .75rem;
    border-top: 1px solid var(--border); margin-top: 3rem;
  }}
  footer span {{ color: var(--green); }}

  /* ── Animations ── */
  @keyframes pulse {{
    0%, 100% {{ opacity:1; }}
    50%       {{ opacity:0.3; }}
  }}
  @keyframes glow {{
    0%, 100% {{ text-shadow: 0 0 10px var(--green); }}
    50%       {{ text-shadow: 0 0 30px var(--green), 0 0 60px var(--green); }}
  }}

  /* ── Collapsible ── */
  details summary {{
    cursor: pointer; color: var(--cyan);
    padding: .5rem 0; list-style: none;
  }}
  details summary::-webkit-details-marker {{ display: none; }}
  details summary::before {{ content: '▶ '; color: var(--green); }}
  details[open] summary::before {{ content: '▼ '; }}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="container">
    <h1>⚡ RECON99</h1>
    <div class="subtitle">Automated Reconnaissance &amp; Vulnerability Scanner</div>
    <div class="meta">
      Target: <span style="color:var(--green)">{target}</span> &nbsp;|&nbsp;
      Scan started: {start_time} &nbsp;|&nbsp;
      Duration: {duration} &nbsp;|&nbsp;
      Author: FMShomit
    </div>
  </div>
</div>

<div class="container">

  <!-- Stats Bar -->
  <div style="margin-top:2rem">
    <div class="stats-bar">
      <div class="stat-card crit">
        <span class="stat-num">{count_critical}</span>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card high">
        <span class="stat-num">{count_high}</span>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card med">
        <span class="stat-num">{count_medium}</span>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card low">
        <span class="stat-num">{count_low}</span>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-card info">
        <span class="stat-num">{count_info}</span>
        <div class="stat-label">Info</div>
      </div>
    </div>
  </div>

  <!-- AI Summary -->
  {ai_summary_block}

  <!-- Target & Recon -->
  <div class="section-title">◈ Target Information</div>
  <div class="grid-2">
    <div class="card">
      <div class="card-header"><span class="dot"></span> Target Details</div>
      <div class="card-body">
        {target_info_rows}
      </div>
    </div>
    <div class="card">
      <div class="card-header"><span class="dot"></span> Technologies Detected</div>
      <div class="card-body">
        {tech_badges}
      </div>
    </div>
  </div>

  <!-- DNS & Ports -->
  <div class="section-title">◈ Reconnaissance Findings</div>
  <div class="grid-2">
    <div class="card">
      <div class="card-header"><span class="dot"></span> DNS Records</div>
      <div class="card-body">
        {dns_block}
      </div>
    </div>
    <div class="card">
      <div class="card-header"><span class="dot"></span> Open Ports</div>
      <div class="card-body">
        {ports_block}
      </div>
    </div>
  </div>

  <!-- Subdomains -->
  {subdomains_block}

  <!-- Crawl Results -->
  <div class="section-title">◈ Crawl Results</div>
  <div class="grid-3">
    <div class="card">
      <div class="card-header"><span class="dot"></span> URLs Collected</div>
      <div class="card-body">
        <details>
          <summary>{url_count} URLs found</summary>
          <ul class="info-list" style="margin-top:.5rem">{url_list}</ul>
        </details>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><span class="dot"></span> JavaScript Files</div>
      <div class="card-body">
        <details>
          <summary>{js_count} JS files</summary>
          <ul class="info-list" style="margin-top:.5rem">{js_list}</ul>
        </details>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><span class="dot"></span> Parameters &amp; Forms</div>
      <div class="card-body">
        <p style="color:var(--muted);font-size:.8rem">Parameters: <span style="color:var(--cyan)">{param_count}</span></p>
        <p style="color:var(--muted);font-size:.8rem;margin-top:.3rem">Forms: <span style="color:var(--cyan)">{form_count}</span></p>
        {params_list}
      </div>
    </div>
  </div>

  <!-- Interesting Paths -->
  {interesting_block}

  <!-- Secrets -->
  {secrets_block}

  <!-- Findings -->
  <div class="section-title">◈ Vulnerability Findings</div>
  {findings_html}

  <!-- WHOIS -->
  {whois_block}

</div>

<footer>
  Generated by <span>Recon99 v1.0.0</span> · Author: <span>FMShomit</span> ·
  {timestamp} · Use only on authorized targets.
</footer>

<script>
  // Sortable table
  document.querySelectorAll('th[data-sort]').forEach(th => {{
    th.style.cursor = 'pointer';
    th.addEventListener('click', () => {{
      const table = th.closest('table');
      const idx = Array.from(th.parentElement.children).indexOf(th);
      const rows = Array.from(table.querySelectorAll('tbody tr'));
      const asc = th.dataset.asc !== 'true';
      th.dataset.asc = asc;
      rows.sort((a, b) => {{
        const av = a.cells[idx]?.textContent.trim() || '';
        const bv = b.cells[idx]?.textContent.trim() || '';
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      }});
      rows.forEach(r => table.querySelector('tbody').appendChild(r));
    }});
  }});
</script>
</body>
</html>
"""


class ReportGenerator:
    """Generates JSON and HTML reports from scan results."""

    def __init__(self, scan_data: dict, output_dir: str = "./reports"):
        self.data = scan_data
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        host = scan_data["meta"]["target"]["host"]
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_name = f"recon99_{re.sub(r'[^a-zA-Z0-9_]', '_', host)}_{ts}"

    # ── JSON Report ───────────────────────────────────────────────────────────
    def save_json(self) -> str:
        path = self.output_dir / f"{self.base_name}.json"
        with open(path, "w") as f:
            json.dump(self.data, f, indent=2, default=str)
        success(f"JSON report saved: {path}")
        return str(path)

    # ── HTML Report ───────────────────────────────────────────────────────────
    def save_html(self) -> str:
        path = self.output_dir / f"{self.base_name}.html"
        html = self._build_html()
        with open(path, "w") as f:
            f.write(html)
        success(f"HTML report saved: {path}")
        return str(path)

    # ── AI Summary (Claude API) ───────────────────────────────────────────────
    def generate_ai_summary(self) -> str:
        """Call Claude API for an executive summary."""
        try:
            import anthropic
        except ImportError:
            warn("anthropic package not installed. pip install anthropic")
            return ""

        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            warn("ANTHROPIC_API_KEY not set; skipping AI summary.")
            return ""

        info("Generating AI executive summary...")
        vulns = self.data.get("vulns", {})
        total_findings = sum(len(v) for v in vulns.values())
        top_findings   = []
        for sev in ["critical", "high", "medium"]:
            for f in vulns.get(sev, [])[:3]:
                top_findings.append(f"  [{sev.upper()}] {f['title']}: {f['description'][:100]}")

        prompt = f"""You are a senior penetration tester. Write a concise executive summary 
(3-4 paragraphs) for the following security assessment:

Target: {self.data['meta']['target']['host']}
Scan Duration: {self.data['meta'].get('duration', 'N/A')}
Total Findings: {total_findings}
Critical: {len(vulns.get('critical', []))}
High: {len(vulns.get('high', []))}
Medium: {len(vulns.get('medium', []))}
Low: {len(vulns.get('low', []))}
Technologies: {', '.join(self.data.get('recon', {}).get('technologies', [])[:8])}
Open Ports: {', '.join(str(p['port']) for p in self.data.get('recon', {}).get('open_ports', [])[:10])}

Top Findings:
{chr(10).join(top_findings)}

Include: overall risk rating, key concerns, and top 3 recommended remediation actions.
Keep it professional and concise."""

        try:
            client = anthropic.Anthropic(api_key=api_key)
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}],
            )
            summary = response.content[0].text
            self.data["ai_summary"] = summary
            success("AI executive summary generated")
            return summary
        except Exception as e:
            warn(f"AI summary error: {e}")
            return ""

    # ── HTML builder ──────────────────────────────────────────────────────────
    def _build_html(self) -> str:
        meta   = self.data.get("meta", {})
        recon  = self.data.get("recon", {})
        crawl  = self.data.get("crawl", {})
        vulns  = self.data.get("vulns", {})
        target = meta.get("target", {})

        # Stats
        counts = {sev: len(vulns.get(sev, [])) for sev in ["critical", "high", "medium", "low", "info"]}

        # AI summary block
        ai_text = self.data.get("ai_summary", "")
        ai_block = ""
        if ai_text:
            ai_block = f"""
<div class="ai-summary">
  <h3>🤖 AI EXECUTIVE SUMMARY</h3>
  <p>{ai_text.replace(chr(10), '<br>')}</p>
</div>"""

        # Target info rows
        target_rows = ""
        fields = [
            ("Host",      target.get("host", "")),
            ("URL",       target.get("url", "")),
            ("Status",    str(recon.get("status_code", ""))),
            ("Final URL", recon.get("final_url", "")),
            ("WAF/CDN",   recon.get("waf", "N/A")),
        ]
        geo = recon.get("geo", {})
        if geo:
            fields.append(("Location", f"{geo.get('city','')}, {geo.get('country','')}"))
            fields.append(("ISP",      geo.get("isp", "")))
        for k, v in fields:
            if v:
                target_rows += f'<div class="target-field"><span class="key">{k}</span><span class="value">{self._esc(str(v)[:80])}</span></div>'

        # Technology badges
        techs = recon.get("technologies", [])
        tech_html = "".join(f'<span class="badge badge-tech">{self._esc(t)}</span>' for t in techs) or "<span style='color:var(--muted)'>None detected</span>"

        # DNS block
        dns_html = ""
        for rtype, vals in recon.get("dns", {}).items():
            if vals:
                dns_html += f"<div style='margin-bottom:.5rem'><span style='color:var(--cyan)'>{rtype}</span><ul class='info-list'>"
                for v in vals[:5]:
                    dns_html += f"<li>{self._esc(v)}</li>"
                dns_html += "</ul></div>"

        # Ports block
        ports_html = ""
        for p in recon.get("open_ports", []):
            ports_html += f'<span class="badge badge-port">{p["port"]}/{p["service"]}</span>'
        if not ports_html:
            ports_html = "<span style='color:var(--muted)'>None found</span>"

        # Subdomains
        subdomains = recon.get("subdomains", [])
        sub_block = ""
        if subdomains:
            sub_items = "".join(f"<li>{self._esc(s)}</li>" for s in subdomains[:50])
            sub_block = f"""
<div class="section-title" style="margin-top:1.5rem">◈ Subdomains ({len(subdomains)})</div>
<div class="card">
  <div class="card-header"><span class="dot"></span> Discovered Subdomains</div>
  <div class="card-body">
    <details><summary>{len(subdomains)} subdomains</summary>
    <ul class="info-list" style="margin-top:.5rem;columns:2">{sub_items}</ul>
    </details>
  </div>
</div>"""

        # Crawl
        urls    = crawl.get("urls", [])
        js      = crawl.get("js_files", [])
        params  = crawl.get("parameters", [])
        forms   = crawl.get("forms", [])
        url_list = "".join(f"<li>{self._esc(u[:80])}</li>" for u in urls[:50])
        js_list  = "".join(f"<li>{self._esc(j[:80])}</li>" for j in js[:30])
        params_html = "".join(f'<span class="badge badge-tech" style="margin:.1rem">{self._esc(p)}</span>' for p in params[:30]) if params else ""

        # Interesting paths
        interesting = crawl.get("interesting_paths", [])
        int_block = ""
        if interesting:
            rows = "".join(
                f"<tr><td>{self._esc(i['path'])}</td>"
                f"<td><span class='badge badge-{'high' if i['status']==200 else 'medium'}'>{i['status']}</span></td>"
                f"<td style='color:var(--muted)'>{i['size']} bytes</td></tr>"
                for i in interesting
            )
            int_block = f"""
<div class="section-title">◈ Interesting Paths ({len(interesting)})</div>
<div class="card"><div class="card-header"><span class="dot"></span> Exposed Paths</div>
<div class="card-body">
<table class="findings-table">
<thead><tr><th>Path</th><th>Status</th><th>Size</th></tr></thead>
<tbody>{rows}</tbody></table></div></div>"""

        # Secrets
        secrets = crawl.get("secrets", [])
        sec_block = ""
        if secrets:
            rows = "".join(
                f"<tr><td style='color:var(--red)'>{self._esc(s['type'])}</td>"
                f"<td><code style='color:var(--green)'>{self._esc(s['value'][:40])}...</code></td>"
                f"<td style='color:var(--muted)'>{self._esc(s['source'][:60])}</td></tr>"
                for s in secrets
            )
            sec_block = f"""
<div class="section-title" style="color:var(--red)">⚠ Secrets &amp; Credentials Found ({len(secrets)})</div>
<div class="card" style="border-color:var(--red)"><div class="card-header" style="color:var(--red)"><span class="dot" style="background:var(--red)"></span> Sensitive Data Exposure</div>
<div class="card-body">
<table class="findings-table">
<thead><tr><th>Type</th><th>Value (truncated)</th><th>Source</th></tr></thead>
<tbody>{rows}</tbody></table></div></div>"""

        # Findings tables per severity
        findings_html = ""
        sev_order = ["critical", "high", "medium", "low", "info"]
        sev_colors = {"critical": "red", "high": "orange", "medium": "yellow", "low": "blue", "info": "purple"}
        for sev in sev_order:
            items = vulns.get(sev, [])
            if not items:
                continue
            color = sev_colors[sev]
            rows = ""
            for f in items:
                rows += f"""<tr>
  <td><div class="finding-title">{self._esc(f.get('title',''))}</div>
      <div class="finding-desc">{self._esc(f.get('description','')[:120])}</div>
      {'<div class="finding-evidence">' + self._esc(f.get('evidence','')[:80]) + '</div>' if f.get('evidence') else ''}
      {'<div class="finding-remedy">✓ ' + self._esc(f.get('remediation','')[:100]) + '</div>' if f.get('remediation') else ''}
  </td>
  <td><code style="color:var(--muted);font-size:.75rem">{self._esc(f.get('url','')[:50])}</code></td>
  <td><span class="badge badge-{f.get('tool','custom')}" style="background:rgba(0,191,255,.1);color:var(--cyan);border:1px solid var(--cyan)">{self._esc(f.get('tool','custom'))}</span></td>
  <td style="color:var(--muted);font-size:.75rem">{self._esc(f.get('cwe',''))}</td>
</tr>"""

            findings_html += f"""
<div style="margin-bottom:1.5rem">
<div class="card" style="border-top:3px solid var(--{color})">
<div class="card-header" style="color:var(--{color})">
  <span class="dot" style="background:var(--{color})"></span>
  {sev.upper()} — {len(items)} finding{'s' if len(items)!=1 else ''}
</div>
<div class="card-body" style="padding:0">
<table class="findings-table">
<thead><tr>
  <th data-sort style="width:55%">Finding</th>
  <th data-sort>URL</th>
  <th data-sort>Tool</th>
  <th data-sort>CWE</th>
</tr></thead>
<tbody>{rows}</tbody>
</table></div></div></div>"""

        # WHOIS
        whois_data = recon.get("whois", {})
        whois_block = ""
        if whois_data:
            rows_w = "".join(
                f'<div class="target-field"><span class="key">{k}</span><span class="value">{self._esc(str(v)[:80])}</span></div>'
                for k, v in whois_data.items() if v
            )
            whois_block = f"""
<div class="section-title">◈ WHOIS Information</div>
<div class="card"><div class="card-header"><span class="dot"></span> Domain Registration</div>
<div class="card-body">{rows_w}</div></div>"""

        return HTML_TEMPLATE.format(
            target=self._esc(target.get("host", "unknown")),
            start_time=meta.get("start_time", ""),
            duration=meta.get("duration", ""),
            count_critical=counts["critical"],
            count_high=counts["high"],
            count_medium=counts["medium"],
            count_low=counts["low"],
            count_info=counts["info"],
            ai_summary_block=ai_block,
            target_info_rows=target_rows,
            tech_badges=tech_html,
            dns_block=dns_html,
            ports_block=ports_html,
            subdomains_block=sub_block,
            url_count=len(urls),
            url_list=url_list,
            js_count=len(js),
            js_list=js_list,
            param_count=len(params),
            form_count=len(forms),
            params_list=params_html,
            interesting_block=int_block,
            secrets_block=sec_block,
            findings_html=findings_html,
            whois_block=whois_block,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

    @staticmethod
    def _esc(s: str) -> str:
        """Escape HTML entities."""
        return (s.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;").replace('"', "&quot;"))
