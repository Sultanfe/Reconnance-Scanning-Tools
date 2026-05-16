"""
utils/console.py
Recon99 — Terminal output helpers (banner, spinners, status printing)
Author: FMShomit
"""

import sys
import time
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.theme import Theme
from colorama import init

init(autoreset=True)

# ── Custom theme ──────────────────────────────────────────────────────────────
THEME = Theme({
    "critical": "bold red",
    "high":     "bold #ff6600",
    "medium":   "bold yellow",
    "low":      "bold cyan",
    "info":     "bold blue",
    "success":  "bold green",
    "muted":    "dim white",
    "target":   "bold #00ff41",   # matrix green
    "header":   "bold #00bfff",   # deep sky blue
})

console = Console(theme=THEME)


BANNER = r"""
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗     █████╗  █████╗ 
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔══██╗
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ╚██████║╚██████║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║     ╚═══██║ ╚═══██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║     █████╔╝ █████╔╝
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚════╝  ╚════╝ 
"""


def print_banner() -> None:
    """Print the Recon99 ASCII banner."""
    console.print(f"[bold #00ff41]{BANNER}[/]")
    console.print(
        Panel(
            "[bold #00bfff]Automated Reconnaissance & Vulnerability Scanner[/]\n"
            "[dim]Author: FMShomit  |  Version: 1.0.0  |  Use Responsibly[/]\n"
            "[bold red]⚠  Scan ONLY authorized targets. Unauthorized scanning is illegal.[/]",
            border_style="#00ff41",
            expand=False,
        )
    )
    console.print()


def section(title: str) -> None:
    """Print a section header."""
    console.rule(f"[header] {title} [/]", style="#00bfff")


def info(msg: str) -> None:
    console.print(f"[bold #00bfff][[*]][/] {msg}")


def success(msg: str) -> None:
    console.print(f"[success][[+]][/] {msg}")


def warn(msg: str) -> None:
    console.print(f"[medium][[!]][/] {msg}")


def error(msg: str) -> None:
    console.print(f"[critical][[-]][/] {msg}")


def finding(severity: str, title: str, url: str = "") -> None:
    """Print a single finding line."""
    color_map = {
        "critical": "critical",
        "high":     "high",
        "medium":   "medium",
        "low":      "low",
        "info":     "info",
    }
    sev = severity.lower()
    color = color_map.get(sev, "info")
    badge = f"[{color}][{sev.upper():8}][/]"
    url_part = f" [muted]→ {url}[/]" if url else ""
    console.print(f"  {badge} {title}{url_part}")


def summary_table(counts: dict, target: str, duration: str) -> None:
    """Print a final summary table."""
    table = Table(
        title=f"[bold #00ff41]── SCAN SUMMARY ──[/]",
        box=box.DOUBLE_EDGE,
        border_style="#00bfff",
        show_lines=True,
        expand=False,
    )
    table.add_column("Metric", style="bold white", justify="right")
    table.add_column("Value",  style="bold #00ff41", justify="left")

    table.add_row("Target",    f"[target]{target}[/]")
    table.add_row("Duration",  duration)
    table.add_row("[critical]Critical[/]", str(counts.get("critical", 0)))
    table.add_row("[high]High[/]",         str(counts.get("high", 0)))
    table.add_row("[medium]Medium[/]",     str(counts.get("medium", 0)))
    table.add_row("[low]Low[/]",           str(counts.get("low", 0)))
    table.add_row("[info]Info[/]",         str(counts.get("info", 0)))
    total = sum(counts.values())
    table.add_row("Total Findings", str(total))

    console.print()
    console.print(table)
    console.print()


def get_progress() -> Progress:
    """Return a Rich Progress object for phase tracking."""
    return Progress(
        SpinnerColumn(spinner_name="dots", style="#00ff41"),
        TextColumn("[bold #00bfff]{task.description}"),
        BarColumn(bar_width=30, style="#00ff41", complete_style="#00ff41"),
        TaskProgressColumn(),
        console=console,
        transient=False,
    )
