from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Static

HELP_TEXT = """\
[bold cyan]Sentinel — Keyboard Reference[/bold cyan]
[dim]Local security and privacy monitor for macOS[/dim]

─────────────────────────────────────────────────────────────────

  [bold yellow]Navigation[/bold yellow]

  [bold]1[/bold]                Switch to Overview tab
  [bold]2[/bold]                Switch to Apps tab
  [bold]3[/bold]                Switch to Network tab
  [bold]4[/bold]                Switch to Findings tab
  [bold]Tab / Shift-Tab[/bold]  Cycle through tabs
  [bold]↑ / ↓[/bold]            Move through a list
  [bold]Enter[/bold]            Inspect the selected row
  [bold]Esc[/bold]              Close this help / go back

─────────────────────────────────────────────────────────────────

  [bold yellow]Actions[/bold yellow]

  [bold]s[/bold]                Rescan now (refreshes all views)
  [bold]p[/bold]                Pause / resume live background monitoring
  [bold]?[/bold]                Open this help screen
  [bold]q[/bold]                Quit Sentinel

─────────────────────────────────────────────────────────────────

  [bold yellow]What each tab shows[/bold yellow]

  [bold cyan]1 · Overview[/bold cyan]
    • Summary bar — process, port, connection, and attention counts
    • Scan status line — last scan time and duration
    • Needs Attention — all flagged items grouped by severity
    • Live Activity — real-time stream of process and network events

  [bold cyan]2 · Apps[/bold cyan]
    • All running processes with open ports
    • [bold red]⬛[/bold red] / [red]●[/red] / [dark_orange]◆[/dark_orange] / [yellow]▲[/yellow]  flag = process has a security finding
    • [yellow]▲[/yellow] without a finding = executable path looks suspicious
    • Select a row with Enter to see command line, path, and finding details

  [bold cyan]3 · Network[/bold cyan]
    • Listening ports (servers waiting for connections)
    • Active connections (established outbound/inbound)
    • [bold red]⚠[/bold red]  = listening on 0.0.0.0 or :: (all interfaces) — HIGH risk
    • [yellow]◆[/yellow]  = listening on a local-network interface — moderate risk
    • (blank) = loopback only — safe

  [bold cyan]4 · Findings[/bold cyan]
    • All security findings sorted by severity (worst first)
    • Select a finding to see the full explanation in the detail panel
    • [green]✓ All clear[/green] = no issues detected

─────────────────────────────────────────────────────────────────

  [bold yellow]Severity levels[/bold yellow]

  [bold red]⬛ CRITICAL[/bold red]    Immediate action required
  [red]● HIGH[/red]          Strong indication of compromise or misconfiguration
  [dark_orange]◆ MEDIUM[/dark_orange]       Unusual — review recommended
  [yellow]▲ LOW[/yellow]           Minor concern — probably fine

─────────────────────────────────────────────────────────────────

  [bold yellow]CLI commands (run in a separate terminal)[/bold yellow]

  [dim]sentinel scan[/dim]                      One-shot quick scan
  [dim]sentinel scan deep[/dim]                 Deep scan: hash integrity + YARA
  [dim]sentinel scan --json[/dim]               Machine-readable JSON output
  [dim]sentinel ports[/dim]                     List listening ports
  [dim]sentinel processes[/dim]                 List all running processes
  [dim]sentinel network[/dim]                   List active connections
  [dim]sentinel baseline list[/dim]             Show baseline entries
  [dim]sentinel baseline add --process nginx --reason "web server"[/dim]
  [dim]sentinel baseline add --port 8080 --reason "dev server"[/dim]
  [dim]sentinel baseline remove <id>[/dim]      Remove a baseline entry
  [dim]sentinel serve[/dim]                     Start HTTP API on localhost:7173
  [dim]sentinel doctor[/dim]                    Check tool availability
  [dim]sentinel version[/dim]                   Show installed version

─────────────────────────────────────────────────────────────────
"""


class HelpScreen(Screen[None]):
    TITLE = "Help  ·  Press Esc or ? to close"

    BINDINGS = [("escape,q,h,question_mark", "dismiss", "Back")]

    DEFAULT_CSS = """
    HelpScreen {
        background: #080e18;
    }
    #help-scroll {
        padding: 0;
        background: #080e18;
    }
    #help-content {
        padding: 1 3;
        color: #a0c8e8;
        background: #080e18;
    }
    """

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="help-scroll"):
            yield Static(HELP_TEXT, id="help-content", markup=True)
        yield Footer()
