from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import RichLog, Static

from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import Severity
from sentinel.domain.findings import Finding
from sentinel.tui.widgets.key_bar import KeyBar
from sentinel.tui.widgets.summary_bar import SummaryBar

_SEV_BADGE: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("[bold red]⬛ CRITICAL[/bold red]", "bold red"),
    Severity.HIGH: ("[red]● HIGH[/red]", "red"),
    Severity.MEDIUM: ("[dark_orange]◆ MEDIUM[/dark_orange]", "dark_orange"),
    Severity.LOW: ("[yellow]▲ LOW[/yellow]", "yellow"),
}


class OverviewScreen(Screen[None]):
    TITLE = "Overview"

    DEFAULT_CSS = """
    OverviewScreen {
        layout: vertical;
    }
    #summary {
        height: 7;
    }
    #scan-status {
        height: 1;
        padding: 0 2;
        background: $panel;
        color: $text-muted;
    }
    #attention-header {
        padding: 0 2;
        margin-top: 1;
        color: $text-muted;
        text-style: bold;
    }
    #attention-area {
        height: 1fr;
        padding: 0 2;
        min-height: 3;
    }
    #activity-header {
        padding: 0 2;
        color: $text-muted;
        text-style: bold;
    }
    #activity-log {
        height: 10;
        border-top: solid $primary;
        background: $panel;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._last_result: ScanResult | None = None

    def compose(self) -> ComposeResult:
        yield SummaryBar(id="summary")
        yield Static("[dim]Waiting for first scan...[/dim]", id="scan-status")
        yield Static(
            "── NEEDS ATTENTION ──────────────────────────────────────", id="attention-header"
        )
        yield VerticalScroll(
            Static("[dim]Scanning...[/dim]", id="attention-content"),
            id="attention-area",
        )
        yield Static(
            "── LIVE ACTIVITY ────────────────────────────────────────", id="activity-header"
        )
        yield RichLog(id="activity-log", highlight=True, markup=True, max_lines=200)
        yield KeyBar(
            [
                ("1-4", "Tabs"),
                ("s", "Rescan"),
                ("p", "Pause"),
                ("?", "Help"),
                ("q", "Quit"),
            ]
        )

    def set_scanning(
        self,
        is_scanning: bool,
        result: ScanResult | None = None,
        duration: float = 0.0,
    ) -> None:
        status = self.query_one("#scan-status", Static)
        if is_scanning:
            status.update("[yellow]⏳ Scanning...[/yellow]")
            return
        ts = datetime.now(UTC).strftime("%H:%M:%S")
        if result is None:
            status.update("[dim]Ready[/dim]")
            return
        if result.findings:
            n = len(result.findings)
            status.update(
                f"[red]⚠  {n} finding{'s' if n > 1 else ''} need attention[/red]"
                f"  [dim]· scanned {ts}  ({duration:.1f}s)[/dim]"
            )
        else:
            status.update(
                f"[green]✓  All clear[/green]"
                f"  [dim]· {result.process_count} processes"
                f" · {result.listener_count} ports"
                f" · {result.connection_count} connections"
                f"  ({duration:.1f}s)[/dim]"
            )

    def update_result(self, result: ScanResult) -> None:
        self._last_result = result
        self.query_one(SummaryBar).update_stats(
            result.process_count,
            result.listener_count,
            result.connection_count,
            result.attention_count,
        )
        self._render_attention(result)

    def _render_attention(self, result: ScanResult) -> None:
        content = self.query_one("#attention-content", Static)
        if not result.findings:
            content.update(
                f"[green]✓  No issues detected[/green]  "
                f"[dim]— {result.process_count} processes"
                f" and {result.listener_count} ports look normal[/dim]"
            )
            return

        # Group by severity (worst first)
        by_sev: dict[Severity, list[Finding]] = {}
        for finding in result.findings:
            by_sev.setdefault(finding.severity, []).append(finding)

        lines: list[str] = []
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            if sev not in by_sev:
                continue
            badge, _ = _SEV_BADGE[sev]
            for finding in by_sev[sev]:
                lines.append(f"{badge}  [bold]{finding.title}[/bold]")
                lines.append(f"         [dim]subject:[/dim] {finding.subject}")
                for reason in finding.reasons[:2]:
                    lines.append(f"         [dim]›[/dim] {reason.description}")
                lines.append("")

        content.update("\n".join(lines).rstrip())

    def log_activity(self, message: str) -> None:
        self.query_one("#activity-log", RichLog).write(message)
