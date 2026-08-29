from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, RichLog, Static

from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import Severity
from sentinel.tui.widgets.summary_bar import SummaryBar

_SEVERITY_ICON = {
    Severity.LOW: "[yellow]![/yellow]",
    Severity.MEDIUM: "[dark_orange]![/dark_orange]",
    Severity.HIGH: "[red]![/red]",
    Severity.CRITICAL: "[bold red]!![/bold red]",
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
    #attention-header {
        padding: 0 2;
        color: $text-muted;
        text-style: bold;
    }
    #attention-area {
        height: 1fr;
        padding: 0 2;
    }
    #activity-header {
        padding: 0 2;
        color: $text-muted;
        text-style: bold;
    }
    #activity-log {
        height: 12;
        border-top: solid $primary;
    }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._last_result: ScanResult | None = None

    def compose(self) -> ComposeResult:
        yield SummaryBar(id="summary")
        yield Static("NEEDS ATTENTION", id="attention-header")
        yield VerticalScroll(Static("", id="attention-content"), id="attention-area")
        yield Static("LIVE ACTIVITY", id="activity-header")
        yield RichLog(id="activity-log", highlight=True, markup=True)
        yield Footer()

    def update_result(self, result: ScanResult) -> None:
        self._last_result = result
        bar = self.query_one(SummaryBar)
        bar.update_stats(
            result.process_count,
            result.listener_count,
            result.connection_count,
            result.attention_count,
        )
        self._render_attention(result)

    def _render_attention(self, result: ScanResult) -> None:
        content = self.query_one("#attention-content", Static)
        if not result.findings:
            content.update("[dim]No issues found[/dim]")
            return

        lines: list[str] = []
        for finding in result.findings:
            icon = _SEVERITY_ICON.get(finding.severity, "!")
            lines.append(f"{icon} [bold]{finding.title}[/bold]  [{finding.severity.upper()}]")
            for reason in finding.reasons[:2]:
                lines.append(f"  [dim]{reason.description}[/dim]")
            lines.append("")

        content.update("\n".join(lines))

    def log_activity(self, message: str) -> None:
        log = self.query_one("#activity-log", RichLog)
        log.write(message)
