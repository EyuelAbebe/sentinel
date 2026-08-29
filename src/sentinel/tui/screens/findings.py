from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Static

from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import Severity
from sentinel.domain.findings import Finding
from sentinel.tui.widgets.key_bar import KeyBar

_SEV_COLOR: dict[Severity, str] = {
    Severity.LOW: "yellow",
    Severity.MEDIUM: "dark_orange",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}

_SEV_ICON: dict[Severity, str] = {
    Severity.LOW: "▲",
    Severity.MEDIUM: "◆",
    Severity.HIGH: "●",
    Severity.CRITICAL: "⬛",
}


class FindingsScreen(Screen[None]):
    TITLE = "Findings"

    DEFAULT_CSS = """
    FindingsScreen {
        layout: vertical;
    }
    #finding-detail {
        height: 12;
        border-top: solid $primary;
        padding: 1 2;
        background: $panel;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._findings: list[Finding] = []

    def compose(self) -> ComposeResult:
        table: DataTable[str] = DataTable(id="findings-table", cursor_type="row")
        table.add_columns("Sev", "Title", "Subject", "Signals")
        yield table
        yield Static(
            "[dim]Select a finding to see the full explanation, signals, and affected subject[/dim]",
            id="finding-detail",
        )
        yield KeyBar(
            [
                ("↑↓", "Navigate"),
                ("Enter", "Detail"),
                ("s", "Rescan"),
                ("p", "Pause"),
                ("1-4", "Tabs"),
                ("?", "Help"),
                ("q", "Quit"),
            ]
        )

    def update_result(self, result: ScanResult) -> None:
        self._findings = result.findings
        table = self.query_one("#findings-table", DataTable)
        table.clear()

        if not result.findings:
            table.add_row(
                "[green]✓[/green]",
                "[green]All clear — no findings[/green]",
                "",
                "",
                key="none",
            )
            self.query_one("#finding-detail", Static).update(
                f"[green]✓  No security issues detected.[/green]\n\n"
                f"[dim]{result.process_count} processes and {result.listener_count} open ports"
                f" are within normal parameters.[/dim]"
            )
            return

        for finding in result.findings:
            color = _SEV_COLOR.get(finding.severity, "white")
            icon = _SEV_ICON.get(finding.severity, "!")
            sev_markup = f"[{color}]{icon}[/{color}]"
            signals = ", ".join(r.signal for r in finding.reasons)
            table.add_row(sev_markup, finding.title, finding.subject, signals, key=finding.id)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key = event.row_key.value
        if not row_key or row_key == "none":
            return
        finding = next((f for f in self._findings if f.id == row_key), None)
        if not finding:
            return
        color = _SEV_COLOR.get(finding.severity, "white")
        icon = _SEV_ICON.get(finding.severity, "!")
        lines = [
            f"[{color}]{icon}[/{color}] [{color}]{finding.severity.upper()}[/{color}]"
            f"  [bold]{finding.title}[/bold]",
            f"[dim]Subject:[/dim] {finding.subject}",
            "",
            "[dim]Why this was flagged:[/dim]",
        ]
        for reason in finding.reasons:
            lines.append(f"  [bold]{reason.signal}[/bold]")
            lines.append(f"  [dim]{reason.description}[/dim]")
            lines.append("")
        self.query_one("#finding-detail", Static).update("\n".join(lines))
