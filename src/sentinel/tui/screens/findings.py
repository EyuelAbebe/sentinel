from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Static
from textual.containers import VerticalScroll

from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import Severity
from sentinel.domain.findings import Finding

_SEV_COLOR = {
    Severity.LOW: "yellow",
    Severity.MEDIUM: "dark_orange",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
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
        color: $text-muted;
    }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._findings: list[Finding] = []

    def compose(self) -> ComposeResult:
        table = DataTable(id="findings-table", cursor_type="row")
        table.add_columns("Severity", "Title", "Signals")
        yield table
        yield Static("[dim]No finding selected[/dim]", id="finding-detail")
        yield Footer()

    def update_result(self, result: ScanResult) -> None:
        self._findings = result.findings
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        if not result.findings:
            table.add_row("—", "No findings", "", key="none")
            return
        for finding in result.findings:
            color = _SEV_COLOR.get(finding.severity, "white")
            sev_markup = f"[{color}]{finding.severity.upper()}[/{color}]"
            signals = ", ".join(r.signal for r in finding.reasons)
            table.add_row(sev_markup, finding.title, signals, key=finding.id)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key = event.row_key.value
        if not row_key or row_key == "none":
            return
        finding = next((f for f in self._findings if f.id == row_key), None)
        if not finding:
            return
        color = _SEV_COLOR.get(finding.severity, "white")
        lines = [
            f"[bold]{finding.title}[/bold]  [{color}]{finding.severity.upper()}[/{color}]",
            "",
        ]
        for reason in finding.reasons:
            lines.append(f"  [bold]{reason.signal}[/bold]")
            lines.append(f"  {reason.description}")
            lines.append("")
        self.query_one("#finding-detail", Static).update("\n".join(lines))
