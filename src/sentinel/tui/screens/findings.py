from __future__ import annotations

import contextlib
from typing import Any

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, Static

from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import ExposureLevel, Severity
from sentinel.domain.findings import Finding
from sentinel.tui.widgets.key_bar import KeyBar

_EXPOSURE_SHORT: dict[ExposureLevel, str] = {
    ExposureLevel.LOOPBACK: "[green]localhost[/green]",
    ExposureLevel.LOCAL_NETWORK: "[yellow]local-net[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[bold red]all-interfaces ⚠[/bold red]",
}

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


class FindingsScreen(Widget):
    DEFAULT_CSS = """
    FindingsScreen {
        layout: vertical;
        height: 1fr;
        background: #080e18;
    }
    #findings-table {
        height: 1fr;
    }
    #finding-detail {
        height: 12;
        border-top: solid #00ff9f;
        padding: 1 2;
        background: #0d1521;
        color: #a0c8e8;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._findings: list[Finding] = []
        self._last_result: ScanResult | None = None

    def compose(self) -> ComposeResult:
        table: DataTable[str] = DataTable(id="findings-table", cursor_type="row")
        table.add_columns("Sev", "Title", "Subject", "Signals")
        yield table
        yield Static(
            "[dim]↑ ↓  move cursor  ·  arrow keys show finding details below[/dim]",
            id="finding-detail",
        )
        yield KeyBar(
            [
                ("↑↓", "Navigate"),
                ("Enter", "Detail"),
                ("s", "Rescan"),
                ("p", "Pause"),
                ("1-7", "Tabs"),
                ("?", "Help"),
                ("q", "Quit"),
            ]
        )

    def on_show(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#findings-table", DataTable).focus()

    def update_result(self, result: ScanResult) -> None:
        self._findings = result.findings
        self._last_result = result
        table = self.query_one("#findings-table", DataTable)
        table.clear()

        if not result.findings:
            # Show each checked port as a passing row
            has_any = False
            for cp in result.correlated:
                for sock in cp.listeners:
                    has_any = True
                    exposure = _EXPOSURE_SHORT.get(sock.exposure, str(sock.exposure))
                    table.add_row(
                        "[green]✓[/green]",
                        f":{sock.local_endpoint.port}  {sock.local_endpoint.protocol.upper()}",
                        cp.name,
                        exposure,
                        key=f"ok-{cp.pid}-{sock.local_endpoint.port}",
                    )
            if not has_any:
                table.add_row(
                    "[green]✓[/green]",
                    "[green]All clear — no open ports or findings[/green]",
                    "",
                    "",
                    key="none",
                )
            with contextlib.suppress(Exception):
                self.query_one("#finding-detail", Static).update(_build_all_clear_detail(result))
            return

        for finding in result.findings:
            color = _SEV_COLOR.get(finding.severity, "white")
            icon = _SEV_ICON.get(finding.severity, "!")
            sev_markup = f"[{color}]{icon}[/{color}]"
            signals = ", ".join(r.signal for r in finding.reasons)
            table.add_row(sev_markup, finding.title, finding.subject, signals, key=finding.id)

    def _render_detail(self, row_key_value: str | None) -> None:
        if not row_key_value or row_key_value == "none":
            return
        finding = next((f for f in self._findings if f.id == row_key_value), None)
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
        with contextlib.suppress(Exception):
            self.query_one("#finding-detail", Static).update("\n".join(lines))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key:
            key = event.row_key.value or ""
            if key.startswith("ok-") or key == "none":
                # Show scan summary for clean rows
                if self._last_result:
                    with contextlib.suppress(Exception):
                        self.query_one("#finding-detail", Static).update(
                            _build_all_clear_detail(self._last_result)
                        )
            else:
                self._render_detail(key)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._render_detail(event.row_key.value)


def _build_all_clear_detail(result: ScanResult) -> str:
    lines = [
        "[green]✓  All clear — no security issues found[/green]",
        "",
        f"[dim]Scanned  {result.process_count} processes"
        f"  ·  {result.listener_count} ports"
        f"  ·  {result.connection_count} connections[/dim]",
        "",
        "[dim]Signals checked:[/dim]",
        "  [dim]·[/dim] all-interface listeners (0.0.0.0 / ::)",
        "  [dim]·[/dim] suspicious executable paths (/tmp, /Downloads, /var/tmp)",
        "  [dim]·[/dim] missing executables (process running, binary deleted)",
        "  [dim]·[/dim] known tracker / advertising connections",
        "",
        "[dim]Navigate rows above to see each checked port.[/dim]",
    ]
    return "\n".join(lines)
