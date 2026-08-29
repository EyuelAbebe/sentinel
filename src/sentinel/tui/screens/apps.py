from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, Static

from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import Severity
from sentinel.domain.findings import Finding
from sentinel.tui.widgets.key_bar import KeyBar

_SEV_FLAG: dict[Severity, str] = {
    Severity.CRITICAL: "[bold red]⬛[/bold red]",
    Severity.HIGH: "[red]●[/red]",
    Severity.MEDIUM: "[dark_orange]◆[/dark_orange]",
    Severity.LOW: "[yellow]▲[/yellow]",
}

_SEV_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "dark_orange",
    Severity.LOW: "yellow",
}

_SEV_ORDER: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

_SUSPICIOUS_PATH_FRAGMENTS = ("/tmp/", "/var/tmp/", "/Downloads/", "/Temp/")


class AppsScreen(Widget):
    DEFAULT_CSS = """
    AppsScreen {
        layout: vertical;
        height: 1fr;
        background: #080e18;
    }
    #detail-panel {
        height: 10;
        border-top: solid #00ff9f;
        padding: 1 2;
        background: #0d1521;
        color: #a0c8e8;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._correlated: list[CorrelatedProcess] = []
        self._findings: list[Finding] = []

    def compose(self) -> ComposeResult:
        table: DataTable[str] = DataTable(id="process-table", cursor_type="row")
        table.add_columns("!", "PID", "Name", "User", "Ports", "Path")
        yield table
        yield Static(
            "[dim]Select a process to inspect it — finding details, path, ports, and command line[/dim]",
            id="detail-panel",
        )
        yield KeyBar(
            [
                ("↑↓", "Navigate"),
                ("Enter", "Inspect"),
                ("s", "Rescan"),
                ("p", "Pause"),
                ("1-4", "Tabs"),
                ("?", "Help"),
                ("q", "Quit"),
            ]
        )

    def update_result(self, result: ScanResult) -> None:
        self._correlated = result.correlated
        self._findings = result.findings

        # Map process name → worst finding
        flagged: dict[str, Finding] = {}
        for f in result.findings:
            existing = flagged.get(f.subject)
            if existing is None or _SEV_ORDER.get(f.severity, 0) > _SEV_ORDER.get(
                existing.severity, 0
            ):
                flagged[f.subject] = f

        table = self.query_one("#process-table", DataTable)
        table.clear()
        for cp in result.correlated:
            if cp.pid == 0:
                continue
            identity = cp.observation.identity
            ports = ", ".join(f":{sock.local_endpoint.port}" for sock in cp.listeners)

            finding = flagged.get(identity.name)
            if finding:
                flag = _SEV_FLAG.get(finding.severity, "[yellow]![/yellow]")
            elif any(p in (identity.executable_path or "") for p in _SUSPICIOUS_PATH_FRAGMENTS):
                flag = "[yellow]▲[/yellow]"
            else:
                flag = ""

            table.add_row(
                flag,
                str(identity.pid),
                identity.name,
                identity.user or "",
                ports,
                identity.executable_path or "",
                key=identity.instance_id,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key = event.row_key.value
        if not row_key:
            return
        cp = next((c for c in self._correlated if c.instance_id == row_key), None)
        if not cp:
            return
        identity = cp.observation.identity

        # Find associated findings (by process name)
        proc_findings = [f for f in self._findings if f.subject == identity.name]

        lines: list[str] = [
            f"[bold]{identity.name}[/bold]  [dim]PID {identity.pid}[/dim]",
            "",
        ]

        if proc_findings:
            for finding in proc_findings:
                color = _SEV_COLOR.get(finding.severity, "red")
                flag = _SEV_FLAG.get(finding.severity, "!")
                lines.append(f"  {flag} [{color}]{finding.title}[/{color}]")
                for r in finding.reasons[:2]:
                    lines.append(f"    [dim]› {r.description}[/dim]")
            lines.append("")

        lines += [
            f"  [dim]Path[/dim]    {identity.executable_path or '(unknown)'}",
            f"  [dim]User[/dim]    {identity.user or '(unknown)'}",
            f"  [dim]PPID[/dim]    {identity.parent_pid or '—'}",
        ]
        if cp.listeners:
            ports = ", ".join(f":{sock.local_endpoint.port}" for sock in cp.listeners)
            lines.append(f"  [dim]Ports[/dim]   {ports}")
        if identity.command_line:
            cmd = " ".join(identity.command_line)[:120]
            lines.append(f"  [dim]Cmd[/dim]     {cmd}")

        self.query_one("#detail-panel", Static).update("\n".join(lines))
