from __future__ import annotations

import contextlib
from typing import Any

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, Static

from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import ExposureLevel, Severity
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

_EXPOSURE_SHORT: dict[ExposureLevel, str] = {
    ExposureLevel.LOOPBACK: "[green]loop[/green]",
    ExposureLevel.LOCAL_NETWORK: "[yellow]local[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[bold red]all ⚠[/bold red]",
}

_SUSPICIOUS_PATH_FRAGMENTS = ("/tmp/", "/var/tmp/", "/Downloads/", "/Temp/")


def _status_badge(
    cp: CorrelatedProcess, finding: Finding | None, suspicious_path: bool
) -> tuple[str, str]:
    """Return (flag markup, status markup) for a process row."""
    if finding:
        flag = _SEV_FLAG.get(finding.severity, "[yellow]![/yellow]")
        color = _SEV_COLOR.get(finding.severity, "red")
        return flag, f"[{color}]FLAGGED[/{color}]"
    if suspicious_path:
        return "[yellow]▲[/yellow]", "[yellow]SUSPECT[/yellow]"
    if cp.listeners:
        return "[green]✓[/green]", "[green]LISTENING[/green]"
    return "", "[dim]CLEAN[/dim]"


class AppsScreen(Widget):
    DEFAULT_CSS = """
    AppsScreen {
        layout: vertical;
        height: 1fr;
        background: #080e18;
    }
    #process-table {
        height: 1fr;
    }
    #detail-panel {
        height: 11;
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
        table.add_columns("!", "PID", "Name", "User", "Ports", "Conns", "Status", "Path")
        yield table
        yield Static(
            "[dim]↑ ↓  navigate  ·  details show below as you scroll[/dim]",
            id="detail-panel",
        )
        yield KeyBar(
            [
                ("↑↓", "Navigate"),
                ("Enter", "Inspect"),
                ("s", "Rescan"),
                ("p", "Pause"),
                ("1-7", "Tabs"),
                ("?", "Help"),
                ("q", "Quit"),
            ]
        )

    def on_show(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#process-table", DataTable).focus()

    def update_result(self, result: ScanResult) -> None:
        self._correlated = result.correlated
        self._findings = result.findings

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
            conns_count = len(cp.connections)
            conn_str = f"[cyan]{conns_count}[/cyan]" if conns_count > 0 else "[dim]0[/dim]"

            suspicious_path = any(
                p in (identity.executable_path or "") for p in _SUSPICIOUS_PATH_FRAGMENTS
            )
            finding = flagged.get(identity.name)
            flag, status = _status_badge(cp, finding, suspicious_path)

            path_short = identity.executable_path or ""
            # Trim /Applications/Foo.app/Contents/MacOS/Foo → Foo.app/...
            if "/Applications/" in path_short:
                parts = path_short.split("/Applications/", 1)
                path_short = parts[1]
            elif "/Library/" in path_short:
                path_short = "…/" + path_short.rsplit("/", 2)[-1]

            table.add_row(
                flag,
                str(identity.pid),
                identity.name,
                identity.user or "",
                ports,
                conn_str,
                status,
                path_short,
                key=identity.instance_id,
            )

    def _render_detail(self, row_key_value: str | None) -> None:
        if not row_key_value:
            return
        cp = next((c for c in self._correlated if c.instance_id == row_key_value), None)
        if not cp:
            return
        identity = cp.observation.identity
        proc_findings = [f for f in self._findings if f.subject == identity.name]

        lines: list[str] = [
            f"[bold]{identity.name}[/bold]"
            f"  [dim]PID {identity.pid}[/dim]"
            f"  [dim]·[/dim]  [dim]User:[/dim] {identity.user or '(unknown)'}"
            f"  [dim]·[/dim]  [dim]PPID:[/dim] {identity.parent_pid or '—'}",
        ]

        if proc_findings:
            lines.append("")
            for finding in proc_findings:
                color = _SEV_COLOR.get(finding.severity, "red")
                flag = _SEV_FLAG.get(finding.severity, "!")
                lines.append(f"  {flag} [{color}]{finding.title}[/{color}]")
                for r in finding.reasons[:2]:
                    lines.append(f"    [dim]› {r.description}[/dim]")

        if cp.listeners:
            lines.append("")
            for sock in cp.listeners:
                exposure = _EXPOSURE_SHORT.get(sock.exposure, str(sock.exposure))
                lines.append(
                    f"  [dim]LISTEN[/dim]  :{sock.local_endpoint.port}"
                    f"  {sock.local_endpoint.protocol.upper()}"
                    f"  {exposure}"
                    f"  [dim]{sock.local_endpoint.address}[/dim]"
                )

        if cp.connections:
            lines.append("")
            shown = 0
            for conn in cp.connections[:5]:
                remote = (
                    f"{conn.remote_endpoint.address}:{conn.remote_endpoint.port}"
                    if conn.remote_endpoint
                    else "—"
                )
                lines.append(
                    f"  [dim]CONN[/dim]    {remote}  [dim]{conn.socket_state.upper()}[/dim]"
                )
                shown += 1
            if len(cp.connections) > shown:
                lines.append(f"  [dim]… {len(cp.connections) - shown} more connections[/dim]")

        lines.append("")
        lines.append(f"  [dim]Path[/dim]  {identity.executable_path or '(unknown)'}")
        if identity.command_line:
            cmd = " ".join(identity.command_line)[:140]
            lines.append(f"  [dim]Cmd[/dim]   {cmd}")

        with contextlib.suppress(Exception):
            self.query_one("#detail-panel", Static).update("\n".join(lines))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key:
            self._render_detail(event.row_key.value)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._render_detail(event.row_key.value)
