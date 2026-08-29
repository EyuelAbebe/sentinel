from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Static

from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.scan_service import ScanResult


class AppsScreen(Screen[None]):
    TITLE = "Apps"

    DEFAULT_CSS = """
    AppsScreen {
        layout: vertical;
    }
    #detail-panel {
        height: 10;
        border-top: solid $primary;
        padding: 1 2;
        color: $text-muted;
    }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._correlated: list[CorrelatedProcess] = []

    def compose(self) -> ComposeResult:
        table = DataTable(id="process-table", cursor_type="row")
        table.add_columns("PID", "Name", "User", "Ports", "Path")
        yield table
        yield Static("[dim]Select a process to inspect[/dim]", id="detail-panel")
        yield Footer()

    def update_result(self, result: ScanResult) -> None:
        self._correlated = result.correlated
        table = self.query_one("#process-table", DataTable)
        table.clear()
        for cp in result.correlated:
            if cp.pid == 0:
                continue
            identity = cp.observation.identity
            ports = ", ".join(f":{sock.local_endpoint.port}" for sock in cp.listeners)
            table.add_row(
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
        lines = [
            f"[bold]{identity.name}[/bold]  PID {identity.pid}",
            f"Path    {identity.executable_path or '(unknown)'}",
            f"User    {identity.user or '(unknown)'}",
            f"PPID    {identity.parent_pid or '—'}",
        ]
        if cp.listeners:
            ports = ", ".join(f":{sock.local_endpoint.port}" for sock in cp.listeners)
            lines.append(f"Ports   {ports}")
        if identity.command_line:
            cmd = " ".join(identity.command_line)[:120]
            lines.append(f"Cmd     {cmd}")
        self.query_one("#detail-panel", Static).update("\n".join(lines))
