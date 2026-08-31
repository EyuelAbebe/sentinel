from __future__ import annotations

import contextlib
import ipaddress
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import DataTable, Static

from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import ExposureLevel
from sentinel.tui.widgets.key_bar import KeyBar

_EXPOSURE_LABEL: dict[ExposureLevel, str] = {
    ExposureLevel.LOOPBACK: "[green]Localhost[/green]",
    ExposureLevel.LOCAL_NETWORK: "[yellow]Local net[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[bold red]All ifaces ⚠[/bold red]",
}

_EXPOSURE_FLAG: dict[ExposureLevel, str] = {
    ExposureLevel.LOOPBACK: "[green]✓[/green]",
    ExposureLevel.LOCAL_NETWORK: "[yellow]◆[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[bold red]⚠[/bold red]",
}


def _classify_remote(address: str | None) -> str:
    """Classify a remote IP address into a human-readable connection type."""
    if not address:
        return "[dim]—[/dim]"
    try:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback:
            return "[green]loopback[/green]"
        if ip.is_private:
            return "[yellow]local-net[/yellow]"
        if ip.is_global:
            return "[cyan]external[/cyan]"
        if ip.is_link_local:
            return "[dim]link-local[/dim]"
    except ValueError:
        pass
    return "[dim]unknown[/dim]"


class NetworkScreen(Widget):
    DEFAULT_CSS = """
    NetworkScreen {
        layout: vertical;
        height: 1fr;
        background: #080e18;
    }
    #tables-area {
        height: 1fr;
    }
    #listeners-pane {
        width: 1fr;
        border-right: solid #1a3a5a;
    }
    #connections-pane {
        width: 1fr;
    }
    .section-label {
        height: 1;
        padding: 0 1;
        color: #00e5ff;
        text-style: bold;
        background: #080e18;
    }
    #listeners-table {
        height: 1fr;
    }
    #connections-table {
        height: 1fr;
    }
    #net-detail {
        height: 7;
        border-top: solid #00ff9f;
        padding: 1 2;
        background: #0d1521;
        color: #a0c8e8;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._listener_rows: list[tuple[CorrelatedProcess, Any]] = []
        self._connection_rows: list[tuple[CorrelatedProcess, Any]] = []

    def compose(self) -> ComposeResult:
        with Horizontal(id="tables-area"):
            with Vertical(id="listeners-pane"):
                yield Static(
                    "── LISTENING PORTS ──",
                    classes="section-label",
                    id="listeners-label",
                )
                listeners: DataTable[str] = DataTable(id="listeners-table", cursor_type="row")
                listeners.add_columns("!", "Port", "Proto", "Process", "Exposure")
                yield listeners
            with Vertical(id="connections-pane"):
                yield Static(
                    "── ACTIVE CONNECTIONS ──",
                    classes="section-label",
                    id="connections-label",
                )
                conns: DataTable[str] = DataTable(id="connections-table", cursor_type="row")
                conns.add_columns("Process", "Local", "Remote", "Type", "State")
                yield conns
        yield Static(
            "[dim]↑ ↓  navigate  ·  Tab  switch tables  ·  details below[/dim]",
            id="net-detail",
        )
        yield KeyBar(
            [
                ("↑↓", "Navigate"),
                ("Tab", "Switch"),
                ("s", "Rescan"),
                ("p", "Pause"),
                ("1-7", "Tabs"),
                ("?", "Help"),
                ("q", "Quit"),
            ]
        )

    def on_show(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#listeners-table", DataTable).focus()

    def update_result(self, result: ScanResult) -> None:
        listeners_table = self.query_one("#listeners-table", DataTable)
        conns_table = self.query_one("#connections-table", DataTable)
        listeners_table.clear()
        conns_table.clear()

        self._listener_rows = []
        self._connection_rows = []

        for cp in result.correlated:
            for sock in cp.listeners:
                idx = len(self._listener_rows)
                self._listener_rows.append((cp, sock))
                flag = _EXPOSURE_FLAG.get(sock.exposure, "")
                exposure_text = _EXPOSURE_LABEL.get(sock.exposure, str(sock.exposure))
                listeners_table.add_row(
                    flag,
                    str(sock.local_endpoint.port),
                    sock.local_endpoint.protocol.upper(),
                    cp.name,
                    exposure_text,
                    key=str(idx),
                )
            for sock in cp.connections:
                idx = len(self._connection_rows)
                self._connection_rows.append((cp, sock))
                remote_addr = sock.remote_endpoint.address if sock.remote_endpoint else None
                remote_str = (
                    f"{sock.remote_endpoint.address}:{sock.remote_endpoint.port}"
                    if sock.remote_endpoint
                    else "—"
                )
                conn_type = _classify_remote(remote_addr)
                conns_table.add_row(
                    cp.name,
                    f"{sock.local_endpoint.address}:{sock.local_endpoint.port}",
                    remote_str,
                    conn_type,
                    sock.socket_state.upper(),
                    key=str(idx),
                )

        n_listeners = len(self._listener_rows)
        n_conns = len(self._connection_rows)
        self.query_one("#listeners-label", Static).update(
            f"── LISTENING PORTS ({n_listeners})"
            f"  [dim][bold red]⚠[/bold red]=all  [yellow]◆[/yellow]=local  [green]✓[/green]=loop[/dim]"
        )
        self.query_one("#connections-label", Static).update(
            f"── ACTIVE CONNECTIONS ({n_conns})"
            f"  [dim][cyan]ext[/cyan] [yellow]local[/yellow] [green]loop[/green][/dim]"
        )

        if n_listeners == 0 and n_conns == 0:
            with contextlib.suppress(Exception):
                self.query_one("#net-detail", Static).update(
                    "[yellow]No network data visible.[/yellow]\n\n"
                    "[dim]macOS restricts socket visibility without elevated privileges.\n"
                    "Run  [bold]sudo sentinel[/bold]  for complete network data.\n\n"
                    "Press  [bold]s[/bold]  to rescan.[/dim]"
                )

    def _render_listener_detail(self, idx: int) -> None:
        if idx < 0 or idx >= len(self._listener_rows):
            return
        cp, sock = self._listener_rows[idx]
        exposure_label = _EXPOSURE_LABEL.get(sock.exposure, str(sock.exposure))
        lines = [
            f"[bold]:{sock.local_endpoint.port}[/bold]"
            f"  [dim]{sock.local_endpoint.protocol.upper()}[/dim]"
            f"  ·  [dim]owned by[/dim] [bold]{cp.name}[/bold]  [dim](PID {cp.pid})[/dim]"
            f"  ·  {exposure_label}",
            f"  [dim]Bind[/dim]  {sock.local_endpoint.address}",
        ]
        if cp.observation.identity.executable_path:
            lines.append(f"  [dim]Path[/dim]  {cp.observation.identity.executable_path}")
        if cp.observation.identity.user:
            lines.append(f"  [dim]User[/dim]  {cp.observation.identity.user}")
        with contextlib.suppress(Exception):
            self.query_one("#net-detail", Static).update("\n".join(lines))

    def _render_connection_detail(self, idx: int) -> None:
        if idx < 0 or idx >= len(self._connection_rows):
            return
        cp, conn = self._connection_rows[idx]
        remote_addr = conn.remote_endpoint.address if conn.remote_endpoint else None
        remote_str = (
            f"{conn.remote_endpoint.address}:{conn.remote_endpoint.port}"
            if conn.remote_endpoint
            else "—"
        )
        conn_type = _classify_remote(remote_addr)
        lines = [
            f"[bold]{cp.name}[/bold]  [dim](PID {cp.pid})[/dim]"
            f"  ·  [dim]state:[/dim] {conn.socket_state.upper()}"
            f"  ·  [dim]type:[/dim] {conn_type}",
            f"  [dim]Local[/dim]   {conn.local_endpoint.address}:{conn.local_endpoint.port}",
            f"  [dim]Remote[/dim]  {remote_str}",
            f"  [dim]Proto[/dim]   {conn.local_endpoint.protocol.upper()}",
        ]
        if cp.observation.identity.executable_path:
            lines.append(f"  [dim]Path[/dim]    {cp.observation.identity.executable_path}")
        with contextlib.suppress(Exception):
            self.query_one("#net-detail", Static).update("\n".join(lines))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if not event.row_key or event.row_key.value is None:
            return
        idx = int(event.row_key.value)
        if event.control.id == "listeners-table":
            self._render_listener_detail(idx)
        elif event.control.id == "connections-table":
            self._render_connection_detail(idx)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if not event.row_key or event.row_key.value is None:
            return
        idx = int(event.row_key.value)
        if event.control.id == "listeners-table":
            self._render_listener_detail(idx)
        elif event.control.id == "connections-table":
            self._render_connection_detail(idx)
