from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Label
from textual.containers import Vertical

from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import ExposureLevel

_EXPOSURE_MARKUP = {
    ExposureLevel.LOOPBACK: "[green]Localhost[/green]",
    ExposureLevel.LOCAL_NETWORK: "[yellow]Local network[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[red]All interfaces[/red]",
}


class NetworkScreen(Screen[None]):
    TITLE = "Network"

    DEFAULT_CSS = """
    NetworkScreen {
        layout: vertical;
    }
    .section-label {
        padding: 0 2;
        color: $text-muted;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        yield Label("LISTENING PORTS", classes="section-label")
        listeners = DataTable(id="listeners-table", cursor_type="row")
        listeners.add_columns("Port", "Proto", "Process", "Exposure")
        yield listeners
        yield Label("CONNECTIONS", classes="section-label")
        conns = DataTable(id="connections-table", cursor_type="row")
        conns.add_columns("Process", "Local", "Remote", "State")
        yield conns
        yield Footer()

    def update_result(self, result: ScanResult) -> None:
        listeners = self.query_one("#listeners-table", DataTable)
        conns = self.query_one("#connections-table", DataTable)
        listeners.clear()
        conns.clear()

        for cp in result.correlated:
            for sock in cp.listeners:
                exposure_text = _EXPOSURE_MARKUP.get(sock.exposure, sock.exposure)
                listeners.add_row(
                    str(sock.local_endpoint.port),
                    sock.local_endpoint.protocol.upper(),
                    cp.name,
                    exposure_text,
                )
            for sock in cp.connections:
                remote = ""
                if sock.remote_endpoint:
                    remote = f"{sock.remote_endpoint.address}:{sock.remote_endpoint.port}"
                conns.add_row(
                    cp.name,
                    f"{sock.local_endpoint.address}:{sock.local_endpoint.port}",
                    remote,
                    sock.socket_state.upper(),
                )
