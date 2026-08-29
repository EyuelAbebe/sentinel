from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Static

from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import ExposureLevel
from sentinel.tui.widgets.key_bar import KeyBar

_EXPOSURE_MARKUP: dict[ExposureLevel, str] = {
    ExposureLevel.LOOPBACK: "[green]Localhost[/green]",
    ExposureLevel.LOCAL_NETWORK: "[yellow]Local network[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[bold red]All interfaces[/bold red]",
}

_EXPOSURE_FLAG: dict[ExposureLevel, str] = {
    ExposureLevel.LOOPBACK: "",
    ExposureLevel.LOCAL_NETWORK: "[yellow]◆[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[bold red]⚠[/bold red]",
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
        yield Static(
            "── LISTENING PORTS ──────────────────────────────────────",
            classes="section-label",
            id="listeners-label",
        )
        listeners: DataTable[str] = DataTable(id="listeners-table", cursor_type="row")
        listeners.add_columns("!", "Port", "Proto", "Process", "Exposure")
        yield listeners
        yield Static(
            "── ACTIVE CONNECTIONS ───────────────────────────────────",
            classes="section-label",
            id="connections-label",
        )
        conns: DataTable[str] = DataTable(id="connections-table", cursor_type="row")
        conns.add_columns("Process", "Local", "Remote", "State")
        yield conns
        yield KeyBar(
            [
                ("↑↓", "Navigate"),
                ("Tab", "Next table"),
                ("s", "Rescan"),
                ("p", "Pause"),
                ("1-4", "Tabs"),
                ("?", "Help"),
                ("q", "Quit"),
            ]
        )

    def update_result(self, result: ScanResult) -> None:
        listeners_table = self.query_one("#listeners-table", DataTable)
        conns_table = self.query_one("#connections-table", DataTable)
        listeners_table.clear()
        conns_table.clear()

        listener_count = 0
        conn_count = 0

        for cp in result.correlated:
            for sock in cp.listeners:
                listener_count += 1
                flag = _EXPOSURE_FLAG.get(sock.exposure, "")
                exposure_text = _EXPOSURE_MARKUP.get(sock.exposure, sock.exposure)
                listeners_table.add_row(
                    flag,
                    str(sock.local_endpoint.port),
                    sock.local_endpoint.protocol.upper(),
                    cp.name,
                    exposure_text,
                )
            for sock in cp.connections:
                conn_count += 1
                remote = ""
                if sock.remote_endpoint:
                    remote = f"{sock.remote_endpoint.address}:{sock.remote_endpoint.port}"
                conns_table.add_row(
                    cp.name,
                    f"{sock.local_endpoint.address}:{sock.local_endpoint.port}",
                    remote,
                    sock.socket_state.upper(),
                )

        self.query_one("#listeners-label", Static).update(
            f"── LISTENING PORTS ({listener_count})"
            f"  [dim][bold red]⚠[/bold red]=all-interfaces  [yellow]◆[/yellow]=local-network[/dim]"
            f"  ─────────────────────"
        )
        self.query_one("#connections-label", Static).update(
            f"── ACTIVE CONNECTIONS ({conn_count}) ───────────────────────────────"
        )
