from __future__ import annotations

import contextlib
from datetime import UTC, datetime

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Header, TabbedContent, TabPane

from sentinel.application.scan_service import QuickScanService, ScanResult
from sentinel.collectors.network_psutil import PsutilNetworkCollector
from sentinel.collectors.process_psutil import PsutilProcessCollector
from sentinel.config import get_config
from sentinel.tui.screens.apps import AppsScreen
from sentinel.tui.screens.findings import FindingsScreen
from sentinel.tui.screens.help import HelpScreen
from sentinel.tui.screens.network import NetworkScreen
from sentinel.tui.screens.overview import OverviewScreen


class SentinelApp(App[None]):
    TITLE = "Sentinel"
    SUB_TITLE = "Local Security Monitor"

    CSS = """
    TabbedContent {
        height: 1fr;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "rescan", "Scan", show=True),
        Binding("question_mark", "show_help", "Help", key_display="?"),
        Binding("1", "tab_overview", "Overview", show=False),
        Binding("2", "tab_apps", "Apps", show=False),
        Binding("3", "tab_network", "Network", show=False),
        Binding("4", "tab_findings", "Findings", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._svc = QuickScanService(
            process_collector=PsutilProcessCollector(),
            network_collector=PsutilNetworkCollector(),
        )
        self._paused = False
        self._last_result: ScanResult | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(id="tabs"):
            with TabPane("Overview", id="tab-overview"):
                yield OverviewScreen(id="overview")
            with TabPane("Apps", id="tab-apps"):
                yield AppsScreen(id="apps")
            with TabPane("Network", id="tab-network"):
                yield NetworkScreen(id="network")
            with TabPane("Findings", id="tab-findings"):
                yield FindingsScreen(id="findings")

    def on_mount(self) -> None:
        self.run_worker(self._initial_scan(), exclusive=False)
        self.set_interval(get_config().poll_interval_seconds * 5, self._refresh_scan)

    async def _initial_scan(self) -> None:
        await self._do_scan()

    async def _refresh_scan(self) -> None:
        if not self._paused:
            await self._do_scan()

    async def _do_scan(self) -> None:
        try:
            result = await self._svc.run()
            self._last_result = result
            self._push_result(result)
        except Exception as exc:
            self.notify(f"Scan error: {exc}", severity="error")

    def _push_result(self, result: ScanResult) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#overview", OverviewScreen).update_result(result)
        with contextlib.suppress(Exception):
            self.query_one("#apps", AppsScreen).update_result(result)
        with contextlib.suppress(Exception):
            self.query_one("#network", NetworkScreen).update_result(result)
        with contextlib.suppress(Exception):
            self.query_one("#findings", FindingsScreen).update_result(result)

        if result.findings:
            ts = datetime.now(UTC).strftime("%H:%M:%S")
            with contextlib.suppress(Exception):
                overview = self.query_one("#overview", OverviewScreen)
                for f in result.findings:
                    overview.log_activity(
                        f"{ts} [bold red]![/bold red] {f.title}  {f.severity.upper()}"
                    )

    def action_rescan(self) -> None:
        self.run_worker(self._do_scan(), exclusive=False)
        self.notify("Scanning…", timeout=1)

    def action_show_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_tab_overview(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab-overview"

    def action_tab_apps(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab-apps"

    def action_tab_network(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab-network"

    def action_tab_findings(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab-findings"
