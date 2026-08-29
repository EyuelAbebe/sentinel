from __future__ import annotations

import contextlib
import time
from datetime import UTC, datetime

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.widgets import Header, TabbedContent, TabPane

from sentinel.application.event_bus import EventBus
from sentinel.application.live_monitor import LiveMonitorService
from sentinel.application.scan_service import QuickScanService, ScanResult
from sentinel.collectors.network_psutil import PsutilNetworkCollector
from sentinel.collectors.process_psutil import PsutilProcessCollector
from sentinel.config import get_config
from sentinel.domain.enums import EventType
from sentinel.domain.events import Event as DomainEvent
from sentinel.storage.database import get_engine, init_db
from sentinel.tui.screens.apps import AppsScreen
from sentinel.tui.screens.findings import FindingsScreen
from sentinel.tui.screens.help import HelpScreen
from sentinel.tui.screens.network import NetworkScreen
from sentinel.tui.screens.overview import OverviewScreen

_EVENT_LABEL: dict[EventType, tuple[str, str]] = {
    EventType.PROCESS_STARTED: ("green", "⬆ PROC"),
    EventType.PROCESS_STOPPED: ("dim", "⬇ PROC"),
    EventType.PORT_OPENED: ("yellow", "◆ PORT"),
    EventType.PORT_CLOSED: ("dim", "◇ PORT"),
    EventType.CONNECTION_OPENED: ("cyan", "→ CONN"),
    EventType.CONNECTION_CLOSED: ("dim", "← DISC"),
    EventType.SITE_VISITED: ("blue", "◎ SITE"),
    EventType.THIRD_PARTY_REQUEST: ("dark_orange", "⇢ 3RD"),
}

_SEV_FIND_COLOR = {
    "low": "yellow",
    "medium": "dark_orange",
    "high": "red",
    "critical": "bold red",
}


class _ActivityLine(Message):
    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text


class SentinelApp(App[None]):
    TITLE = "Sentinel"
    SUB_TITLE = "Local Security Monitor  ·  Press ? for help"

    CSS = """
    /* ── global neon-hacking palette ──────────────────────────── */
    Header {
        background: #080e18;
        color: #00ff9f;
        border-bottom: solid #00ff9f;
    }
    TabbedContent {
        height: 1fr;
        background: #080e18;
    }
    TabbedContent ContentSwitcher {
        background: #080e18;
    }
    TabPane {
        background: #080e18;
        padding: 0;
    }
    Tabs {
        background: #0d1521;
        border-bottom: solid #00ff9f;
    }
    Tab {
        background: #0d1521;
        color: #2a4a6a;
    }
    Tab.-active {
        background: #080e18;
        color: #00ff9f;
        text-style: bold;
    }
    Tab:hover {
        color: #00e5ff;
    }
    DataTable {
        background: #080e18;
        color: #a0c8e8;
    }
    DataTable > .datatable--header {
        background: #0d1521;
        color: #00e5ff;
        text-style: bold;
    }
    DataTable > .datatable--cursor {
        background: #0d3050;
        color: #00ff9f;
    }
    DataTable > .datatable--hover {
        background: #0a1e30;
    }
    RichLog {
        background: #080e18;
        color: #a0c8e8;
    }
    VerticalScroll {
        background: #080e18;
    }
    Static {
        color: #a0c8e8;
    }
    Footer {
        background: #0d1521;
        color: #2a4a6a;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "rescan", "Rescan", show=True),
        Binding("p", "toggle_pause", "Pause", show=True),
        Binding("question_mark", "show_help", "Help", key_display="?"),
        Binding("1", "tab_overview", "Overview", show=False),
        Binding("2", "tab_apps", "Apps", show=False),
        Binding("3", "tab_network", "Network", show=False),
        Binding("4", "tab_findings", "Findings", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        cfg = get_config()
        _procs = PsutilProcessCollector()
        _nets = PsutilNetworkCollector()
        self._bus = EventBus()
        self._svc = QuickScanService(
            process_collector=_procs,
            network_collector=_nets,
        )
        _engine = get_engine()
        init_db(_engine)
        self._monitor = LiveMonitorService(
            process_collector=_procs,
            network_collector=_nets,
            event_bus=self._bus,
            engine=_engine,
            poll_interval=cfg.poll_interval_seconds,
        )
        self._paused = False
        self._last_result: ScanResult | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(id="tabs"):
            with TabPane("1 Overview", id="tab-overview"):
                yield OverviewScreen(id="overview")
            with TabPane("2 Apps", id="tab-apps"):
                yield AppsScreen(id="apps")
            with TabPane("3 Network", id="tab-network"):
                yield NetworkScreen(id="network")
            with TabPane("4 Findings", id="tab-findings"):
                yield FindingsScreen(id="findings")

    async def on_mount(self) -> None:
        self._bus.subscribe_all(self._on_domain_event)
        await self._monitor.start()
        self.run_worker(self._initial_scan(), exclusive=False)
        self.set_interval(get_config().poll_interval_seconds * 5, self._refresh_scan)

    async def on_unmount(self) -> None:
        await self._monitor.stop()

    async def _on_domain_event(self, event: DomainEvent) -> None:
        ts = datetime.now(UTC).strftime("%H:%M:%S")
        color, label = _EVENT_LABEL.get(event.event_type, ("dim", event.event_type.value))

        # Build the most informative detail string from payload
        name = event.payload.get("name", "")
        pid = event.payload.get("pid", "")
        port = event.payload.get("local_port", "")
        remote = event.payload.get("remote_address", "")
        domain = event.payload.get("domain", "")

        if name and pid:
            detail = f"{name} (pid {pid})"
        elif name:
            detail = name
        elif domain:
            detail = domain
        elif port:
            detail = f":{port}"
        elif remote:
            detail = remote
        else:
            detail = ""

        text = f"[dim]{ts}[/dim]  [{color}]{label}[/{color}]"
        if detail:
            text += f"  [bold]{detail}[/bold]"
        self.post_message(_ActivityLine(text))

    def on__activity_line(self, msg: _ActivityLine) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#overview", OverviewScreen).log_activity(msg.text)

    async def _initial_scan(self) -> None:
        await self._do_scan()

    async def _refresh_scan(self) -> None:
        if not self._paused:
            await self._do_scan()

    async def _do_scan(self) -> None:
        t0 = time.monotonic()
        with contextlib.suppress(Exception):
            self.query_one("#overview", OverviewScreen).set_scanning(True)
        try:
            result = await self._svc.run()
            self._last_result = result
            duration = time.monotonic() - t0
            with contextlib.suppress(Exception):
                self.query_one("#overview", OverviewScreen).set_scanning(False, result, duration)
            self._push_result(result)
            if result.findings:
                n = len(result.findings)
                self.notify(
                    f"⚠  {n} finding{'s' if n > 1 else ''} need attention",
                    severity="warning",
                    timeout=4,
                )
            else:
                self.notify("✓  All clear", severity="information", timeout=2)
        except Exception as exc:
            with contextlib.suppress(Exception):
                self.query_one("#overview", OverviewScreen).set_scanning(False)
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

        # Log findings into the activity stream
        if result.findings:
            ts = datetime.now(UTC).strftime("%H:%M:%S")
            with contextlib.suppress(Exception):
                overview = self.query_one("#overview", OverviewScreen)
                for f in result.findings:
                    color = _SEV_FIND_COLOR.get(f.severity.value, "red")
                    overview.log_activity(
                        f"[dim]{ts}[/dim]  [{color}]● FIND[/{color}]"
                        f"  [bold]{f.title}[/bold]"
                        f"  [{color}]{f.severity.upper()}[/{color}]"
                    )

    def action_rescan(self) -> None:
        if self._paused:
            self.notify("⏸  Paused — press p to resume first", severity="warning", timeout=2)
            return
        self.run_worker(self._do_scan(), exclusive=False)

    def action_toggle_pause(self) -> None:
        self._paused = not self._paused
        if self._paused:
            self.notify("⏸  Live monitoring paused", severity="warning", timeout=2)
        else:
            self.notify("▶  Live monitoring resumed", severity="information", timeout=2)
            self.run_worker(self._do_scan(), exclusive=False)

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
