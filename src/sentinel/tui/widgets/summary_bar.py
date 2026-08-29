from __future__ import annotations

import contextlib
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Label


class StatBox(Widget):
    DEFAULT_CSS = """
    StatBox {
        padding: 0 2;
        border: round #00e5ff;
        height: 5;
        min-width: 18;
        content-align: center middle;
        background: #0d1521;
    }
    StatBox .label {
        text-style: bold;
        color: #2a6a8a;
        text-align: center;
    }
    StatBox .value {
        text-style: bold;
        color: #00e5ff;
        text-align: center;
    }
    StatBox.has-findings {
        border: round #ff3358;
        background: #1a0810;
    }
    StatBox.has-findings .value {
        color: #ff3358;
    }
    StatBox.all-clear {
        border: round #00ff9f;
        background: #081a10;
    }
    StatBox.all-clear .value {
        color: #00ff9f;
    }
    """

    value: reactive[int] = reactive(0)
    title_text: reactive[str] = reactive("")

    def __init__(self, title: str, value: int = 0, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.title_text = title
        self.value = value

    def compose(self) -> ComposeResult:
        yield Label(self.title_text, classes="label")
        yield Label(str(self.value), classes="value", id="stat-value")

    def watch_value(self, new_value: int) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#stat-value", Label).update(str(new_value))


class SummaryBar(Horizontal):
    DEFAULT_CSS = """
    SummaryBar {
        height: 7;
        align: center middle;
        padding: 1 2;
        background: #080e18;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._processes = StatBox("⬤  PROCESSES", id="stat-processes")
        self._ports = StatBox("◆  PORTS", id="stat-ports")
        self._connections = StatBox("⇄  CONNECTIONS", id="stat-connections")
        self._attention = StatBox("●  ATTENTION", id="stat-attention")

    def compose(self) -> ComposeResult:
        yield self._processes
        yield self._ports
        yield self._connections
        yield self._attention

    def update_stats(
        self,
        processes: int,
        ports: int,
        connections: int,
        attention: int,
    ) -> None:
        self._processes.value = processes
        self._ports.value = ports
        self._connections.value = connections
        self._attention.value = attention

        self._attention.remove_class("has-findings")
        self._attention.remove_class("all-clear")
        if attention > 0:
            self._attention.add_class("has-findings")
        else:
            self._attention.add_class("all-clear")
