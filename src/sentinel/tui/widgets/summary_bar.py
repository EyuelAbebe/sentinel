from __future__ import annotations

from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Label
from textual.containers import Horizontal


class StatBox(Widget):
    DEFAULT_CSS = """
    StatBox {
        padding: 0 2;
        border: round $primary;
        height: 5;
        min-width: 16;
        content-align: center middle;
    }
    StatBox .label {
        text-style: bold;
        color: $text;
        text-align: center;
    }
    StatBox .value {
        text-style: bold;
        color: $accent;
        text-align: center;
    }
    """

    value: reactive[int] = reactive(0)
    title_text: reactive[str] = reactive("")

    def __init__(self, title: str, value: int = 0, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.title_text = title
        self.value = value

    def compose(self) -> ComposeResult:
        yield Label(self.title_text, classes="label")
        yield Label(str(self.value), classes="value", id="stat-value")

    def watch_value(self, new_value: int) -> None:
        try:
            self.query_one("#stat-value", Label).update(str(new_value))
        except Exception:
            pass


class SummaryBar(Horizontal):
    DEFAULT_CSS = """
    SummaryBar {
        height: 7;
        align: center middle;
        padding: 1 2;
    }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._processes = StatBox("Processes", id="stat-processes")
        self._ports = StatBox("Ports", id="stat-ports")
        self._connections = StatBox("Connections", id="stat-connections")
        self._attention = StatBox("Attention", id="stat-attention")

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
        if attention > 0:
            self._attention.add_class("has-attention")
        else:
            self._attention.remove_class("has-attention")
