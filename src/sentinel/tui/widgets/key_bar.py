from __future__ import annotations

from typing import Any

from rich.text import Text
from textual.app import RenderResult
from textual.widget import Widget


class KeyBar(Widget):
    """htop-style bottom key-hint bar.

    Each hint is a (key_display, label) pair rendered as a colored block.
    Example: KeyBar([("s", "Rescan"), ("q", "Quit")])
    """

    DEFAULT_CSS = """
    KeyBar {
        height: 1;
        background: #0d1521;
        border-top: solid #00ff9f;
        padding: 0 1;
        content-align: left middle;
    }
    """

    def __init__(self, hints: list[tuple[str, str]], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._hints = hints

    def render(self) -> RenderResult:
        text = Text(overflow="ellipsis", no_wrap=True)
        for i, (key, label) in enumerate(self._hints):
            if i > 0:
                text.append("  ", style="")
            text.append(f" {key} ", style="bold black on #00ff9f")
            text.append(f" {label}", style="#2a6a8a")
        return text
