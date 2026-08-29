from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Static

HELP_TEXT = """\
[bold cyan]Keyboard Reference[/bold cyan]

  [bold]Navigation[/bold]
  ↑ / ↓         Move through list
  Enter          Inspect selected item
  Esc            Go back

  [bold]Actions[/bold]
  s              Rescan now
  p              Pause / resume live display
  /              Search (where available)
  f              Filter (where available)

  [bold]Views[/bold]
  1              Overview
  2              Apps
  3              Network
  4              Findings
  ? or h         This help screen

  [bold]Other[/bold]
  q              Quit
"""


class HelpScreen(Screen[None]):
    TITLE = "Help"

    BINDINGS = [("escape,q,h,question_mark", "dismiss", "Back")]

    def compose(self) -> ComposeResult:
        yield Static(HELP_TEXT, id="help-content")
        yield Footer()
