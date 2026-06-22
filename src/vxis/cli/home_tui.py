"""VXIS interactive home — a Textual screen (dossier identity) for the main menu.

The stock InquirerPy list (emoji bullets + a dashed separator) reads as a generic
library widget no matter the colour. This makes the entry a *designed* surface
matching the scan TUI: a brass wordmark panel + a bordered menu with label +
description rows and a brass highlight bar.

``run_home_menu()`` returns the chosen action
('scan'|'results'|'report'|'advanced'|'settings'|'exit'), or 'exit' on quit. The
caller falls back to the InquirerPy menu off-TTY / when textual is unavailable.
"""
from __future__ import annotations

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Footer, OptionList, Static
from textual.widgets.option_list import Option

from vxis.cli.theme import MUTED, vxis_textual_theme

_WORDMARK = r"""
__     __ __  __ ___  ____
\ \   / / \ \/ /|_ _|/ ___|
 \ \ / /   \  /  | | \___ \
  \ V /    /  \ _| |_ ___) |
   \_/    /_/\_\_____|____/
"""

# (action value, label, one-line description)
_MENU: list[tuple[str, str, str]] = [
    ("scan", "Scan", "run an autonomous assessment"),
    ("results", "Results", "browse past scans & findings"),
    ("report", "Report", "generate / export a report"),
    ("advanced", "Advanced", "industry · clients · plugins · dashboard"),
    ("settings", "Settings", "brain · models · API keys"),
    ("exit", "Quit", ""),
]


def _row(label: str, desc: str) -> Text:
    row = Text()
    row.append(f"  {label:<11}", style="bold")
    if desc:
        row.append(desc, style=MUTED)
    return row


class VxisHome(App):
    CSS = """
    Screen { background: $background; align: center middle; }
    #wrap { width: 66; height: auto; }
    #banner {
        color: $primary;
        text-align: center;
        border: round $primary;
        border-title-align: center;
        padding: 0 1;
        margin-bottom: 1;
    }
    #menu {
        background: $surface;
        border: round $secondary;
        border-title-align: left;
        padding: 1 1;
        height: auto;
    }
    OptionList:focus > .option-list--option-highlighted {
        background: $primary 25%;
        text-style: bold;
    }
    """
    BINDINGS = [("q", "quit_home", "Quit"), ("escape", "quit_home", "Quit")]

    def compose(self) -> ComposeResult:
        with Vertical(id="wrap"):
            banner = Static(_WORDMARK.strip("\n"), id="banner")
            banner.border_title = "VXIS"
            banner.border_subtitle = "autonomous pentesting"
            yield banner
            menu = OptionList(
                *[Option(_row(lbl, desc), id=val) for val, lbl, desc in _MENU],
                id="menu",
            )
            menu.border_title = "MAIN"
            yield menu
        yield Footer()

    def on_mount(self) -> None:
        self.register_theme(vxis_textual_theme())
        self.theme = "vxis"
        self.title = "VXIS"
        self.query_one("#menu", OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.exit(event.option.id)

    def action_quit_home(self) -> None:
        self.exit("exit")


def run_home_menu() -> str | None:
    """Run the Textual home; return the chosen action ('exit' on quit)."""
    return VxisHome().run()


__all__ = ["VxisHome", "run_home_menu"]
