"""VXIS interactive menus — Textual screens (dossier identity) for the home and
every submenu, so the whole menu flow is one designed surface (not a stock
InquirerPy list anywhere). Brass is the single chrome accent.

- run_home_menu() -> action ('scan'|'results'|...|'exit'); the framed home with
  the wordmark banner + label/description rows.
- run_menu(title, items) -> selected value | None; a generic brass menu for
  submenus (advanced / settings / ...). `items` = list of (value, label).

Off-TTY / no textual, the caller falls back to InquirerPy.
"""
from __future__ import annotations

import re
from typing import Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Footer, Input, OptionList, Static
from textual.widgets.option_list import Option

from vxis.cli.theme import MUTED, vxis_textual_theme

_WORDMARK = r"""
__     __ __  __ ___  ____
\ \   / / \ \/ /|_ _|/ ___|
 \ \ / /   \  /  | | \___ \
  \ V /    /  \ _| |_ ___) |
   \_/    /_/\_\_____|____/
"""

# (action value, label, one-line description) for the home screen.
_HOME: list[tuple[str, str, str]] = [
    ("scan", "Scan", "run an autonomous assessment"),
    ("results", "Results", "browse past scans & findings"),
    ("report", "Report", "generate / export a report"),
    ("advanced", "Advanced", "industry · clients · plugins · dashboard"),
    ("settings", "Settings", "brain · models · API keys"),
    ("exit", "Quit", ""),
]


def _home_row(label: str, desc: str) -> Text:
    row = Text()
    row.append(f"  {label:<11}", style="bold")
    if desc:
        row.append(desc, style=MUTED)
    return row


# Emoji / variation-selector / ZWJ ranges — stripped from submenu labels so the
# Textual menu reads clean (the InquirerPy choice strings bundle an icon).
_EMOJI_RE = re.compile(
    "[\U0001f000-\U0001faff\U00002600-\U000027bf\U00002b00-\U00002bff"
    "\U0001f1e6-\U0001f1ff️‍]+"
)


def _menu_row(raw: str, *, max_desc: int = 60) -> Text:
    """Clean a bundled InquirerPy choice name ("<emoji>  Name    description") into
    a tidy dossier row: emoji removed, name bold + description dimmed, description
    truncated so it stays on ONE line (no ugly wrap)."""
    text = _EMOJI_RE.sub("", str(raw)).strip()
    # Choices put a wide gap (3+ spaces) between the name and its description.
    parts = re.split(r"\s{3,}", text, maxsplit=1)
    name = re.sub(r"\s{2,}", " ", parts[0]).strip()
    desc = re.sub(r"\s{2,}", " ", parts[1]).strip() if len(parts) > 1 else ""
    row = Text()
    row.append("  " + name, style="bold")
    if desc:
        if len(desc) > max_desc:
            desc = desc[: max_desc - 1].rstrip() + "…"
        row.append("   " + desc, style=MUTED)
    return row


class VxisMenu(App):
    """A framed, navigable dossier menu. Returns the selected item id from run()
    (or None on quit/back). Brass chrome throughout."""

    CSS = """
    Screen { background: $background; align: center middle; }
    #wrap { width: 88; height: auto; max-width: 96%; }
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
        border: round $primary;
        border-title-color: $primary;
        border-title-align: left;
        padding: 1 1;
        height: auto;
    }
    OptionList:focus > .option-list--option-highlighted {
        background: $primary 25%;
        text-style: bold;
    }
    """
    BINDINGS = [("q", "quit_menu", "Quit"), ("escape", "quit_menu", "Back")]

    def __init__(
        self,
        *,
        items: list[tuple[str, Any]],
        title: str = "MENU",
        show_banner: bool = False,
    ) -> None:
        super().__init__()
        self._items = items  # (id, prompt-renderable)
        self._menu_title = title
        self._show_banner = show_banner

    def compose(self) -> ComposeResult:
        with Vertical(id="wrap"):
            if self._show_banner:
                banner = Static(_WORDMARK.strip("\n"), id="banner")
                banner.border_title = "VXIS"
                banner.border_subtitle = "autonomous pentesting"
                yield banner
            menu = OptionList(*[Option(prompt, id=ident) for ident, prompt in self._items], id="menu")
            menu.border_title = self._menu_title
            yield menu
        yield Footer()

    def on_mount(self) -> None:
        self.register_theme(vxis_textual_theme())
        self.theme = "vxis"
        self.title = "VXIS"
        self.query_one("#menu", OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.exit(event.option.id)

    def action_quit_menu(self) -> None:
        self.exit(None)


class VxisHome(VxisMenu):
    """The home screen — the main menu with the wordmark banner."""

    def __init__(self) -> None:
        super().__init__(
            items=[(val, _home_row(lbl, desc)) for val, lbl, desc in _HOME],
            title="MAIN",
            show_banner=True,
        )


def run_home_menu() -> str | None:
    """Run the home; return the chosen action ('exit'/None on quit)."""
    return VxisHome().run()


def run_menu(title: str, items: list[tuple[Any, str]]) -> Any:
    """Run a generic dossier submenu. `items` = (value, label) — value may be any
    object (e.g. a sentinel). Returns the selected value, or None on quit/back."""
    # OptionList ids must be strings, so key options by index and map back to the
    # original (possibly non-string) value.
    options = [(str(idx), _menu_row(label)) for idx, (_v, label) in enumerate(items)]
    result = VxisMenu(items=options, title=title.upper(), show_banner=False).run()
    if result is None:
        return None
    return items[int(result)][0]


class VxisInput(App):
    """A single-field dossier text prompt (for the scan wizard's target etc.).
    run() returns the entered string, or None on Esc."""

    CSS = """
    Screen { background: $background; align: center middle; }
    #wrap { width: 72; height: auto; }
    #prompt { color: $text; padding: 0 1; margin-bottom: 1; }
    #field { border: round $primary; }
    """
    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, *, title: str, prompt: str = "", default: str = "") -> None:
        super().__init__()
        self._field_title = title
        self._prompt = prompt
        self._default = default

    def compose(self) -> ComposeResult:
        with Vertical(id="wrap"):
            if self._prompt:
                yield Static(self._prompt, id="prompt")
            field = Input(value=self._default, id="field")
            field.border_title = self._field_title
            yield field
        yield Footer()

    def on_mount(self) -> None:
        self.register_theme(vxis_textual_theme())
        self.theme = "vxis"
        self.title = "VXIS"
        self.query_one("#field", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.exit(event.value)

    def action_cancel(self) -> None:
        self.exit(None)


def run_input(title: str, prompt: str = "", default: str = "") -> str | None:
    """Run a dossier text prompt; return the entered string (None on Esc)."""
    return VxisInput(title=title.upper(), prompt=prompt, default=default).run()


__all__ = ["VxisMenu", "VxisHome", "VxisInput", "run_home_menu", "run_menu", "run_input"]
