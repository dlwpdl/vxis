"""VXIS CLI visual identity — the single source for the "dossier" look shared by
the input wizard (InquirerPy) and the scan TUI (Textual).

Graphite ink ground + brass home accent + steel cyan — the same palette as the
VXIS comparison artifact, so the whole CLI reads as one designed surface instead
of generic library defaults. Heavy deps (textual / InquirerPy) are imported
lazily inside the factories so importing the palette stays cheap.
"""

from __future__ import annotations

import os
from pathlib import Path

# ── palette (hex) ──────────────────────────────────────────────────────────
BRASS = "#E3A24A"  # primary / home accent
CYAN = "#5FB6C4"  # secondary
GREEN = "#6FB86F"  # success / found
HAIR = "#3A4150"  # hairline separators
INK = "#13161C"  # background
SURFACE = "#1B1F27"
PANEL = "#222732"
TEXT = "#E8EAED"
MUTED = "#868E9B"
ERROR = "#D97777"


def get_ui_language() -> str:
    """Return the selected terminal UI language (English is the safe default)."""
    return "ko" if os.environ.get("VXIS_UI_LANGUAGE", "").strip().lower() == "ko" else "en"


def tr(english: str, korean: str) -> str:
    """Select operator-facing text for the active terminal UI language."""
    return korean if get_ui_language() == "ko" else english


def set_ui_language(language: str, *, path: Path | None = None) -> str:
    """Activate and persist a supported terminal UI language."""
    from vxis.config.env_store import upsert_env

    value = "ko" if language.strip().lower() == "ko" else "en"
    upsert_env("VXIS_UI_LANGUAGE", value, path=path)
    return value


def vxis_textual_theme():
    """The Textual Theme for the scan TUI (registered + applied on mount)."""
    from textual.theme import Theme

    return Theme(
        name="vxis",
        primary=BRASS,
        secondary=CYAN,
        accent=BRASS,
        foreground=TEXT,
        background=INK,
        surface=SURFACE,
        panel=PANEL,
        success=GREEN,
        warning=BRASS,
        error=ERROR,
        dark=True,
    )


def vxis_inquirer_style():
    """InquirerPy style for the input wizard — matches the scan TUI palette so the
    prompts (pointer, choices, answers, instructions) stop looking like generic
    library defaults. Merged over InquirerPy's defaults (style_override=False)."""
    from InquirerPy.utils import get_style

    return get_style(
        {
            "questionmark": f"{BRASS} bold",
            "answermark": GREEN,
            "answer": f"{BRASS} bold",
            "question": f"{TEXT} bold",
            "instruction": MUTED,
            "long_instruction": MUTED,
            "pointer": f"{BRASS} bold",
            "marker": BRASS,
            "checkbox": BRASS,
            "separator": HAIR,
            "skipped": MUTED,
            "input": TEXT,
            "validation_toolbar": ERROR,
        },
        style_override=False,
    )
