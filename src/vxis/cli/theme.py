"""VXIS CLI visual identity — the single source for the "dossier" look shared by
the input wizard (InquirerPy) and the scan TUI (Textual).

Graphite ink ground + brass home accent + steel cyan — the same palette as the
VXIS comparison artifact, so the whole CLI reads as one designed surface instead
of generic library defaults. Heavy deps (textual / InquirerPy) are imported
lazily inside the factories so importing the palette stays cheap.
"""
from __future__ import annotations

# ── palette (hex) ──────────────────────────────────────────────────────────
BRASS = "#E3A24A"   # primary / home accent
CYAN = "#5FB6C4"    # secondary
GREEN = "#6FB86F"   # success / found
HAIR = "#3A4150"    # hairline separators
INK = "#13161C"     # background
SURFACE = "#1B1F27"
PANEL = "#222732"
TEXT = "#E8EAED"
MUTED = "#868E9B"
ERROR = "#D97777"


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
