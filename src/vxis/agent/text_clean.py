"""Strip terminal noise — ANSI escapes (CSI/OSC/other) + C0/C1 control bytes —
from tool output before it reaches the Brain's context window or the scan TUI.

Keeps tab / newline / carriage-return. Tools like linpeas/winpeas/hexdump emit
raw cursor-movement, colour and control bytes that otherwise corrupt the RichLog
pane and pollute the LLM context. (This generalizes the colour-only scrub that
already guarded the claude-CLI input path in brain.py / brain_prompts.py.)
"""
from __future__ import annotations

import re

_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")  # OSC … BEL / ST
_ANSI_CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")          # CSI (colour, cursor, erase…)
_ANSI_ESC = re.compile(r"\x1b[@-Z\\-_]")                      # other 2-byte escapes
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")    # C0/C1 except \t \n \r


def strip_terminal_noise(text: str) -> str:
    """Return `text` with ANSI sequences and non-printing control bytes removed
    (tab/newline/carriage-return preserved). Safe on already-clean text."""
    if not text:
        return text
    text = _ANSI_OSC.sub("", text)
    text = _ANSI_CSI.sub("", text)
    text = _ANSI_ESC.sub("", text)
    return _CONTROL.sub("", text)


__all__ = ["strip_terminal_noise"]
