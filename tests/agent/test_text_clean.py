"""strip_terminal_noise — scrub ANSI / control bytes from tool output."""

from __future__ import annotations

from vxis.agent.text_clean import strip_terminal_noise


def test_strips_colour_ansi():
    assert strip_terminal_noise("\x1b[31mRED\x1b[0m text") == "RED text"


def test_strips_cursor_and_osc():
    # clear-screen, home, and an OSC window-title sequence all vanish
    assert strip_terminal_noise("\x1b[2J\x1b[H\x1b]0;title\x07done") == "done"


def test_strips_control_bytes_keeps_whitespace():
    assert strip_terminal_noise("a\x00b\x07c\td\ne\rf") == "abc\td\ne\rf"


def test_passthrough_plain_text():
    plain = "plain output\nline2\t tabbed\r"
    assert strip_terminal_noise(plain) == plain


def test_empty_and_none_safe():
    assert strip_terminal_noise("") == ""
    assert strip_terminal_noise(None) is None
