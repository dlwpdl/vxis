"""_should_use_tui — when does `vxis scan` launch the Textual TUI vs Rich Live."""
import sys

from vxis.cli import main


def test_off_when_flag_false():
    assert main._should_use_tui(False, interactive=False) is False


def test_off_when_interactive_brain():
    # --interactive owns stdin/stdout as a JSON protocol; never the TUI.
    assert main._should_use_tui(True, interactive=True) is False


def test_off_when_not_a_tty(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    assert main._should_use_tui(True, interactive=False) is False


def test_on_when_tty_and_textual(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(main, "_textual_available", lambda: True)
    assert main._should_use_tui(True, interactive=False) is True


def test_off_when_textual_missing(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(main, "_textual_available", lambda: False)
    assert main._should_use_tui(True, interactive=False) is False
