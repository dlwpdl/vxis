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


# _tui_skip_reason — surface WHY the TUI was skipped, so a silent fallback to the
# Rich display (e.g. textual missing in the uv-tool venv) never confuses again.

def test_skip_reason_none_for_no_tui():
    # --no-tui is the user's explicit choice; no warning needed.
    assert main._tui_skip_reason(False, interactive=False) is None


def test_skip_reason_none_for_interactive():
    assert main._tui_skip_reason(True, interactive=True) is None


def test_skip_reason_textual_missing(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(main, "_textual_available", lambda: False)
    reason = main._tui_skip_reason(True, interactive=False)
    assert reason and "textual" in reason.lower()


def test_skip_reason_not_a_tty(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    monkeypatch.setattr(main, "_textual_available", lambda: True)
    reason = main._tui_skip_reason(True, interactive=False)
    assert reason and ("tty" in reason.lower() or "terminal" in reason.lower())


def test_skip_reason_none_when_tui_will_launch(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(main, "_textual_available", lambda: True)
    assert main._tui_skip_reason(True, interactive=False) is None
