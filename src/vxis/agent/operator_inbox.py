"""Mid-scan operator → Brain steering channel (Strix-style interactive control).

The scan runs in a worker thread while the TUI runs on the UI thread. The
operator types a directive in the TUI; it lands in a thread-safe inbox; the scan
loop drains the inbox at the start of each iteration and injects each directive
into the Brain's message history as authoritative human steering — so the Brain
folds it into its very next decision (pivot, focus, stop, "try X on /admin").
"""
from __future__ import annotations

import threading
from typing import Any, Protocol


class _MessageState(Protocol):
    def add_message(self, role: str, content: Any) -> Any: ...


class OperatorInbox:
    """Thread-safe queue of operator directives. submit() from the UI thread,
    drain() from the scan-loop thread. Blank messages are dropped."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: list[str] = []

    def submit(self, text: str) -> bool:
        """Queue a directive. Returns True if accepted (non-blank)."""
        cleaned = (text or "").strip()
        if not cleaned:
            return False
        with self._lock:
            self._pending.append(cleaned)
        return True

    def drain(self) -> list[str]:
        """Atomically take and clear all pending directives (FIFO)."""
        with self._lock:
            taken, self._pending = self._pending, []
        return taken

    def __len__(self) -> int:
        with self._lock:
            return len(self._pending)


def inject_operator_directives(state: _MessageState, inbox: OperatorInbox | None) -> int:
    """Drain `inbox` and append each directive to the Brain history as an
    authoritative operator instruction. Returns the number injected (0 if none /
    no inbox). Called at the top of each scan-loop iteration."""
    if inbox is None:
        return 0
    directives = inbox.drain()
    for directive in directives:
        state.add_message(
            "user",
            {
                "operator_directive": directive,
                "hint": (
                    "OPERATOR DIRECTIVE — authoritative live instruction from the "
                    "human operator. Prioritize it over your current plan: "
                    + directive
                ),
            },
        )
    return len(directives)


__all__ = ["OperatorInbox", "inject_operator_directives"]
