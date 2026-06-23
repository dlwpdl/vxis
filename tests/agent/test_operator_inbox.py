"""OperatorInbox + inject_operator_directives — mid-scan operator steering."""

from __future__ import annotations

import threading

from vxis.agent.operator_inbox import OperatorInbox, inject_operator_directives


class _FakeState:
    def __init__(self) -> None:
        self.messages: list[tuple[str, object]] = []

    def add_message(self, role: str, content: object) -> None:
        self.messages.append((role, content))


def test_submit_and_drain_fifo():
    inbox = OperatorInbox()
    assert inbox.submit("focus on /admin")
    assert inbox.submit("try JWT alg:none")
    assert len(inbox) == 2
    assert inbox.drain() == ["focus on /admin", "try JWT alg:none"]
    assert inbox.drain() == []  # drained


def test_blank_messages_dropped():
    inbox = OperatorInbox()
    assert inbox.submit("   ") is False
    assert inbox.submit("") is False
    assert len(inbox) == 0


def test_inject_appends_authoritative_user_directive():
    inbox = OperatorInbox()
    inbox.submit("stop and dump the users table")
    state = _FakeState()
    n = inject_operator_directives(state, inbox)
    assert n == 1
    role, content = state.messages[0]
    assert role == "user"
    assert content["operator_directive"] == "stop and dump the users table"
    assert "OPERATOR DIRECTIVE" in content["hint"]
    # inbox is now empty -> a second drain injects nothing
    assert inject_operator_directives(state, inbox) == 0


def test_inject_with_no_inbox_is_noop():
    state = _FakeState()
    assert inject_operator_directives(state, None) == 0
    assert state.messages == []


def test_submit_is_thread_safe():
    inbox = OperatorInbox()

    def worker(start: int) -> None:
        for i in range(100):
            inbox.submit(f"msg-{start + i}")

    threads = [threading.Thread(target=worker, args=(n * 100,)) for n in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(inbox.drain()) == 500  # no lost/duplicated under concurrency
