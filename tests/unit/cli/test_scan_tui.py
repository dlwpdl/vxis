"""Pilot tests for the Textual scan TUI — the navigable Director/Agents tree.

Headless via App.run_test() (no real scan). Assertions lean on the model (which
drives the tree) plus the Textual Tree node structure.
"""
from textual.widgets import RichLog, Static, Tree

from vxis.cli.scan_tui import ScanTUI


async def test_feed_builds_director_iteration_tree():
    app = ScanTUI(target="http://localhost:3000", brain="together/GLM-5")
    async with app.run_test() as pilot:
        app.feed_event("brain_thinking", {
            "iteration": 1, "max_iters": 120,
            "vectors": [{"id": "web:recon", "reasoning": "map the surface"}],
        })
        app.feed_event("attack", {"vector_id": "skill:test_injection", "method": "SKILL", "endpoint": "/login"})
        app.feed_event("hit", {"vector_id": "sqli", "confidence": "critical"})
        await pilot.pause()

        # model (drives the tree): topic from the brain round's vector, finding counted
        assert app.model.iterations[0].topic == "Recon"
        assert app.model.iterations[0].found == 1

        # tree: a Director branch with one iteration leaf under it
        tree = app.query_one("#tree", Tree)
        director = tree.root.children[0]
        assert "Director" in str(director.label)
        assert len(director.children) == 1

        # detail renders the iteration's coloured timeline without error
        app._render_detail({"kind": "iter", "pos": 0})
        assert len(app.query_one("#detail", RichLog).lines) > 0

        assert "1 finding" in str(app.query_one("#status", Static).render())


async def test_control_plane_shows_nested_agent_subtree():
    app = ScanTUI(target="t")
    async with app.run_test() as pilot:
        app.feed_event("brain_thinking", {"iteration": 1, "vectors": [{"id": "web:recon", "reasoning": "a"}]})
        app.feed_event("injection_approval_result", {"decision": "readonly"})
        app.feed_event("control_plane", {"agents": [
            {"id": "director", "status": "running", "role": "director"},
            {"id": "w1", "parent_id": "director", "status": "running", "task": "skill:test_ssrf"},
            {"id": "w2", "parent_id": "director", "status": "waiting", "task": "skill:test_xss"},
        ], "telemetry": {
            "brain_decisions": 3,
            "memory_compression": {
                "last_tokens_before": 12_000,
                "last_threshold": 200_000,
                "total_tokens_saved": 1000,
            },
        }})
        await pilot.pause()

        assert {n["agent"]["id"] for n in app.model.agent_tree()} == {"director"}
        tree = app.query_one("#tree", Tree)
        # second top branch is "Agents", with the director nesting two workers
        labels = [str(c.label) for c in tree.root.children]
        assert any("Agents" in lbl for lbl in labels)
        agents_branch = [c for c in tree.root.children if "Agents" in str(c.label)][0]
        director = agents_branch.children[0]
        assert len(director.children) == 2  # w1, w2 nested under director
        status = str(app.query_one("#status", Static).render())
        assert "inject readonly" in status
        assert "ctx 12,000/200,000" in status
        assert "brain 3" in status


async def test_scan_runner_worker_drives_feed_and_marks_done():
    holder: dict = {}

    async def runner():
        app = holder["app"]
        app.thread_safe_feed("brain_thinking", {"iteration": 1, "vectors": [{"id": "skill:test_ssrf", "reasoning": "x"}]})
        app.thread_safe_feed("hit", {"vector_id": "ssrf", "confidence": "high"})

    app = ScanTUI(target="t", scan_runner=runner)
    holder["app"] = app
    async with app.run_test() as pilot:
        for _ in range(40):
            await pilot.pause(0.05)
            if app._done:
                break
        assert app.scan_error is None
        assert app._done is True
        assert app.model.iterations and app.model.iterations[0].topic == "SSRF"
        assert app.model.iterations[0].found == 1


async def test_live_updates_preserve_iteration_node_identity():
    """A burst of events must update the tree in place, not clear()+rebuild it.

    The bug: _sync() called tree.clear() on every event, so every refresh threw
    away and recreated all TreeNodes — destroying cursor/selection/expansion mid
    scan. After the fix the SAME node objects persist and only their labels move.
    """
    app = ScanTUI(target="t")
    async with app.run_test() as pilot:
        app.feed_event("brain_thinking", {"iteration": 1, "vectors": [{"id": "web:recon", "reasoning": "a"}]})
        await pilot.pause()
        tree = app.query_one("#tree", Tree)
        director_before = tree.root.children[0]
        iter_before = director_before.children[0]

        # a finding on the same iteration + a brand new iteration arrive
        app.feed_event("hit", {"vector_id": "sqli", "confidence": "high"})
        app.feed_event("brain_thinking", {"iteration": 2, "vectors": [{"id": "skill:test_ssrf", "reasoning": "b"}]})
        await pilot.pause()

        director_after = tree.root.children[0]
        assert director_after is director_before          # not rebuilt
        assert director_after.children[0] is iter_before   # same leaf object
        assert "1 found" in str(iter_before.label)         # label updated in place
        assert len(director_after.children) == 2           # new iteration appended


async def test_agent_node_updates_status_in_place():
    """An agent's status flip (running → done) reuses the same node, relabelled."""
    app = ScanTUI(target="t")
    async with app.run_test() as pilot:
        app.feed_event("control_plane", {"agents": [{"id": "w1", "status": "running", "task": "skill:test_ssrf"}]})
        await pilot.pause()
        tree = app.query_one("#tree", Tree)
        agents_branch = [c for c in tree.root.children if "Agents" in str(c.label)][0]
        w1_before = agents_branch.children[0]
        assert "running" in str(w1_before.label)

        app.feed_event("control_plane", {"agents": [{"id": "w1", "status": "done", "task": "skill:test_ssrf"}]})
        await pilot.pause()
        agents_after = [c for c in tree.root.children if "Agents" in str(c.label)][0]
        w1_after = agents_after.children[0]
        assert w1_after is w1_before        # same node, not recreated
        assert "done" in str(w1_after.label)
        # the detail pane reads node.data live — it must hold the fresh agent dict
        assert w1_after.data["agent"]["status"] == "done"


async def test_cursor_selection_survives_live_updates():
    """Moving the cursor onto a node must survive a burst of later events."""
    app = ScanTUI(target="t")
    async with app.run_test() as pilot:
        app.feed_event("brain_thinking", {"iteration": 1, "vectors": [{"id": "web:recon", "reasoning": "a"}]})
        app.feed_event("brain_thinking", {"iteration": 2, "vectors": [{"id": "skill:test_ssrf", "reasoning": "b"}]})
        await pilot.pause()
        tree = app.query_one("#tree", Tree)
        second_iter = tree.root.children[0].children[1]
        tree.move_cursor(second_iter)
        await pilot.pause()
        assert tree.cursor_node is second_iter

        app.feed_event("hit", {"vector_id": "x", "confidence": "low"})
        app.feed_event("control_plane", {"agents": [{"id": "w1", "status": "running", "task": "t"}]})
        await pilot.pause()
        assert tree.cursor_node is second_iter   # not yanked back to the root


async def test_markup_for_iteration_is_scoped_director_is_everything():
    """Drill-in scoping: an iteration node shows only its own events; the Director
    (root) node shows the whole narrative across all iterations."""
    app = ScanTUI(target="t")
    async with app.run_test() as pilot:
        app.feed_event("brain_thinking", {"iteration": 1, "vectors": [{"id": "web:recon", "reasoning": "map surface"}]})
        app.feed_event("attack", {"vector_id": "skill:test_injection", "method": "SKILL", "endpoint": "/login"})
        app.feed_event("brain_thinking", {"iteration": 2, "vectors": [{"id": "skill:test_ssrf", "reasoning": "probe ssrf"}]})
        await pilot.pause()

        iter0 = app._markup_for({"kind": "iter", "pos": 0})
        assert any("map surface" in m for m in iter0)
        assert any("SQL Injection" in m for m in iter0)
        assert not any("probe ssrf" in m for m in iter0)   # scoped to iteration 0

        everything = app._markup_for({"kind": "root"})
        assert any("map surface" in m for m in everything)
        assert any("probe ssrf" in m for m in everything)  # all iterations


async def test_detail_follows_live_then_freezes_on_drill_in():
    """The detail pane streams the narrative live (no click needed); drilling into
    a specific iteration stops the live follow and shows just that node."""
    app = ScanTUI(target="t")
    async with app.run_test() as pilot:
        detail = app.query_one("#detail", RichLog)
        app.feed_event("attack", {"vector_id": "skill:test_injection", "method": "SKILL", "endpoint": "/login"})
        await pilot.pause()
        n1 = len(detail.lines)
        app.feed_event("hit", {"vector_id": "sqli", "confidence": "high"})
        await pilot.pause()
        assert len(detail.lines) > n1            # streamed live, without any click

        app._on_node_focus({"kind": "iter", "pos": 0})  # drill in
        await pilot.pause()
        frozen = len(detail.lines)
        app.feed_event("attack", {"vector_id": "skill:test_xss", "method": "GET", "endpoint": "/s"})
        await pilot.pause()
        assert len(detail.lines) == frozen       # frozen on the drilled node


async def test_dossier_theme_and_chrome_applied():
    """The refined 'dossier' look: vxis theme, titled bordered panels, hidden root,
    and a status bar that renders (markup valid) with the brass cost segment."""
    app = ScanTUI(target="http://localhost:3000")
    async with app.run_test():
        assert app.theme == "vxis"
        tree = app.query_one("#tree", Tree)
        assert tree.show_root is False
        assert str(tree.border_title) == "SCAN TREE"
        # detail starts "DETAIL"; focusing the tree highlights the (root) Director
        # view in live-follow mode, so the title reflects the followed node.
        assert str(app.query_one("#detail", RichLog).border_title) in ("DETAIL", "DIRECTOR")
        status = str(app.query_one("#status", Static).render())
        assert "$" in status and "tok" in status  # cost segment present + markup OK


async def test_detail_border_title_follows_drilled_node():
    app = ScanTUI(target="t")
    async with app.run_test() as pilot:
        app.feed_event("brain_thinking", {"iteration": 1, "vectors": [{"id": "web:recon", "reasoning": "a"}]})
        await pilot.pause()
        app._render_detail({"kind": "iter", "pos": 0})
        assert str(app.query_one("#detail", RichLog).border_title) == "ITER 01"
        app._render_detail({"kind": "agent", "agent": {"id": "w1"}})
        assert str(app.query_one("#detail", RichLog).border_title) == "W1"


async def test_i_key_focuses_message_box():
    from textual.widgets import Input

    from vxis.agent.operator_inbox import OperatorInbox

    app = ScanTUI(target="t", operator_inbox=OperatorInbox())
    async with app.run_test() as pilot:
        await pilot.press("i")
        await pilot.pause()
        assert app.focused is app.query_one("#cmd", Input)


async def test_operator_message_queues_directive_for_the_brain():
    """Typing a directive + Enter queues it in the operator inbox (the scan loop
    drains it next iteration) and clears the input."""
    from textual.widgets import Input

    from vxis.agent.operator_inbox import OperatorInbox

    inbox = OperatorInbox()
    app = ScanTUI(target="t", operator_inbox=inbox)
    async with app.run_test() as pilot:
        await pilot.press("i")
        await pilot.pause()
        cmd = app.query_one("#cmd", Input)
        cmd.value = "focus on /admin and try JWT alg:none"
        await pilot.press("enter")
        await pilot.pause()
        assert cmd.value == ""  # cleared after send
    assert inbox.drain() == ["focus on /admin and try JWT alg:none"]


async def test_status_bar_shows_budget_spent_over_target(monkeypatch):
    monkeypatch.setenv("VXIS_SCAN_MAX_USD", "2.00")
    monkeypatch.delenv("VXIS_SCAN_MAX_TOKENS", raising=False)
    app = ScanTUI(target="t")
    async with app.run_test():
        status = str(app.query_one("#status", Static).render())
    assert "/ $2.00" in status  # spent / target rendered when a budget is set


async def test_feed_event_never_raises_on_garbage():
    app = ScanTUI(target="t")
    async with app.run_test():
        app.feed_event("brain_thinking", None)
        app.feed_event("totally_unknown", {"x": 1})
        app.feed_event("attack", {})
        app.feed_event("control_plane", {"agents": [{"no_id": 1}]})
        assert len(app.model.iterations) <= 1
        assert app.model.agent_tree() == []
