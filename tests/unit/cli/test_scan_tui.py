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
        app.feed_event("control_plane", {"agents": [
            {"id": "director", "status": "running", "role": "director"},
            {"id": "w1", "parent_id": "director", "status": "running", "task": "skill:test_ssrf"},
            {"id": "w2", "parent_id": "director", "status": "waiting", "task": "skill:test_xss"},
        ]})
        await pilot.pause()

        assert {n["agent"]["id"] for n in app.model.agent_tree()} == {"director"}
        tree = app.query_one("#tree", Tree)
        # second top branch is "Agents", with the director nesting two workers
        labels = [str(c.label) for c in tree.root.children]
        assert any("Agents" in lbl for lbl in labels)
        agents_branch = [c for c in tree.root.children if "Agents" in str(c.label)][0]
        director = agents_branch.children[0]
        assert len(director.children) == 2  # w1, w2 nested under director


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


async def test_feed_event_never_raises_on_garbage():
    app = ScanTUI(target="t")
    async with app.run_test():
        app.feed_event("brain_thinking", None)
        app.feed_event("totally_unknown", {"x": 1})
        app.feed_event("attack", {})
        app.feed_event("control_plane", {"agents": [{"no_id": 1}]})
        assert len(app.model.iterations) <= 1
        assert app.model.agent_tree() == []
