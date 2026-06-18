"""Pilot tests for the Textual scan TUI — feed events, assert the iteration tree
+ detail pane + status update. Headless via App.run_test() (no real scan)."""
from textual.widgets import ListView, RichLog, Static

from vxis.cli.scan_tui import ScanTUI


async def test_feed_events_build_iteration_tree_and_detail():
    app = ScanTUI(target="http://localhost:3000", brain="gemini/gemini-2.5-flash")
    async with app.run_test() as pilot:
        app.feed_event("brain_thinking", {
            "iteration": 1, "max_iters": 120,
            "vectors": [{"id": "web:recon", "reasoning": "map the surface"}],
        })
        app.feed_event("attack", {"vector_id": "skill:sqli", "method": "SKILL", "endpoint": "/rest/user/login"})
        app.feed_event("hit", {"vector_id": "sqli", "confidence": "critical"})
        await pilot.pause()

        lv = app.query_one("#iters", ListView)
        assert len(lv) == 1                          # one Brain round → one node
        assert app.model.iterations[0].topic == "web:recon"
        assert app.model.iterations[0].found == 1

        # detail pane rendered the current iteration's coloured timeline
        detail = app.query_one("#detail", RichLog)
        assert len(detail.lines) > 0

        # status bar reflects the finding count
        status = app.query_one("#status", Static)
        assert "1 finding" in str(status.render())


async def test_second_brain_round_adds_a_second_node():
    app = ScanTUI(target="t")
    async with app.run_test() as pilot:
        app.feed_event("brain_thinking", {"iteration": 1, "vectors": [{"id": "v1", "reasoning": "a"}]})
        app.feed_event("brain_thinking", {"iteration": 2, "vectors": [{"id": "v2", "reasoning": "b"}]})
        await pilot.pause()
        assert len(app.query_one("#iters", ListView)) == 2
        assert [it.topic for it in app.model.iterations] == ["v1", "v2"]


async def test_feed_event_never_raises_on_garbage():
    app = ScanTUI(target="t")
    async with app.run_test():
        app.feed_event("brain_thinking", None)
        app.feed_event("totally_unknown", {"x": 1})
        app.feed_event("attack", {})  # missing keys
        # no exception, no spurious iterations from unknown/None
        assert len(app.model.iterations) <= 1
