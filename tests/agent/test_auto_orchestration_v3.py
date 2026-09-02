from __future__ import annotations

import pytest

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult


class _FakeShellTool:
    name = "shell_exec"
    description = "fake shell"
    input_schema = {"type": "object", "properties": {}}

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def run(self, **kwargs):
        self.calls.append(kwargs)
        return ToolResult(ok=True, summary="ran", data={"stdout": "output"})


@pytest.mark.asyncio
async def test_dispatch_and_record_updates_v3_and_attempt_outcome(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VXIS_V3", "1")
    monkeypatch.setenv("VXIS_PTI_DIR", str(tmp_path / "pti"))
    monkeypatch.setenv("VXIS_ALLOW_ARBITRARY_EXEC", "1")

    registry = ToolRegistry()
    tool = _FakeShellTool()
    registry.register(tool)
    loop = ScanAgentLoop(target="http://localhost:3000", registry=registry, max_iters=3)
    loop.state.ensure_vector_candidate("web:dir-bruteforce", "web:dir-bruteforce", "ffuf")

    cells_before = len(loop.state.coverage_matrix.cells)

    result = await loop._dispatch_and_record(
        "shell_exec",
        {"command": "ffuf -u http://localhost:3000/FUZZ", "timeout": 60},
        candidate_id="web:dir-bruteforce",
        record_args={"command": "ffuf -u http://localhost:3000/FUZZ"},
    )

    # The tool actually dispatched and its result is returned.
    assert result.ok is True
    assert tool.calls

    # record_attempt_outcome ran (candidate attempt counted).
    assert loop.state.vector_candidates["web:dir-bruteforce"].attempts == 1

    # v3_after_action ran — the auto-fired scan is no longer blind to the
    # coverage matrix (a new cell was marked for this action).
    assert len(loop.state.coverage_matrix.cells) > cells_before


def test_auto_sqlmap_target_skips_generic_500_redirect() -> None:
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)

    target = loop._pick_auto_sqlmap_target(
        [
            {
                "title": "HTTP 500 on /redirect",
                "finding_type": "error_oracle",
                "affected_component": "http://localhost:3000/redirect",
                "evidence": "TypeError: Cannot read properties of undefined (reading 'includes')",
            }
        ]
    )

    assert target is None


def test_auto_sqlmap_target_prefers_query_surface_with_sql_signal() -> None:
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)

    target = loop._pick_auto_sqlmap_target(
        [
            {
                "title": "HTTP 500 on /redirect?url=http://example.com",
                "finding_type": "error_oracle",
                "affected_component": "http://localhost:3000/redirect?url=http://example.com",
                "evidence": "TypeError: Cannot read properties of undefined (reading 'includes')",
            },
            {
                "title": "HTTP 500 on /rest/products/search?q=test",
                "finding_type": "error_oracle",
                "affected_component": "http://localhost:3000/rest/products/search?q=test",
                "evidence": 'SequelizeDatabaseError: SQLITE_ERROR: near "\'": syntax error',
            },
        ]
    )

    assert target == "http://localhost:3000/rest/products/search?q=test"
