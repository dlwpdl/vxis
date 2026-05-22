import pytest
from unittest.mock import MagicMock, AsyncMock
import asyncio

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.agent.tools.finding_tools import (
    ReportFindingTool,
    _reset_for_tests as _reset_findings,
)


class EchoTool:
    name = "echo"
    description = "echo back"
    input_schema = {"type": "object"}

    async def run(self, **kw) -> ToolResult:
        return ToolResult(ok=True, summary="echoed", data=kw)


class FinishTool:
    name = "finish_scan"
    description = "end scan"
    input_schema = {"type": "object"}

    async def run(self, **kw) -> ToolResult:
        return ToolResult(ok=True, summary="done")


@pytest.fixture(autouse=True)
def _isolate_findings():
    _reset_findings()
    yield
    _reset_findings()


@pytest.mark.asyncio
async def test_brain_drives_loop_via_think_in_loop():
    """Brain drives loop via think_in_loop; Q11 requires ≥1 finding before
    finish_scan can complete, and the min_iters guard requires iter ≥
    max_iters//2 (= 2 here). Sequence: echo → report_finding → finish_scan
    rejected (iter 3, but actually iter < min_iters? min=2, iter 3 ≥ 2 so
    passes min_iters; 1 finding so passes 0-finding gate; chains check
    skipped for <3 findings) → completes.
    """
    reg = ToolRegistry()
    reg.register(EchoTool())
    reg.register(FinishTool())
    reg.register(ReportFindingTool())

    fake_brain = MagicMock()
    fake_brain.think_in_loop = AsyncMock(side_effect=[
        [("echo", {"msg": "hello"})],
        [("report_finding", {
            "title": "stub", "severity": "low", "finding_type": "test_stub",
            "affected_component": "/x", "description": "fixture",
        })],
        [("finish_scan", {})],
    ])

    loop = ScanAgentLoop(target="http://x", registry=reg, max_iters=5, brain=fake_brain)
    result = await loop.run()

    assert result["completed"] is True
    assert fake_brain.think_in_loop.await_count == 3
    first_call_args = fake_brain.think_in_loop.await_args_list[0].args
    messages_arg = first_call_args[0]
    tools_arg = first_call_args[1]
    assert isinstance(messages_arg, list) and len(messages_arg) > 0
    assert any(t["name"] == "echo" for t in tools_arg)
    assert any(t["name"] == "finish_scan" for t in tools_arg)


@pytest.mark.asyncio
async def test_think_in_loop_returns_parsed_actions_from_real_brain(monkeypatch):
    from vxis.agent.brain import AgentBrain, get_brain_decision_count, reset_brain_decision_count

    reset_brain_decision_count()

    brain = AgentBrain()
    fake_llm_response = (
        '```json\n'
        '{"reasoning": "map first", "actions": [{"tool": "cpr_recon", "args": {"depth": 2}, '
        '"reasoning": "map attack surface", "priority": "high"}]}\n'
        '```'
    )
    monkeypatch.setattr(brain, "_call_llm_with_fallback", lambda s, u, **kw: fake_llm_response)

    messages = [
        {"role": "system", "content": "Scan started"},
        {"role": "user", "content": "Target: http://example.com"},
    ]
    tool_catalog = [
        {"name": "cpr_recon", "description": "map endpoints + subdomains", "input_schema": {"type": "object"}},
        {"name": "finish_scan", "description": "end scan", "input_schema": {"type": "object"}},
    ]

    actions = await brain.think_in_loop(messages, tool_catalog)

    assert len(actions) == 1
    assert actions[0] == ("cpr_recon", {"depth": 2})
    assert get_brain_decision_count() == 1


@pytest.mark.asyncio
async def test_think_in_loop_injects_operator_instructions(monkeypatch):
    from vxis.agent.brain import AgentBrain

    brain = AgentBrain(provider="openai", model="gpt-5.4")
    captured: dict[str, str] = {}

    def fake_call(system: str, user: str, **kwargs) -> str:
        captured["user"] = user
        return (
            '```json\n'
            '{"reasoning":"follow operator scope","actions":[{"tool":"echo",'
            '"args":{"msg":"ok"},"reasoning":"instruction honored","priority":"high"}]}\n'
            '```'
        )

    monkeypatch.setenv("VXIS_SCAN_INSTRUCTIONS", "Focus on IDOR. Exclude /admin.")
    monkeypatch.setattr(brain, "_call_llm_with_fallback", fake_call)

    actions = await brain.think_in_loop(
        [{"role": "user", "content": "Target: http://example.com"}],
        [{"name": "echo", "description": "echo back", "input_schema": {"type": "object"}}],
    )

    assert actions == [("echo", {"msg": "ok"})]
    assert "## Operator instructions" in captured["user"]
    assert "Focus on IDOR. Exclude /admin." in captured["user"]


@pytest.mark.asyncio
async def test_think_in_loop_injects_director_protocol_memory(monkeypatch):
    from vxis.agent.brain import AgentBrain

    brain = AgentBrain(provider="openai", model="gpt-5.4")
    captured: dict[str, str] = {}

    def fake_call(system: str, user: str, **kwargs) -> str:
        captured["user"] = user
        return (
            '```json\n'
            '{"reasoning":"keep chaining","actions":[{"tool":"agent_graph",'
            '"args":{"task":"verify IDOR with replay evidence"},'
            '"reasoning":"bounded worker proof","priority":"high"}]}\n'
            '```'
        )

    monkeypatch.delenv("VXIS_SCAN_INSTRUCTIONS", raising=False)
    monkeypatch.setattr(brain, "_call_llm_with_fallback", fake_call)

    actions = await brain.think_in_loop(
        [{"role": "user", "content": "Target: http://example.com"}],
        [{"name": "agent_graph", "description": "spawn worker", "input_schema": {"type": "object"}}],
    )

    assert actions[0][0] == "agent_graph"
    assert "## Director protocol" in captured["user"]
    assert "Send task -> run worker/tool -> read evidence -> finish/send sharper task" in captured["user"]
    assert "Positive worker result must spawn post_exploit_worker" in captured["user"]


@pytest.mark.asyncio
async def test_think_in_loop_injects_specialist_skill_context(monkeypatch):
    from vxis.agent.brain import AgentBrain

    brain = AgentBrain(provider="openai", model="gpt-5.4")
    captured: dict[str, str] = {}

    def fake_call(system: str, user: str, **kwargs) -> str:
        captured["user"] = user
        return (
            '```json\n'
            '{"reasoning":"use idor context","actions":[{"tool":"run_skill",'
            '"args":{"skill":"test_idor","target_url":"http://example.com","params":{}},'
            '"reasoning":"worker card points at IDOR","priority":"high"}]}\n'
            '```'
        )

    monkeypatch.setattr(brain, "_call_llm_with_fallback", fake_call)

    actions = await brain.think_in_loop(
        [{"role": "user", "content": "Need to validate IDOR on /api/users/{id}"}],
        [{"name": "run_skill", "description": "run skill", "input_schema": {"type": "object"}}],
    )

    assert actions[0][0] == "run_skill"
    assert "## Specialist skill context" in captured["user"]
    assert "test_idor" in captured["user"]
    assert "Require a control" in captured["user"]


@pytest.mark.asyncio
async def test_think_in_loop_recovers_registered_browser_tool_from_malformed_json(monkeypatch):
    from vxis.agent.brain import AgentBrain

    brain = AgentBrain()
    fake_llm_response = (
        '```json\n'
        '{"reasoning":"render first","actions":[{"tool":"browser_navigate",'
        '"args":{"url":"http://example.test/login",},'
        '"reasoning":"need rendered forms","priority":"high"}]}\n'
        '```'
    )
    monkeypatch.setattr(brain, "_call_llm_with_fallback", lambda s, u, **kw: fake_llm_response)

    actions = await brain.think_in_loop(
        [{"role": "user", "content": "Target: http://example.test"}],
        [
            {
                "name": "browser_navigate",
                "description": "rendered navigation",
                "input_schema": {"type": "object"},
            },
            {"name": "finish_scan", "description": "end", "input_schema": {"type": "object"}},
        ],
    )

    assert actions == [("browser_navigate", {"url": "http://example.test/login"})]


@pytest.mark.asyncio
async def test_think_in_loop_recovers_run_skill_nested_args_from_malformed_json(monkeypatch):
    from vxis.agent.brain import AgentBrain

    brain = AgentBrain()
    fake_llm_response = (
        '{"reasoning":"try focused template","actions":[{"tool":"run_skill",'
        '"args":{"skill":"test_auth_deep","target_url":"http://target.local",'
        '"params":{"login_path":"/login","depth":2}},'
        '"reasoning":"auth lead","priority":"high"}],}'
    )
    monkeypatch.setattr(brain, "_call_llm_with_fallback", lambda s, u, **kw: fake_llm_response)

    actions = await brain.think_in_loop(
        [{"role": "user", "content": "Target: http://target.local"}],
        [
            {"name": "run_skill", "description": "skill runner", "input_schema": {"type": "object"}},
            {"name": "finish_scan", "description": "end", "input_schema": {"type": "object"}},
        ],
    )

    assert actions == [
        (
            "run_skill",
            {
                "skill": "test_auth_deep",
                "target_url": "http://target.local",
                "params": {"login_path": "/login", "depth": 2},
            },
        )
    ]


@pytest.mark.asyncio
async def test_think_in_loop_filters_hallucinated_tools(monkeypatch):
    from vxis.agent.brain import AgentBrain

    brain = AgentBrain()
    fake_llm_response = (
        '{"actions":['
        '{"tool":"made_up_scan","args":{"url":"http://x"}},'
        '{"tool":"finish_scan","args":{}}'
        ']}'
    )
    monkeypatch.setattr(brain, "_call_llm_with_fallback", lambda s, u, **kw: fake_llm_response)

    actions = await brain.think_in_loop(
        [{"role": "user", "content": "Target: http://x"}],
        [{"name": "finish_scan", "description": "end", "input_schema": {"type": "object"}}],
    )

    assert actions == [("finish_scan", {})]


def test_think_in_loop_adapter_concatenation_no_brace_explosion():
    from vxis.agent.brain import LOOP_PROMPT_ADAPTER, AGENT_SYSTEM_PROMPT

    body = AGENT_SYSTEM_PROMPT.format(available_tools="  - test_tool: test description")
    full = LOOP_PROMPT_ADAPTER + "\n" + body

    # Phase B rewrote the adapter from a thin "ADAPTER INSTRUCTIONS / STRIX-STYLE
    # ADAPTER" header into a full HOW-TO-THINK guide. "STRIX-STYLE ADAPTER" no
    # longer appears; assert on the actual section header present instead.
    assert "HOW TO THINK" in full
    # Authorization preamble survives the rewrite.
    assert "Authorization confirmed" in full

    # No brace explosion — AGENT_SYSTEM_PROMPT.format() must not raise KeyError.
    # The adapter is a raw string so its JSON-example braces are literals, not
    # format placeholders.  Only check that the adapter itself has no {{ or }}
    # (which would indicate accidental double-escaping in the raw string).
    assert "{{" not in LOOP_PROMPT_ADAPTER
    # AGENT_SYSTEM_PROMPT has {available_tools} filled above — confirm no
    # unfilled placeholders remain in the body.
    assert "{available_tools}" not in body

    assert "Controller" in full
    # Phase B: adapter upgraded to prefer shell_exec (real sqlmap/nuclei/ffuf)
    # over the hypothetical cpr_recon tool that was never implemented.
    assert "shell_exec" in full
    # link_chain is surfaced via the adapter's FINDING REPORT FORMAT section.
    assert "link_chain" in full


def test_think_in_loop_trims_history_for_small_llamacpp_context(monkeypatch):
    from vxis.agent.brain import AgentBrain

    monkeypatch.setenv("VXIS_LLAMACPP_CONTEXT", "8192")

    brain = AgentBrain(
        provider="llamacpp",
        model="huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-q4_k_m",
    )

    captured: dict[str, str] = {}

    def fake_llm(system: str, user: str, **kwargs) -> str:
        captured["system"] = system
        captured["user"] = user
        return (
            '```json\n'
            '{"reasoning":"trimmed","actions":[{"tool":"finish_scan","args":{},"reasoning":"done","priority":"low"}]}\n'
            '```'
        )

    monkeypatch.setattr(brain, "_call_llm_with_fallback", fake_llm)

    messages = [
        {"role": "system", "content": "Scan started", "iter": 0},
    ]
    for i in range(1, 140):
        messages.append(
            {
                "role": "user",
                "content": (
                    f"Iteration {i} " + ("A" * 1400)
                ),
                "iter": i,
            }
        )

    tool_catalog = [
        {"name": "finish_scan", "description": "end scan", "input_schema": {"type": "object"}},
    ]

    actions = asyncio.run(brain.think_in_loop(messages, tool_catalog))

    assert actions == [("finish_scan", {})]
    assert "PROMPT-BUDGET COMPACTION" in captured["user"]
    prompt_tokens = (len(captured["system"]) + len(captured["user"])) // 4
    assert prompt_tokens < 8192


def test_think_in_loop_uses_compact_prompt_for_small_local_context(monkeypatch):
    from vxis.agent.brain import AgentBrain

    monkeypatch.setenv("VXIS_LLAMACPP_CONTEXT", "8192")

    brain = AgentBrain(
        provider="llamacpp",
        model="huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-q4_k_m",
    )

    captured: dict[str, str] = {}

    def fake_llm(system: str, user: str, **kwargs) -> str:
        captured["system"] = system
        captured["user"] = user
        return (
            '```json\n'
            '{"reasoning":"compact","actions":[{"tool":"finish_scan","args":{},"reasoning":"done","priority":"low"}]}\n'
            '```'
        )

    monkeypatch.setattr(brain, "_call_llm_with_fallback", fake_llm)

    messages = [{"role": "system", "content": "Scan started", "iter": 0}]
    tool_catalog = [
        {
            "name": "finish_scan",
            "description": "Finish the scan after all credible attack families are exhausted and the final report can be generated safely.",
            "input_schema": {"type": "object"},
        },
    ]

    actions = asyncio.run(brain.think_in_loop(messages, tool_catalog))

    assert actions == [("finish_scan", {})]
    assert "autonomous pentest operator" in captured["system"]
    assert "OWASP Top 10" not in captured["system"]
    assert "Bug bounty hunters spend days on one target" not in captured["system"]
    assert "## Director protocol" in captured["user"]
    assert "keep one active proof path" in captured["user"]
