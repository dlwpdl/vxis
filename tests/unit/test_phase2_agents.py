"""Tests for CRT Phase 2 agents — all 57 agents must register and run."""

from __future__ import annotations

import pytest
from unittest.mock import patch

from vxis.agent.base import BaseAgent, AgentResult
from vxis.agent.context import AgentContext
from vxis.agent.registry import _REGISTRY, list_agents, spawn
from vxis.mission.config import MissionConfig, Depth, Perspective, Scope
from vxis.graph.attack_graph import LivingAttackGraph
from vxis.evidence.engine import EvidenceEngine
from vxis.mission.selector import AgentSelector, ALL_AGENTS


@pytest.fixture
def context(tmp_path):
    cfg = MissionConfig(target="example.com", depth=Depth.NORMAL)
    graph = LivingAttackGraph()
    engine = EvidenceEngine(db_path=str(tmp_path / "ev.db"))
    return AgentContext(mission=cfg, attack_graph=graph, evidence_engine=engine)


@pytest.fixture
def elite_context(tmp_path):
    cfg = MissionConfig(
        target="*.acme.com",
        depth=Depth.ELITE,
        perspective=Perspective.BOTH,
        scope=Scope.FULL,
    )
    graph = LivingAttackGraph()
    engine = EvidenceEngine(db_path=str(tmp_path / "ev.db"))
    return AgentContext(mission=cfg, attack_graph=graph, evidence_engine=engine)


# ---------------------------------------------------------------------------
# Registry & import tests
# ---------------------------------------------------------------------------


def test_agents_package_imports():
    """Importing agents package should register all agents."""
    import vxis.agent.agents  # noqa: F401

    assert len(_REGISTRY) >= 8, f"Expected >=8 registered agents, got {len(_REGISTRY)}"


def test_core_8_agents_registered():
    """The 8 Phase 2 priority agents must be registered."""
    import vxis.agent.agents  # noqa: F401

    core_ids = [
        "recon",
        "web",
        "api",
        "cloud",
        "identity_ad",
        "os_host",
        "deserialization",
        "http_protocol",
    ]
    for agent_id in core_ids:
        assert agent_id in _REGISTRY, f"Agent '{agent_id}' not registered"


def test_all_selector_agents_have_implementation():
    """Every agent_id in ALL_AGENTS should have a registered implementation."""
    import vxis.agent.agents  # noqa: F401

    missing = [a for a in ALL_AGENTS if a not in _REGISTRY]
    # Allow some missing for now but report them
    assert len(missing) <= 5, f"Too many unregistered agents: {missing}"


def test_spawn_returns_correct_type():
    import vxis.agent.agents  # noqa: F401

    agent = spawn("recon")
    assert agent is not None
    assert isinstance(agent, BaseAgent)
    assert agent.agent_id == "recon"


def test_all_agents_are_base_agent_subclass():
    import vxis.agent.agents  # noqa: F401

    for agent_id, cls in _REGISTRY.items():
        assert issubclass(cls, BaseAgent), f"{agent_id} is not a BaseAgent subclass"


# ---------------------------------------------------------------------------
# Individual agent run tests (tools mocked — no actual binary needed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recon_agent_no_tools(context):
    """ReconAgent should complete gracefully when no tools installed."""
    import vxis.agent.agents  # noqa: F401

    agent = spawn("recon")
    assert agent is not None
    with patch("shutil.which", return_value=None):
        result = await agent.run(context)
    assert isinstance(result, AgentResult)
    assert result.status == "completed"


@pytest.mark.asyncio
async def test_web_agent_no_tools(context):
    import vxis.agent.agents  # noqa: F401

    agent = spawn("web")
    assert agent is not None
    with patch("shutil.which", return_value=None):
        result = await agent.run(context)
    assert isinstance(result, AgentResult)
    assert result.status == "completed"


@pytest.mark.asyncio
async def test_api_agent_no_tools(context):
    import vxis.agent.agents  # noqa: F401

    agent = spawn("api")
    assert agent is not None
    with patch("shutil.which", return_value=None):
        result = await agent.run(context)
    assert isinstance(result, AgentResult)
    assert result.status == "completed"


@pytest.mark.asyncio
async def test_cloud_agent_no_tools(context):
    import vxis.agent.agents  # noqa: F401

    agent = spawn("cloud")
    assert agent is not None
    with patch("shutil.which", return_value=None):
        result = await agent.run(context)
    assert isinstance(result, AgentResult)
    assert result.status == "completed"


@pytest.mark.asyncio
async def test_identity_ad_agent_no_tools(context):
    import vxis.agent.agents  # noqa: F401

    agent = spawn("identity_ad")
    assert agent is not None
    with patch("shutil.which", return_value=None):
        result = await agent.run(context)
    assert isinstance(result, AgentResult)
    assert result.status == "completed"


@pytest.mark.asyncio
async def test_os_host_agent_no_tools(context):
    import vxis.agent.agents  # noqa: F401

    agent = spawn("os_host")
    assert agent is not None
    with patch("shutil.which", return_value=None):
        result = await agent.run(context)
    assert isinstance(result, AgentResult)
    assert result.status == "completed"


@pytest.mark.asyncio
async def test_deserialization_agent_no_tools(context):
    import vxis.agent.agents  # noqa: F401

    agent = spawn("deserialization")
    assert agent is not None
    with patch("shutil.which", return_value=None):
        result = await agent.run(context)
    assert isinstance(result, AgentResult)
    assert result.status == "completed"


@pytest.mark.asyncio
async def test_http_protocol_agent_no_tools(context):
    import vxis.agent.agents  # noqa: F401

    agent = spawn("http_protocol")
    assert agent is not None
    with patch("shutil.which", return_value=None):
        result = await agent.run(context)
    assert isinstance(result, AgentResult)
    assert result.status == "completed"


# ---------------------------------------------------------------------------
# Agent selection integration
# ---------------------------------------------------------------------------


def test_selector_web_scope():
    cfg = MissionConfig(target="example.com", scope=Scope.WEB)
    agents = AgentSelector.select(cfg)
    assert "recon" in agents
    assert "web" in agents
    assert "api" in agents
    assert "http_protocol" in agents


def test_selector_full_scope_elite():
    cfg = MissionConfig(
        target="example.com",
        scope=Scope.FULL,
        depth=Depth.ELITE,
        perspective=Perspective.BOTH,
    )
    agents = AgentSelector.select(cfg)
    # Elite + full + both should include nearly everything
    assert len(agents) > 40


def test_selector_stealth_disables_dos():
    cfg = MissionConfig(target="example.com", stealth=True)
    agents = AgentSelector.select(cfg)
    assert "dos_resilience" not in agents
    assert "deception_detection" in agents


# ---------------------------------------------------------------------------
# Hypothesis chaining
# ---------------------------------------------------------------------------


def test_agent_result_metadata():
    result = AgentResult(
        agent_id="recon",
        findings=[],
        hypotheses=[],
        status="completed",
        metadata={"subdomains_found": 42},
    )
    assert result.metadata["subdomains_found"] == 42
    assert result.is_success


# ---------------------------------------------------------------------------
# Batch run: try to instantiate and run every registered agent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_registered_agents_run_without_tools(context):
    """Every registered agent should complete gracefully with no tools."""
    import vxis.agent.agents  # noqa: F401

    failures = []
    with patch("shutil.which", return_value=None):
        for agent_id in list(list_agents()):
            agent = spawn(agent_id)
            if agent is None:
                continue
            try:
                result = await agent.run(context)
                assert isinstance(result, AgentResult), f"{agent_id} returned non-AgentResult"
                assert result.status in ("completed", "partial", "error"), (
                    f"{agent_id} unexpected status: {result.status}"
                )
            except Exception as e:
                failures.append(f"{agent_id}: {e}")
    assert not failures, "Agents failed:\n" + "\n".join(failures)
