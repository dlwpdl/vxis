import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from vxis.agent.director import DirectorAgent
from vxis.agent.context import AgentContext
from vxis.agent.base import AgentResult
from vxis.mission.config import MissionConfig, Depth
from vxis.graph.attack_graph import LivingAttackGraph
from vxis.evidence.engine import EvidenceEngine
from vxis.evidence.schema import Evidence, Severity, EvidenceType


@pytest.fixture
def context(tmp_path):
    cfg = MissionConfig(target="example.com", depth=Depth.NORMAL)
    graph = LivingAttackGraph()
    engine = EvidenceEngine(db_path=str(tmp_path / "ev.db"))
    return AgentContext(mission=cfg, attack_graph=graph, evidence_engine=engine)


@pytest.mark.asyncio
async def test_director_integrates_finding(context, tmp_path):
    await context.evidence_engine.init()
    director = DirectorAgent()

    ev = Evidence(
        agent_id="cloud",
        title="s3 bucket public",
        severity=Severity.HIGH,
        evidence_type=EvidenceType.MISCONFIGURATION,
        description="S3 bucket is public",
    )
    await director.integrate_finding(ev, context)

    summary = context.attack_graph.summary()
    assert summary["total_findings"] == 1
    assert summary["high"] == 1


@pytest.mark.asyncio
async def test_director_spawns_hypotheses_on_finding(context, tmp_path):
    await context.evidence_engine.init()
    director = DirectorAgent()

    ev = Evidence(
        agent_id="cloud",
        title="s3 bucket with credential files",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.SECRET,
        description="credential found in s3",
    )
    await director.integrate_finding(ev, context)

    assert director.hypothesis_queue.size() >= 1


def test_director_select_agents(context):
    director = DirectorAgent()
    agents = director.select_initial_agents(context.mission)
    assert len(agents) > 0
