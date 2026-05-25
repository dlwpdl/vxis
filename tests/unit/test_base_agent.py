import pytest
from vxis.agent.base import BaseAgent, AgentResult
from vxis.agent.context import AgentContext
from vxis.mission.config import MissionConfig
from vxis.graph.attack_graph import LivingAttackGraph
from vxis.evidence.engine import EvidenceEngine


class ConcreteAgent(BaseAgent):
    agent_id = "test_agent"
    description = "Test agent"

    async def run(self, context: AgentContext) -> AgentResult:
        return AgentResult(
            agent_id=self.agent_id,
            findings=[],
            hypotheses=[],
            status="completed",
        )


@pytest.fixture
def context(tmp_path):
    cfg = MissionConfig(target="example.com")
    graph = LivingAttackGraph()
    engine = EvidenceEngine(db_path=str(tmp_path / "ev.db"))
    return AgentContext(
        mission=cfg,
        attack_graph=graph,
        evidence_engine=engine,
    )


def test_agent_has_required_attributes():
    agent = ConcreteAgent()
    assert agent.agent_id == "test_agent"
    assert agent.description == "Test agent"


@pytest.mark.asyncio
async def test_agent_run_returns_result(context):
    agent = ConcreteAgent()
    result = await agent.run(context)
    assert result.agent_id == "test_agent"
    assert result.status == "completed"


def test_agent_result_structure():
    result = AgentResult(
        agent_id="web",
        findings=[],
        hypotheses=[],
        status="completed",
        error=None,
    )
    assert result.is_success
