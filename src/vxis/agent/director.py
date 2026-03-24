from __future__ import annotations
import asyncio
from typing import Optional
from .base import BaseAgent, AgentResult
from .context import AgentContext
from .registry import spawn
from ..graph.hypothesis import HypothesisQueue, HypothesisGenerator
from ..evidence.schema import Evidence
from ..evidence.engine import EvidenceEngine
from ..mission.config import MissionConfig
from ..mission.selector import AgentSelector


class DirectorAgent:
    """
    전략적 판단 + 에이전트 동적 스폰.
    발견물 통합 → Attack Graph 업데이트 → 새 가설 생성 → 에이전트 재투입.
    """

    def __init__(self) -> None:
        self.hypothesis_queue = HypothesisQueue()
        self._active_agents: set[str] = set()

    def select_initial_agents(self, mission: MissionConfig) -> list[str]:
        return AgentSelector.select(mission)

    async def integrate_finding(
        self,
        evidence: Evidence,
        context: AgentContext,
    ) -> None:
        """발견물을 Attack Graph에 통합 + 새 가설 생성."""
        await context.evidence_engine.save(evidence)
        context.attack_graph.add_finding(evidence)

        new_hypotheses = HypothesisGenerator.from_finding(evidence)
        for h in new_hypotheses:
            self.hypothesis_queue.push(h)

    async def run_mission(self, context: AgentContext) -> None:
        """전체 미션 루프."""
        initial_agent_ids = self.select_initial_agents(context.mission)
        await self._run_agents(initial_agent_ids, context)

        while self.hypothesis_queue.size() > 0:
            hypothesis = self.hypothesis_queue.pop()
            if hypothesis and hypothesis.suggested_agent:
                await self._run_agents(
                    [hypothesis.suggested_agent], context
                )

    async def _run_agents(
        self,
        agent_ids: list[str],
        context: AgentContext,
    ) -> None:
        tasks = []
        for agent_id in agent_ids:
            if agent_id in self._active_agents:
                continue
            agent = spawn(agent_id)
            if agent:
                self._active_agents.add(agent_id)
                tasks.append(self._run_single(agent, context))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, AgentResult):
                    for finding in result.findings:
                        await self.integrate_finding(finding, context)

    async def _run_single(
        self,
        agent: BaseAgent,
        context: AgentContext,
    ) -> AgentResult:
        try:
            return await agent.run(context)
        except Exception as e:
            return AgentResult(
                agent_id=agent.agent_id,
                findings=[],
                hypotheses=[],
                status="error",
                error=str(e),
            )
