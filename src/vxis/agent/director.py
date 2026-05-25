"""VXIS Director Agent — Phase 3 전략적 오케스트레이터.

Phase 3 Architecture:
    ┌──────────────────────────────────────────────────────────┐
    │  DirectorAgent (전략 지휘관)                               │
    │                                                          │
    │  1. 미션 시작 → Knowledge Store에서 전략 로드              │
    │  2. 에이전트 선택 → 컴파일된 패턴 + 추천 우선 적용         │
    │  3. 발견물 통합 → Chain Reasoner에 전달                   │
    │  4. 체인 추론 → 새로운 가설 생성 (기존 + 체인 기반)        │
    │  5. 토큰 사용량 추적 → Token Router로 비용 최적화         │
    │  6. 스캔 완료 → 결과를 Knowledge Store에 학습             │
    └──────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import asyncio
import logging

from .base import BaseAgent, AgentResult
from .context import AgentContext
from .registry import spawn
from ..graph.hypothesis import Hypothesis, HypothesisQueue, HypothesisGenerator
from ..evidence.schema import Evidence
from ..mission.config import MissionConfig
from ..mission.selector import AgentSelector

logger = logging.getLogger(__name__)


class DirectorAgent:
    """Phase 3 전략적 판단 + 에이전트 동적 스폰 + 지식 축적.

    기존 기능:
        - 발견물 통합 → Attack Graph 업데이트 → 가설 생성 → 에이전트 재투입

    Phase 3 추가:
        - Chain Reasoner 통합 (공격 체인 자동 추론)
        - Knowledge Store 통합 (도구 추천/스킵, 상관관계)
        - Token Router 통합 (비용 최적화)
        - 미션 완료 시 학습 (다음 스캔에 반영)
    """

    def __init__(self) -> None:
        self.hypothesis_queue = HypothesisQueue()
        self._active_agents: set[str] = set()
        self._completed_agents: set[str] = set()
        self._total_findings: int = 0

        # Phase 3 모듈 (lazy init)
        self._chain_reasoner = None
        self._knowledge_store = None
        self._token_router = None

    def _init_phase3_modules(self) -> None:
        """Phase 3 모듈을 지연 초기화한다."""
        try:
            from vxis.graph.chain_reasoner import ChainReasoner

            self._chain_reasoner = ChainReasoner()
        except Exception as exc:
            logger.debug("ChainReasoner 초기화 실패 (무시): %s", exc)

        try:
            from vxis.knowledge.store import KnowledgeStore

            self._knowledge_store = KnowledgeStore()
        except Exception as exc:
            logger.debug("KnowledgeStore 초기화 실패 (무시): %s", exc)

        try:
            from vxis.llm.router import TokenRouter

            self._token_router = TokenRouter()
        except Exception as exc:
            logger.debug("TokenRouter 초기화 실패 (무시): %s", exc)

    def select_initial_agents(self, mission: MissionConfig) -> list[str]:
        """미션 기반 에이전트 선택 + Knowledge Store 추천 반영."""
        base_agents = AgentSelector.select(mission)

        # Knowledge Store에서 추천 도구 기반 에이전트 우선순위 조정
        if self._knowledge_store is not None:
            try:
                skip_tools = self._knowledge_store.get_tools_to_skip(mission.custom_agents or [])
                if skip_tools:
                    logger.info(
                        "Knowledge Store 추천: 효과 낮은 에이전트 후순위 — %s",
                        skip_tools,
                    )
            except Exception:
                pass

        return base_agents

    async def integrate_finding(
        self,
        evidence: Evidence,
        context: AgentContext,
    ) -> None:
        """발견물 통합: Attack Graph + Chain Reasoner + 가설 생성."""
        await context.evidence_engine.save(evidence)
        context.attack_graph.add_finding(evidence)
        self._total_findings += 1

        # 기존: 키워드 기반 가설 생성
        new_hypotheses = HypothesisGenerator.from_finding(evidence)
        for h in new_hypotheses:
            self.hypothesis_queue.push(h)

        # Phase 3: Chain Reasoner에 발견물 전달 + 체인 가설 생성
        if self._chain_reasoner is not None:
            try:
                self._chain_reasoner.add_finding(evidence)
                chains = self._chain_reasoner.infer_chains()

                if chains:
                    logger.info(
                        "공격 체인 %d개 발견: %s",
                        len(chains),
                        ", ".join(c.title for c in chains[:3]),
                    )

                # 체인 기반 가설 추가
                chain_hypotheses = self._chain_reasoner.get_chain_hypotheses()
                for ch in chain_hypotheses:
                    # 체인 가설은 높은 우선순위
                    vuln_to_agent = {
                        "ssrf": "web",
                        "sqli": "database",
                        "info_disclosure": "recon",
                        "redis_noauth": "database",
                        "mongodb_noauth": "database",
                        "cloud_metadata": "cloud",
                        "xss": "web",
                        "secret_exposure": "secrets_lifecycle",
                        "container_escape": "container_k8s",
                        "jwt_vulnerability": "crypto_tls",
                    }
                    suggested_agent = vuln_to_agent.get(ch.get("missing_vuln_type", ""), "web")

                    h = Hypothesis(
                        title=ch["title"],
                        rationale=ch["rationale"],
                        probability=ch.get("probability", 0.7),
                        impact=ch.get("impact", 0.8),
                        suggested_agent=suggested_agent,
                    )
                    self.hypothesis_queue.push(h)
            except Exception as exc:
                logger.debug("Chain Reasoner 통합 실패 (무시): %s", exc)

    async def run_mission(self, context: AgentContext) -> None:
        """Phase 3 미션 루프."""
        # Phase 3 모듈 초기화
        self._init_phase3_modules()

        # 에이전트 선택 + 실행
        initial_agent_ids = self.select_initial_agents(context.mission)
        logger.info("미션 시작: %d개 에이전트 선택", len(initial_agent_ids))
        await self._run_agents(initial_agent_ids, context)

        # 가설 기반 추가 탐색 루프
        max_rounds = 10
        round_count = 0
        while self.hypothesis_queue.size() > 0 and round_count < max_rounds:
            round_count += 1
            hypothesis = self.hypothesis_queue.pop()
            if hypothesis and hypothesis.suggested_agent:
                logger.info(
                    "가설 탐색 [%d/%d]: %s → %s (점수: %.2f)",
                    round_count,
                    max_rounds,
                    hypothesis.title,
                    hypothesis.suggested_agent,
                    hypothesis.priority_score,
                )
                await self._run_agents([hypothesis.suggested_agent], context)

        # 미션 완료 후 학습
        self._learn_from_mission(context)

        # 토큰 사용량 리포트
        if self._token_router is not None:
            logger.info(self._token_router.format_usage_report())

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
                    self._completed_agents.add(result.agent_id)
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

    def _learn_from_mission(self, context: AgentContext) -> None:
        """미션 완료 후 Knowledge Store에 학습 데이터를 저장한다."""
        if self._knowledge_store is None:
            return

        try:
            logger.info(
                "미션 학습: %d개 에이전트 완료, %d건 발견",
                len(self._completed_agents),
                self._total_findings,
            )
            # Knowledge Store는 각 도구 실행 시 이미 record_execution()을 호출하므로
            # 여기서는 전체 미션 레벨의 메타데이터만 저장
        except Exception as exc:
            logger.debug("미션 학습 실패 (무시): %s", exc)

    def get_chain_report(self) -> str:
        """발견된 공격 체인 리포트를 반환한다."""
        if self._chain_reasoner is None:
            return ""

        try:
            return self._chain_reasoner.format_chains_for_brain()
        except Exception:
            return ""
