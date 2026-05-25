"""VXIS Agent Runner — 통합 실행 파이프라인.

Director + 63개 에이전트 + Chain Reasoner + Token Router + Knowledge Store를
하나의 실행 플로우로 연결합니다.

Usage:
    runner = AgentRunner()
    result = await runner.run("example.com", scan_type="external")
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from vxis.agent.director import DirectorAgent
from vxis.agent.context import AgentContext
from vxis.evidence.engine import EvidenceEngine
from vxis.evidence.schema import Evidence
from vxis.graph.attack_graph import LivingAttackGraph
from vxis.graph.hypothesis import HypothesisQueue
from vxis.mission.config import MissionConfig

logger = logging.getLogger(__name__)


# ── Scan type → mission mapping ─────────────────────────────────

SCAN_TYPE_MISSIONS = {
    "zero_touch": {
        "scope": "passive",
        "agents": ["recon", "email_security", "threat_intel"],
        "max_rounds": 3,
    },
    "external": {
        "scope": "external",
        "agents": [
            "recon",
            "web",
            "api",
            "crypto_tls",
            "email_security",
            "dns_deep",
            "subdomain_takeover",
            "cms_biz_platform",
        ],
        "max_rounds": 8,
    },
    "internal": {
        "scope": "internal",
        "agents": [
            "network",
            "identity_ad",
            "database",
            "container_k8s",
            "remote_access",
            "l2_network",
        ],
        "max_rounds": 8,
    },
    "code": {
        "scope": "code",
        "agents": [
            "supply_chain",
            "deserialization",
            "encoding_attack",
        ],
        "max_rounds": 5,
    },
    "cloud": {
        "scope": "cloud",
        "agents": [
            "cloud",
            "container_k8s",
            "iam_rbac",
        ],
        "max_rounds": 5,
    },
    "full": {
        "scope": "full",
        "agents": [],  # Director selects all relevant
        "max_rounds": 15,
    },
}


@dataclass
class RunnerResult:
    """통합 실행 결과."""

    target: str
    scan_type: str
    findings: list[Evidence] = field(default_factory=list)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    agents_used: list[str] = field(default_factory=list)
    agents_completed: list[str] = field(default_factory=list)
    hypotheses_explored: int = 0
    steps_taken: int = 0
    duration_seconds: float = 0.0
    token_usage: dict[str, Any] = field(default_factory=dict)
    execution_log: list[str] = field(default_factory=list)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }
        for f in self.findings:
            sev = getattr(f, "severity", None)
            if sev:
                key = sev.value if hasattr(sev, "value") else str(sev).lower()
                counts[key] = counts.get(key, 0) + 1
        return counts


class AgentRunner:
    """통합 실행 파이프라인.

    1. MissionConfig 생성
    2. AgentContext 초기화 (AttackGraph, EvidenceEngine, HypothesisQueue)
    3. DirectorAgent.run_mission() 실행
    4. 결과 수집 + Chain 리포트 생성
    """

    def __init__(
        self,
        on_status: Callable[[str, dict], None] | None = None,
    ) -> None:
        """
        Args:
            on_status: 상태 변경 콜백 (phase, details).
                       CLI 라이브 디스플레이에서 사용.
        """
        self._on_status = on_status or (lambda *_: None)

    async def run(
        self,
        target: str,
        scan_type: str = "external",
        profile: str = "standard",
        custom_agents: list[str] | None = None,
    ) -> RunnerResult:
        """통합 실행."""
        started_at = time.monotonic()

        # Load agents module to trigger @register decorators
        try:
            import vxis.agent.agents  # noqa: F401
        except Exception as exc:
            logger.warning("에이전트 로드 실패: %s", exc)

        # Step 1: Mission Config
        mission_def = SCAN_TYPE_MISSIONS.get(scan_type, SCAN_TYPE_MISSIONS["external"])
        mission = MissionConfig(
            target=target,
            scope=mission_def["scope"],
            profile=profile,
            custom_agents=custom_agents or mission_def.get("agents", []),
            max_rounds=mission_def.get("max_rounds", 10),
        )

        self._emit("초기화", {"target": target, "scan_type": scan_type})

        # Step 2: Context
        attack_graph = LivingAttackGraph()
        evidence_engine = EvidenceEngine()
        hypothesis_queue = HypothesisQueue()

        context = AgentContext(
            mission=mission,
            attack_graph=attack_graph,
            evidence_engine=evidence_engine,
            hypothesis_queue=hypothesis_queue,
        )

        # Step 3: Director
        director = DirectorAgent()

        self._emit(
            "에이전트 선택",
            {
                "agents": mission.custom_agents or [],
                "max_rounds": mission.max_rounds,
            },
        )

        # Step 4: Run mission
        log_entries: list[str] = []

        # Patch director to capture log
        original_run_agents = director._run_agents

        async def logged_run_agents(agent_ids, ctx):
            for aid in agent_ids:
                self._emit("에이전트 실행", {"agent": aid, "phase": "running"})
                log_entries.append(f"[{_now()}] 에이전트 실행: {aid}")
            await original_run_agents(agent_ids, ctx)
            for aid in agent_ids:
                self._emit("에이전트 완료", {"agent": aid, "phase": "completed"})
                log_entries.append(f"[{_now()}] 에이전트 완료: {aid}")

        director._run_agents = logged_run_agents

        try:
            self._emit("미션 시작", {"phase": "mission_start"})
            await director.run_mission(context)
            self._emit("미션 완료", {"phase": "mission_complete"})
        except Exception as exc:
            log_entries.append(f"[{_now()}] 미션 실패: {exc}")
            logger.exception("미션 실행 실패")
            self._emit("미션 실패", {"error": str(exc)})

        # Step 5: Collect results
        duration = time.monotonic() - started_at

        # Get chain report
        director.get_chain_report()
        attack_chains = []
        if director._chain_reasoner:
            try:
                attack_chains = [
                    {"title": c.title, "severity": c.severity, "steps": len(c.links)}
                    for c in director._chain_reasoner.get_confirmed_chains()
                ]
            except Exception:
                pass

        # Token usage
        token_usage = {}
        if director._token_router:
            try:
                token_usage = director._token_router.get_usage_stats()
            except Exception:
                pass

        all_findings = evidence_engine.get_all() if hasattr(evidence_engine, "get_all") else []

        result = RunnerResult(
            target=target,
            scan_type=scan_type,
            findings=all_findings,
            attack_chains=attack_chains,
            agents_used=list(director._active_agents),
            agents_completed=list(director._completed_agents),
            hypotheses_explored=director.hypothesis_queue.total_processed
            if hasattr(director.hypothesis_queue, "total_processed")
            else 0,
            steps_taken=len(log_entries),
            duration_seconds=duration,
            token_usage=token_usage,
            execution_log=log_entries,
        )

        # Log summary
        logger.info(
            "미션 완료: %d건 발견, %d개 에이전트, %d개 체인, %.0f초",
            len(result.findings),
            len(result.agents_completed),
            len(result.attack_chains),
            duration,
        )

        return result

    def _emit(self, phase: str, details: dict) -> None:
        """상태 변경 이벤트 발생."""
        try:
            self._on_status(phase, details)
        except Exception:
            pass


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")
