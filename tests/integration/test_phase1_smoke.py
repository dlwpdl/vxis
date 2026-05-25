"""
Phase 1 전체 통합 테스트.
Director → Attack Graph → Evidence Engine → Hypothesis Queue 흐름 검증.
"""

import pytest
from vxis.mission.config import MissionConfig, Depth, Scope
from vxis.graph.attack_graph import LivingAttackGraph
from vxis.evidence.engine import EvidenceEngine
from vxis.evidence.schema import Evidence, Severity, EvidenceType
from vxis.agent.director import DirectorAgent
from vxis.agent.context import AgentContext


@pytest.mark.asyncio
async def test_full_phase1_flow(tmp_path):
    """
    시나리오: S3 공개 → .env 크레덴셜 → DB 접근 체인
    검증: Director가 세 발견을 통합하고 체인을 탐지한다.
    """
    cfg = MissionConfig(
        target="*.acme.com",
        depth=Depth.AGGRESSIVE,
        scope=Scope.FULL,
    )
    graph = LivingAttackGraph()
    engine = EvidenceEngine(db_path=str(tmp_path / "ev.db"))
    await engine.init()

    context = AgentContext(
        mission=cfg,
        attack_graph=graph,
        evidence_engine=engine,
    )
    director = DirectorAgent()

    # Finding 1: S3 공개
    ev1 = Evidence(
        agent_id="cloud",
        title="S3 bucket acme-dev is public",
        severity=Severity.HIGH,
        evidence_type=EvidenceType.MISCONFIGURATION,
        description="S3 bucket public read access",
    )
    await director.integrate_finding(ev1, context)

    # Finding 2: .env 발견 (ev1에서 파생)
    ev2 = Evidence(
        agent_id="secrets_lifecycle",
        title=".env file with DB credentials",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.SECRET,
        description="DATABASE_URL=postgres://admin:secret@db:5432/prod",
        chained_from=ev1.id,
    )
    await director.integrate_finding(ev2, context)

    # Finding 3: DB 직접 접근 (ev2에서 파생)
    ev3 = Evidence(
        agent_id="database",
        title="Direct PostgreSQL access achieved",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.EXPLOIT,
        description="Full read/write access to production DB (2.5M records)",
        chained_from=ev2.id,
    )
    await director.integrate_finding(ev3, context)

    # 검증
    summary = graph.summary()
    assert summary["total_findings"] == 3
    assert summary["critical"] == 2
    assert summary["high"] == 1

    chains = graph.find_critical_chains()
    assert len(chains) >= 1
    longest = max(chains, key=len)
    assert len(longest) == 3  # S3 → .env → DB

    # Evidence Engine 저장 확인
    all_ev = await engine.get_all()
    assert len(all_ev) == 3

    critical_ev = await engine.get_by_severity(Severity.CRITICAL)
    assert len(critical_ev) == 2

    # Hypothesis 자동 생성 확인
    assert director.hypothesis_queue.size() >= 1

    print("\n[PASS] Phase 1 통합 테스트 통과")
    print(f"   총 발견: {summary['total_findings']}")
    print(f"   체인 수: {len(chains)}")
    print(f"   최장 체인: {len(longest)}단계")
    print(f"   생성된 가설: {director.hypothesis_queue.size()}")
