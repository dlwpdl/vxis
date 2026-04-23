"""ScoreTracker — ScanContext에 내장되는 스코어링 이벤트 수집기.

각 파이프라인 Phase가 공격 시도, 발견, 에스컬레이션, 체인을 기록하면
ScoringEngine이 이를 소비하여 VXISScore를 계산한다.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)


class PhaseStatus(str, Enum):
    """Phase 실행 결과 상태."""

    completed = "completed"   # 정상 완료
    skipped_na = "skipped_na"  # N/A (해당 없음) — 점수 차감 없음
    skipped_error = "skipped_error"  # 버그로 인한 스킵 — 완성도 점수 차감
    failed = "failed"          # 실행 실패 — 완성도 점수 차감


@dataclass
class PhaseResult:
    """단일 Phase의 실행 결과."""

    phase_name: str
    status: PhaseStatus
    duration_ms: float = 0.0
    findings_count: int = 0
    vectors_attempted: list[str] = field(default_factory=list)
    error: str | None = None
    skipped_reason: str | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class ChainStep:
    """공격 체인의 단일 단계."""

    step_index: int        # 0-based
    vector_id: str         # 이 단계에서 사용된 벡터
    finding_id: str        # 이 단계에서 생성된 Finding
    level: int             # 익스플로잇 레벨 (0-4)
    description_en: str
    description_ko: str


@dataclass
class AttackChain:
    """여러 단계로 구성된 멀티-스텝 공격 체인."""

    chain_id: str
    steps: list[ChainStep] = field(default_factory=list)
    description_en: str = ""
    description_ko: str = ""
    final_impact: str = ""  # 최종 임팩트 설명

    @property
    def depth(self) -> int:
        """체인의 단계 수."""
        return len(self.steps)

    def add_step(
        self,
        vector_id: str,
        finding_id: str,
        level: int,
        description_en: str,
        description_ko: str,
    ) -> ChainStep:
        """체인에 단계를 추가한다."""
        step = ChainStep(
            step_index=len(self.steps),
            vector_id=vector_id,
            finding_id=finding_id,
            level=level,
            description_en=description_en,
            description_ko=description_ko,
        )
        self.steps.append(step)
        logger.debug(
            "[CHAIN %s] Step %d: %s → %s (L%d)",
            self.chain_id, step.step_index, vector_id, finding_id, level,
        )
        return step


@dataclass
class ScoreTracker:
    """ScanContext에 내장 — 스캔 중 스코어링 이벤트를 실시간 수집한다.

    파이프라인 Phase는 다음 메서드를 호출한다:
      - record_vector_attempt(vector_id)
      - record_finding(finding_id, vector_id, level)
      - escalate_level(finding_id, new_level)
      - record_chain(chain)
      - record_phase_complete(phase_name)
      - record_phase_skipped(phase_name, reason)
    """

    target_type: str  # "web" | "game" | "mobile" | "desktop"

    # ── Vector Coverage ──
    vectors_attempted: set[str] = field(default_factory=set)
    vectors_found: set[str] = field(default_factory=set)

    # ── Exploitation Reach ──
    # finding_id → max exploitation level (0-4)
    exploitation_levels: dict[str, int] = field(default_factory=dict)
    # finding_id → vector_id (어떤 벡터로 발견했는지)
    finding_vectors: dict[str, str] = field(default_factory=dict)

    # ── Chain Intelligence ──
    attack_chains: list[AttackChain] = field(default_factory=list)

    # ── Phase Completeness ──
    phase_results: dict[str, PhaseResult] = field(default_factory=dict)

    # ── Finding Precision (ground truth) ──
    # expected_finding_id → was_found (True/False)
    ground_truth_matches: dict[str, bool] = field(default_factory=dict)
    # finding_id → analyst verdict (True = TP, False = FP)
    analyst_verdicts: dict[str, bool] = field(default_factory=dict)

    # ── Evidence Quality ──
    # finding_id → evidence count
    evidence_counts: dict[str, int] = field(default_factory=dict)

    def record_vector_attempt(self, vector_id: str) -> None:
        """벡터 시도를 기록한다. 중복 기록은 무시된다."""
        self.vectors_attempted.add(vector_id)
        logger.debug("[SCORE] Vector attempted: %s", vector_id)

    def record_finding(
        self,
        finding_id: str,
        vector_id: str,
        level: int,
        evidence_count: int = 0,
    ) -> None:
        """새 Finding을 기록하고 초기 익스플로잇 레벨을 설정한다.

        Args:
            finding_id: Finding의 고유 ID (예: VXIS-001).
            vector_id: 발견에 사용된 공격 벡터 ID (예: WEB-SQLI-001).
            level: 초기 익스플로잇 레벨 (0-4).
            evidence_count: 첨부된 증거 아이템 수.
        """
        if level < 0 or level > 4:
            raise ValueError(
                f"Exploitation level must be 0-4, got {level} for {finding_id}"
            )

        # 이미 기록된 경우 더 높은 레벨로 업데이트
        current = self.exploitation_levels.get(finding_id, -1)
        if level > current:
            self.exploitation_levels[finding_id] = level

        self.finding_vectors[finding_id] = vector_id
        self.vectors_found.add(vector_id)
        self.evidence_counts[finding_id] = evidence_count

        logger.debug(
            "[SCORE] Finding recorded: %s via %s at L%d",
            finding_id, vector_id, level,
        )

    def escalate_level(self, finding_id: str, new_level: int) -> None:
        """기존 Finding의 익스플로잇 레벨을 상향한다.

        새 레벨이 현재보다 낮거나 같으면 무시한다.
        """
        if new_level < 0 or new_level > 4:
            raise ValueError(
                f"Exploitation level must be 0-4, got {new_level} for {finding_id}"
            )

        current = self.exploitation_levels.get(finding_id, 0)
        if new_level > current:
            self.exploitation_levels[finding_id] = new_level
            logger.info(
                "[SCORE] Escalated %s: L%d → L%d",
                finding_id, current, new_level,
            )
        else:
            logger.debug(
                "[SCORE] Escalation ignored for %s (L%d ≤ current L%d)",
                finding_id, new_level, current,
            )

    def record_chain(self, chain: AttackChain) -> None:
        """완성된 공격 체인을 기록한다."""
        self.attack_chains.append(chain)
        logger.info(
            "[SCORE] Attack chain recorded: %s (%d steps)",
            chain.chain_id, chain.depth,
        )

    def record_phase_complete(
        self,
        phase_name: str,
        duration_ms: float = 0.0,
        findings_count: int = 0,
        vectors_attempted: list[str] | None = None,
    ) -> None:
        """Phase가 정상 완료됐음을 기록한다."""
        result = PhaseResult(
            phase_name=phase_name,
            status=PhaseStatus.completed,
            duration_ms=duration_ms,
            findings_count=findings_count,
            vectors_attempted=vectors_attempted or [],
        )
        self.phase_results[phase_name] = result
        logger.debug("[SCORE] Phase complete: %s", phase_name)

    def record_phase_skipped(
        self,
        phase_name: str,
        reason: str,
        is_error: bool = False,
    ) -> None:
        """Phase 스킵을 기록한다.

        Args:
            phase_name: 스킵된 Phase 이름.
            reason: 스킵 이유.
            is_error: True이면 버그로 인한 스킵 (완성도 점수 차감).
                      False이면 N/A (해당 없음) — 점수 차감 없음.
        """
        status = PhaseStatus.skipped_error if is_error else PhaseStatus.skipped_na
        result = PhaseResult(
            phase_name=phase_name,
            status=status,
            skipped_reason=reason,
        )
        self.phase_results[phase_name] = result
        log_level = logging.WARNING if is_error else logging.DEBUG
        logger.log(
            log_level,
            "[SCORE] Phase skipped (%s): %s — %s",
            status.value, phase_name, reason,
        )

    def record_phase_failed(
        self,
        phase_name: str,
        error: str,
        duration_ms: float = 0.0,
    ) -> None:
        """Phase 실패를 기록한다. 완성도 점수 차감 대상."""
        result = PhaseResult(
            phase_name=phase_name,
            status=PhaseStatus.failed,
            duration_ms=duration_ms,
            error=error,
        )
        self.phase_results[phase_name] = result
        logger.error("[SCORE] Phase failed: %s — %s", phase_name, error)

    def set_ground_truth(
        self,
        expected_finding_id: str,
        found: bool,
    ) -> None:
        """레퍼런스 타겟의 예상 Finding 매칭 결과를 설정한다."""
        self.ground_truth_matches[expected_finding_id] = found

    def mark_analyst_verdict(
        self,
        finding_id: str,
        is_true_positive: bool,
    ) -> None:
        """애널리스트의 TP/FP 판정을 기록한다."""
        self.analyst_verdicts[finding_id] = is_true_positive

    def update_evidence_count(self, finding_id: str, count: int) -> None:
        """Finding의 증거 개수를 업데이트한다."""
        self.evidence_counts[finding_id] = count

    # ── Computed Properties ──

    @property
    def total_findings(self) -> int:
        """기록된 Finding 총 수."""
        return len(self.exploitation_levels)

    @property
    def max_chain_depth(self) -> int:
        """기록된 공격 체인 중 최대 깊이."""
        if not self.attack_chains:
            return 0
        return max(c.depth for c in self.attack_chains)

    @property
    def true_positive_count(self) -> int:
        """애널리스트가 TP로 판정한 Finding 수."""
        return sum(1 for v in self.analyst_verdicts.values() if v)

    @property
    def false_positive_count(self) -> int:
        """애널리스트가 FP로 판정한 Finding 수."""
        return sum(1 for v in self.analyst_verdicts.values() if not v)

    @property
    def completed_phases(self) -> list[str]:
        """정상 완료된 Phase 목록."""
        return [
            name for name, r in self.phase_results.items()
            if r.status == PhaseStatus.completed
        ]

    @property
    def error_skipped_phases(self) -> list[str]:
        """버그로 인해 스킵된 Phase 목록 (완성도 차감 대상)."""
        return [
            name for name, r in self.phase_results.items()
            if r.status in (PhaseStatus.skipped_error, PhaseStatus.failed)
        ]
