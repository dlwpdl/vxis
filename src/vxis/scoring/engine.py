"""ScoringEngine — 5차원 VXIS 역량 점수 계산 엔진.

같은 입력에 대해 항상 동일한 결과를 보장하는 결정론적 엔진이다.
외부 랜덤성, 타임스탬프 비교, 환경 의존성을 점수 계산 로직에서 배제한다.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from vxis.scoring.tracker import PhaseStatus, ScoreTracker
from vxis.scoring.vectors import get_vectors_for_type

logger = logging.getLogger(__name__)

# ── 레벨별 점수 가중치 (Exploitation Reach) ──
_LEVEL_POINTS: dict[int, int] = {
    0: 1,   # Recon only
    1: 3,   # Vulnerability confirmed
    2: 6,   # Exploit successful
    3: 8,   # Post-exploit (pivot, privesc)
    4: 10,  # Crown Jewel access
}

# ── Finding Precision: 통계적 신뢰도 임계값 (ADR-008) ──
# n (total_judged) < _MIN_JUDGMENTS_FOR_CONFIDENCE 일 때는 단일 판정이
# 전체 precision 점수를 좌우하는 것을 막기 위해 Bayesian smoothing 적용.
_MIN_JUDGMENTS_FOR_CONFIDENCE: int = 3
_PRECISION_PRIOR: float = 3.0  # α=β — 중립(0.5) 방향 prior 강도

# ── 등급 임계값 ──
_GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (900, "S"),
    (750, "A"),
    (600, "B"),
    (400, "C"),
    (0, "D"),
]


def _compute_grade(total: float) -> str:
    """총점에서 등급을 계산한다."""
    for threshold, grade in _GRADE_THRESHOLDS:
        if total >= threshold:
            return grade
    return "D"


@dataclass
class DimensionScore:
    """단일 차원의 점수 상세 정보."""

    name: str
    name_ko: str
    score: float       # 실제 획득 점수
    max_score: float   # 해당 차원의 최대 점수
    percentage: float  # score / max_score (0.0 ~ 1.0)
    details: dict      # 계산 근거 세부 정보

    @property
    def score_int(self) -> int:
        return round(self.score)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "name_ko": self.name_ko,
            "score": round(self.score, 2),
            "max_score": self.max_score,
            "percentage": round(self.percentage, 4),
            "details": self.details,
        }


@dataclass
class VXISScore:
    """VXIS 스캔의 전체 역량 점수."""

    total: float
    grade: str
    target_type: str
    scan_id: str
    timestamp: str

    vector_coverage: DimensionScore
    exploitation_reach: DimensionScore
    chain_intelligence: DimensionScore
    finding_precision: DimensionScore
    completeness: DimensionScore

    dimensions: list[DimensionScore] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.dimensions:
            self.dimensions = [
                self.vector_coverage,
                self.exploitation_reach,
                self.chain_intelligence,
                self.finding_precision,
                self.completeness,
            ]

    def to_dict(self) -> dict:
        return {
            "total": round(self.total, 2),
            "grade": self.grade,
            "target_type": self.target_type,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "dimensions": {
                "vector_coverage": self.vector_coverage.to_dict(),
                "exploitation_reach": self.exploitation_reach.to_dict(),
                "chain_intelligence": self.chain_intelligence.to_dict(),
                "finding_precision": self.finding_precision.to_dict(),
                "completeness": self.completeness.to_dict(),
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def summary_text(self) -> str:
        """사람이 읽기 쉬운 요약 텍스트."""
        lines = [
            f"VXIS Score Report — {self.target_type.upper()}",
            f"Scan ID : {self.scan_id}",
            f"Total   : {self.total:.1f} / 1000  [{self.grade}]",
            "",
            "Dimensions:",
            f"  Vector Coverage    : {self.vector_coverage.score:>6.1f} / {self.vector_coverage.max_score:.0f}  "
            f"({self.vector_coverage.percentage * 100:.1f}%)",
            f"  Exploitation Reach : {self.exploitation_reach.score:>6.1f} / {self.exploitation_reach.max_score:.0f}  "
            f"({self.exploitation_reach.percentage * 100:.1f}%)",
            f"  Chain Intelligence : {self.chain_intelligence.score:>6.1f} / {self.chain_intelligence.max_score:.0f}  "
            f"({self.chain_intelligence.percentage * 100:.1f}%)",
            f"  Finding Precision  : {self.finding_precision.score:>6.1f} / {self.finding_precision.max_score:.0f}  "
            f"({self.finding_precision.percentage * 100:.1f}%)",
            f"  Completeness       : {self.completeness.score:>6.1f} / {self.completeness.max_score:.0f}  "
            f"({self.completeness.percentage * 100:.1f}%)",
        ]
        return "\n".join(lines)


class ScoringEngine:
    """VXIS 역량 점수 계산 엔진.

    결정론적으로 동작한다 — 동일한 ScoreTracker 입력에 대해
    항상 동일한 VXISScore를 반환한다.
    """

    MAX_SCORES: dict[str, float] = {
        "vector_coverage": 250.0,
        "exploitation_reach": 300.0,
        "chain_intelligence": 150.0,
        "finding_precision": 200.0,
        "completeness": 100.0,
    }

    def __init__(self, target_type: str) -> None:
        if target_type not in ("web", "game", "mobile", "desktop"):
            raise ValueError(
                f"Unknown target_type: {target_type!r}. "
                f"Must be one of: web, game, mobile, desktop"
            )
        self.target_type = target_type
        self._vectors = get_vectors_for_type(target_type)
        self._total_vectors = len(self._vectors)

    # ─────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────

    def calculate(
        self,
        tracker: ScoreTracker,
        findings: list,
        scan_id: str = "",
    ) -> VXISScore:
        """ScoreTracker 데이터로부터 VXISScore를 계산한다."""
        vc = self._calc_vector_coverage(tracker)
        er = self._calc_exploitation_reach(tracker)
        ci = self._calc_chain_intelligence(tracker)
        fp = self._calc_finding_precision(tracker, findings)
        co = self._calc_completeness(tracker)

        total = vc.score + er.score + ci.score + fp.score + co.score
        grade = _compute_grade(total)

        score = VXISScore(
            total=total,
            grade=grade,
            target_type=self.target_type,
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            vector_coverage=vc,
            exploitation_reach=er,
            chain_intelligence=ci,
            finding_precision=fp,
            completeness=co,
        )

        logger.info(
            "[SCORE] %s — Total: %.1f (%s) | VC:%.0f ER:%.0f CI:%.0f FP:%.0f CO:%.0f",
            target_type_upper := self.target_type.upper(),  # noqa: F841
            total, grade,
            vc.score, er.score, ci.score, fp.score, co.score,
        )
        return score

    def compare(
        self,
        baseline: VXISScore,
        current: VXISScore,
    ) -> object:
        """두 VXISScore를 비교하여 ScoreComparison을 반환한다."""
        from vxis.scoring.reporter import ScoreComparison
        return ScoreComparison.build(baseline, current)

    # ─────────────────────────────────────────────────────────────────────
    # Dimension Calculators (private)
    # ─────────────────────────────────────────────────────────────────────

    def _calc_vector_coverage(self, tracker: ScoreTracker) -> DimensionScore:
        """Dimension 1: Vector Coverage (max 250pts).

        Score = attempt_score + found_score
          attempt_score = (vectors_attempted / total_vectors) × 120  (도구 능력)
          found_score   = (vectors_found    / total_vectors) × 130  (실제 발견)

        취약점을 하나도 못 찾으면 최대 120pts, 찾을수록 추가 점수.
        """
        max_score = self.MAX_SCORES["vector_coverage"]
        ATTEMPT_MAX = 120.0
        FOUND_MAX = 130.0

        total = self._total_vectors
        valid_ids = {v.id for v in self._vectors}

        valid_attempted = len(tracker.vectors_attempted & valid_ids)
        valid_found = len(tracker.vectors_found & valid_ids)

        attempt_ratio = valid_attempted / total if total > 0 else 0.0
        found_ratio = valid_found / total if total > 0 else 0.0

        attempt_score = attempt_ratio * ATTEMPT_MAX
        found_score = found_ratio * FOUND_MAX
        score = attempt_score + found_score

        # 카테고리별 커버리지 세부 정보
        category_coverage: dict[str, dict] = {}
        for v in self._vectors:
            cat = v.category
            if cat not in category_coverage:
                category_coverage[cat] = {"total": 0, "attempted": 0, "found": 0}
            category_coverage[cat]["total"] += 1
            if v.id in tracker.vectors_attempted:
                category_coverage[cat]["attempted"] += 1
            if v.id in tracker.vectors_found:
                category_coverage[cat]["found"] += 1

        return DimensionScore(
            name="Vector Coverage",
            name_ko="벡터 커버리지",
            score=score,
            max_score=max_score,
            percentage=score / max_score,
            details={
                "vectors_attempted": valid_attempted,
                "vectors_found": valid_found,
                "total_vectors": total,
                "attempt_score": round(attempt_score, 2),
                "found_score": round(found_score, 2),
                "unknown_vectors_ignored": len(tracker.vectors_attempted) - valid_attempted,
                "category_coverage": category_coverage,
            },
        )

    def _calc_exploitation_reach(self, tracker: ScoreTracker) -> DimensionScore:
        """Dimension 2: Exploitation Reach (max 300pts).

        Level 0→1pt, 1→3pt, 2→6pt, 3→8pt, 4→10pt
        Score = (sum_of_max_levels / ideal_score_if_all_L4) × 300

        ideal = total_findings × 10 (L4점수)
        """
        max_score = self.MAX_SCORES["exploitation_reach"]

        levels = tracker.exploitation_levels
        if not levels:
            return DimensionScore(
                name="Exploitation Reach",
                name_ko="익스플로잇 도달 깊이",
                score=0.0,
                max_score=max_score,
                percentage=0.0,
                details={
                    "findings_count": 0,
                    "level_distribution": {},
                    "actual_points": 0,
                    "ideal_points": 0,
                },
            )

        actual_points = sum(
            _LEVEL_POINTS.get(lvl, 0) for lvl in levels.values()
        )
        ideal_points = len(levels) * _LEVEL_POINTS[4]  # 모두 L4라고 가정

        ratio = actual_points / ideal_points if ideal_points > 0 else 0.0
        score = ratio * max_score

        # 레벨 분포
        level_dist: dict[str, int] = {f"L{i}": 0 for i in range(5)}
        for lvl in levels.values():
            level_dist[f"L{lvl}"] += 1

        return DimensionScore(
            name="Exploitation Reach",
            name_ko="익스플로잇 도달 깊이",
            score=score,
            max_score=max_score,
            percentage=ratio,
            details={
                "findings_count": len(levels),
                "level_distribution": level_dist,
                "actual_points": actual_points,
                "ideal_points": ideal_points,
                "level_points_mapping": {f"L{k}": v for k, v in _LEVEL_POINTS.items()},
            },
        )

    def _calc_chain_intelligence(self, tracker: ScoreTracker) -> DimensionScore:
        """Dimension 3: Chain Intelligence (max 150pts) — continuous gradient.

        depth_points = min(max_depth * 25, 125)            # 1→25, 5+→125
        count_bonus  = min((chain_count - 1) * 10, 15)     # 2→+10, 3+→+15
        crown_bonus  = 25 if any step.level >= 3 else 0    # critical impact
        score        = min(sum, 150)

        기존 step-function (0/50/100/150) 의 단점:
          - chain_count 무시 → 여러 체인 구축 무보상
          - 체인 임팩트 무시 → recon-only 체인과 RCE 체인이 동점
          - 깊이 1-2 gradient 부재 → 2 step 만 채우면 최대 보상 착각

        경계 보존: 5-depth + crown + 2+chains = 125+15+25 = 165 → clamp 150.
        See: wiki/sources/incidents/2026_04_20_brain_prompt_prison.md
        """
        max_score = self.MAX_SCORES["chain_intelligence"]
        max_depth = tracker.max_chain_depth
        chain_count = len(tracker.attack_chains)

        depth_points = min(max_depth * 25, 125) if max_depth > 0 else 0
        count_bonus = min((chain_count - 1) * 10, 15) if chain_count > 1 else 0
        has_crown = any(
            step.level >= 3
            for chain in tracker.attack_chains
            for step in chain.steps
        )
        crown_bonus = 25 if has_crown else 0
        score = float(min(depth_points + count_bonus + crown_bonus, max_score))

        return DimensionScore(
            name="Chain Intelligence",
            name_ko="체인 지능",
            score=score,
            max_score=max_score,
            percentage=score / max_score,
            details={
                "chain_count": chain_count,
                "max_chain_depth": max_depth,
                "depth_points": depth_points,
                "count_bonus": count_bonus,
                "crown_bonus": crown_bonus,
                "chains": [
                    {
                        "chain_id": c.chain_id,
                        "depth": c.depth,
                        "description_en": c.description_en,
                    }
                    for c in tracker.attack_chains
                ],
            },
        )

    def _calc_finding_precision(
        self,
        tracker: ScoreTracker,
        findings: list,
    ) -> DimensionScore:
        """Dimension 4: Finding Precision (max 200pts).

        ADR-008: 판정 수 부족 시 Bayesian smoothing 으로 noise 축소.
          total_judged == 0 → 중립 100pts (기존 140pts, perverse incentive 제거)
          0 < total_judged < MIN_JUDGMENTS_FOR_CONFIDENCE → (tp+α)/(n+2α), α=3
          total_judged ≥ MIN_JUDGMENTS_FOR_CONFIDENCE → tp/n × 200 (그대로)

        Bonus 1: Evidence quality (+최대 20pts, finding당 증거 2개 이상 시)
        Bonus 2: Dedup accuracy (+최대 10pts, ground truth 매칭률)

        총점은 200pts를 초과할 수 없다.
        """
        max_score = self.MAX_SCORES["finding_precision"]

        tp = tracker.true_positive_count
        fp = tracker.false_positive_count
        total_judged = tp + fp
        total_findings = len(tracker.exploitation_levels)  # 실제 기록된 findings 수

        measurement_valid = False
        if total_findings == 0:
            # findings가 하나도 없으면 정밀도 측정 대상 없음.
            precision_ratio = 0.0
            base_score = 0.0
        elif total_judged == 0:
            # 판정 0건 → 중립 50% (기존 70% 기본값은 "판정 안 할수록 고득점" 결함).
            # ADR-008 참조.
            precision_ratio = 0.5
            base_score = max_score * 0.5
        elif total_judged < _MIN_JUDGMENTS_FOR_CONFIDENCE:
            # 판정 1~2건 → Bayesian smoothing (α=β=_PRECISION_PRIOR) 으로
            # prior (0.5) 방향으로 shrink. 단일 판정의 극단값(0% 또는 100%)이
            # 전체 점수를 좌우하지 못하도록. ADR-008 참조.
            alpha = _PRECISION_PRIOR
            precision_ratio = (tp + alpha) / (total_judged + 2 * alpha)
            base_score = precision_ratio * max_score
        else:
            # 판정 ≥_MIN_JUDGMENTS_FOR_CONFIDENCE 건 → 통계적 의미 있음, 그대로.
            precision_ratio = tp / total_judged
            base_score = precision_ratio * max_score
            measurement_valid = True

        # Bonus 1: Evidence quality (finding당 증거 2개 이상 → 보너스)
        findings_with_good_evidence = sum(
            1 for count in tracker.evidence_counts.values() if count >= 2
        )
        total_findings = max(len(tracker.evidence_counts), 1)
        evidence_ratio = findings_with_good_evidence / total_findings
        evidence_bonus = evidence_ratio * 20.0

        # Bonus 2: Ground truth dedup accuracy
        ground_truth = tracker.ground_truth_matches
        if ground_truth:
            gt_matched = sum(1 for v in ground_truth.values() if v)
            gt_ratio = gt_matched / len(ground_truth)
            gt_bonus = gt_ratio * 10.0
        else:
            gt_bonus = 0.0

        score = min(base_score + evidence_bonus + gt_bonus, max_score)
        percentage = score / max_score

        return DimensionScore(
            name="Finding Precision",
            name_ko="발견 정밀도",
            score=score,
            max_score=max_score,
            percentage=percentage,
            details={
                "true_positives": tp,
                "false_positives": fp,
                "total_judged": total_judged,
                "precision_ratio": round(precision_ratio, 4),
                "base_score": round(base_score, 2),
                "evidence_bonus": round(evidence_bonus, 2),
                "ground_truth_bonus": round(gt_bonus, 2),
                "ground_truth_coverage": len(ground_truth),
                "analyst_judged_coverage": total_judged,
                # ADR-008: 통계적 신뢰도 메타데이터.
                "measurement_valid": measurement_valid,
                "min_judgments_required": _MIN_JUDGMENTS_FOR_CONFIDENCE,
            },
        )

    def _calc_completeness(self, tracker: ScoreTracker) -> DimensionScore:
        """Dimension 5: Completeness (max 100pts).

        Score = (completed_phases / total_applicable_phases) × 100
        - N/A 스킵은 total_applicable_phases에서 제외 (분모에 포함 안 함)
        - 버그 스킵, 실패는 total에 포함 (분모) + 완료 카운트에 불포함 → 차감
        """
        max_score = self.MAX_SCORES["completeness"]

        results = tracker.phase_results
        if not results:
            # 아직 아무 Phase도 기록되지 않음 — 완료로 처리 (N/A 상황)
            return DimensionScore(
                name="Completeness",
                name_ko="완성도",
                score=max_score,
                max_score=max_score,
                percentage=1.0,
                details={
                    "completed": 0,
                    "skipped_na": 0,
                    "skipped_error": 0,
                    "failed": 0,
                    "total_applicable": 0,
                    "note": "No phases recorded — assuming full completeness",
                },
            )

        completed = sum(
            1 for r in results.values()
            if r.status == PhaseStatus.completed
        )
        skipped_na = sum(
            1 for r in results.values()
            if r.status == PhaseStatus.skipped_na
        )
        skipped_error = sum(
            1 for r in results.values()
            if r.status == PhaseStatus.skipped_error
        )
        failed = sum(
            1 for r in results.values()
            if r.status == PhaseStatus.failed
        )

        # N/A는 분모에서 제외
        total_applicable = completed + skipped_error + failed
        if total_applicable == 0:
            ratio = 1.0
        else:
            ratio = completed / total_applicable

        score = ratio * max_score

        return DimensionScore(
            name="Completeness",
            name_ko="완성도",
            score=score,
            max_score=max_score,
            percentage=ratio,
            details={
                "completed": completed,
                "skipped_na": skipped_na,
                "skipped_error": skipped_error,
                "failed": failed,
                "total_applicable": total_applicable,
                "error_phases": [
                    {"phase": r.phase_name, "reason": r.error or r.skipped_reason}
                    for r in results.values()
                    if r.status in (PhaseStatus.skipped_error, PhaseStatus.failed)
                ],
            },
        )
