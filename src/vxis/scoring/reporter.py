"""ScoreReporter — 점수 비교 리포트 생성기.

Markdown, Telegram 메시지, GitHub PR 코멘트 형식을 지원한다.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vxis.scoring.engine import VXISScore

logger = logging.getLogger(__name__)

# 등급별 이모지 (리포트 가독성 향상)
_GRADE_EMOJI: dict[str, str] = {
    "S": "S",
    "A": "A",
    "B": "B",
    "C": "C",
    "D": "D",
}

_DIMENSION_KEYS = [
    "vector_coverage",
    "exploitation_reach",
    "chain_intelligence",
    "finding_precision",
    "completeness",
]

_DIMENSION_LABELS: dict[str, str] = {
    "vector_coverage":    "Vector Coverage    (25%)",
    "exploitation_reach": "Exploitation Reach (30%)",
    "chain_intelligence": "Chain Intelligence (15%)",
    "finding_precision":  "Finding Precision  (20%)",
    "completeness":       "Completeness       (10%)",
}


@dataclass
class ScoreComparison:
    """두 VXISScore의 비교 결과."""

    baseline: "VXISScore"
    current: "VXISScore"
    total_delta: float            # positive = 개선, negative = 회귀
    dimension_deltas: dict[str, float]
    regression: bool              # current < baseline이면 True
    regression_details: list[str]
    new_vectors_covered: list[str]
    lost_vectors: list[str]

    @classmethod
    def build(
        cls,
        baseline: "VXISScore",
        current: "VXISScore",
    ) -> "ScoreComparison":
        """두 VXISScore를 비교하여 ScoreComparison을 생성한다."""
        total_delta = current.total - baseline.total

        dim_deltas: dict[str, float] = {}
        regression_details: list[str] = []

        for key in _DIMENSION_KEYS:
            b_dim = getattr(baseline, key, None)
            c_dim = getattr(current, key, None)
            if b_dim is None or c_dim is None:
                dim_deltas[key] = 0.0
                continue

            delta = c_dim.score - b_dim.score
            dim_deltas[key] = delta

            if delta < -1.0:  # 1pt 이상 하락 시 회귀로 간주
                regression_details.append(
                    f"{_DIMENSION_LABELS.get(key, key)}: "
                    f"{b_dim.score:.1f} -> {c_dim.score:.1f} "
                    f"(delta {delta:+.1f})"
                )

        regression = total_delta < -5.0  # 총점 5pt 이상 하락 시 회귀

        # 벡터 커버리지 변화 분석
        b_details = baseline.vector_coverage.details
        c_details = current.vector_coverage.details

        set(
            b_details.get("category_coverage", {}).keys()
        )
        set(
            c_details.get("category_coverage", {}).keys()
        )

        # 상세 벡터 ID 추적 (tracker에서 가져온 경우)
        b_vector_details = b_details.get("vectors_attempted_ids", set())
        c_vector_details = c_details.get("vectors_attempted_ids", set())

        if isinstance(b_vector_details, list):
            b_vector_details = set(b_vector_details)
        if isinstance(c_vector_details, list):
            c_vector_details = set(c_vector_details)

        new_vectors = list(c_vector_details - b_vector_details)
        lost_vectors = list(b_vector_details - c_vector_details)

        return cls(
            baseline=baseline,
            current=current,
            total_delta=total_delta,
            dimension_deltas=dim_deltas,
            regression=regression,
            regression_details=regression_details,
            new_vectors_covered=new_vectors,
            lost_vectors=lost_vectors,
        )

    def to_dict(self) -> dict:
        return {
            "total_delta": round(self.total_delta, 2),
            "dimension_deltas": {k: round(v, 2) for k, v in self.dimension_deltas.items()},
            "regression": self.regression,
            "regression_details": self.regression_details,
            "new_vectors_covered_count": len(self.new_vectors_covered),
            "lost_vectors_count": len(self.lost_vectors),
        }


class ScoreReporter:
    """다양한 형식의 스코어 비교 리포트를 생성한다."""

    # ─────────────────────────────────────────────────────────────────────
    # Markdown
    # ─────────────────────────────────────────────────────────────────────

    def generate_markdown(self, comparison: ScoreComparison) -> str:
        """GitHub/GitLab Markdown 형식의 전체 비교 리포트."""
        b = comparison.baseline
        c = comparison.current
        delta = comparison.total_delta
        delta_sign = "+" if delta >= 0 else ""
        regression_badge = (
            "**REGRESSION DETECTED**"
            if comparison.regression
            else "PASS"
        )

        lines: list[str] = [
            "## VXIS Capability Score Report",
            "",
            "| | Baseline | Current | Delta |",
            "|---|---|---|---|",
            f"| **Total** | {b.total:.1f} [{b.grade}] | {c.total:.1f} [{c.grade}] | `{delta_sign}{delta:.1f}` |",
            f"| Target Type | {b.target_type} | {c.target_type} | — |",
            "",
        ]

        # 차원별 비교 테이블
        lines += [
            "### Dimension Breakdown",
            "",
            "| Dimension | Baseline | Current | Delta | Max |",
            "|---|---|---|---|---|",
        ]

        for key in _DIMENSION_KEYS:
            b_dim = getattr(b, key, None)
            c_dim = getattr(c, key, None)
            if b_dim is None or c_dim is None:
                continue

            delta_val = comparison.dimension_deltas.get(key, 0.0)
            delta_str = f"{'+' if delta_val >= 0 else ''}{delta_val:.1f}"
            trend = "" if abs(delta_val) < 0.5 else (" (UP)" if delta_val > 0 else " (DOWN)")

            lines.append(
                f"| {_DIMENSION_LABELS.get(key, key)} "
                f"| {b_dim.score:.1f} "
                f"| {c_dim.score:.1f} "
                f"| `{delta_str}`{trend} "
                f"| {b_dim.max_score:.0f} |"
            )

        lines += [""]

        # 회귀 상세 정보
        if comparison.regression:
            lines += [
                "### Regression Details",
                "",
                f"**Status: {regression_badge}**",
                "",
            ]
            for detail in comparison.regression_details:
                lines.append(f"- {detail}")
            lines.append("")
        else:
            lines += [
                f"### Status: {regression_badge}",
                "",
            ]

        # 새로 커버된 벡터
        if comparison.new_vectors_covered:
            lines += [
                "### New Vectors Covered",
                "",
            ]
            for v in comparison.new_vectors_covered[:20]:  # 최대 20개 표시
                lines.append(f"- `{v}`")
            if len(comparison.new_vectors_covered) > 20:
                lines.append(
                    f"- _...and {len(comparison.new_vectors_covered) - 20} more_"
                )
            lines.append("")

        # 손실된 벡터
        if comparison.lost_vectors:
            lines += [
                "### Lost Vectors (Coverage Regression)",
                "",
            ]
            for v in comparison.lost_vectors[:20]:
                lines.append(f"- `{v}`")
            lines.append("")

        lines += [
            "---",
            "_Generated by VXIS Capability Scoring System_",
        ]

        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────────────────
    # Telegram
    # ─────────────────────────────────────────────────────────────────────

    def generate_telegram_message(self, comparison: ScoreComparison) -> str:
        """Telegram HTML 형식의 간결한 알림 메시지."""
        b = comparison.baseline
        c = comparison.current
        delta = comparison.total_delta
        delta_sign = "+" if delta >= 0 else ""
        status_text = "REGRESSION" if comparison.regression else "PASS"

        dim_lines = []
        for key in _DIMENSION_KEYS:
            b_dim = getattr(b, key, None)
            c_dim = getattr(c, key, None)
            if b_dim is None or c_dim is None:
                continue
            delta_val = comparison.dimension_deltas.get(key, 0.0)
            delta_str = f"{'+' if delta_val >= 0 else ''}{delta_val:.0f}"
            label = key.replace("_", " ").title()[:20]
            dim_lines.append(
                f"  {label:<22} {b_dim.score:>6.0f} -> {c_dim.score:>6.0f} ({delta_str})"
            )

        regression_note = ""
        if comparison.regression:
            regression_note = "\n\nRegression Details:\n" + "\n".join(
                f"  - {d}" for d in comparison.regression_details
            )

        message = (
            f"[VXIS Benchmark] {c.target_type.upper()} Scan\n"
            f"Status: {status_text}\n\n"
            f"Score: {b.total:.0f} [{b.grade}] -> {c.total:.0f} [{c.grade}] "
            f"({delta_sign}{delta:.0f})\n\n"
            f"Dimensions:\n"
            + "\n".join(dim_lines)
            + regression_note
        )
        return message

    # ─────────────────────────────────────────────────────────────────────
    # GitHub PR Comment
    # ─────────────────────────────────────────────────────────────────────

    def generate_github_comment(self, comparison: ScoreComparison) -> str:
        """GitHub PR 코멘트 형식 (Markdown + collapsible details)."""
        b = comparison.baseline
        c = comparison.current
        delta = comparison.total_delta
        delta_sign = "+" if delta >= 0 else ""

        status_icon = "FAIL" if comparison.regression else "PASS"
        grade_changed = b.grade != c.grade
        grade_note = (
            f" (Grade: {b.grade} -> {c.grade})"
            if grade_changed
            else ""
        )

        lines: list[str] = [
            f"## VXIS Benchmark {status_icon}",
            "",
            f"> Total Score: **{c.total:.1f}** / 1000 [{c.grade}]{grade_note}  ",
            f"> Delta: **{delta_sign}{delta:.1f}** vs baseline ({b.total:.1f} [{b.grade}])",
            "",
            "<details>",
            "<summary>Dimension Scores (click to expand)</summary>",
            "",
            "| Dimension | Baseline | Current | Delta | Max |",
            "|---|---|---|---|---|",
        ]

        for key in _DIMENSION_KEYS:
            b_dim = getattr(b, key, None)
            c_dim = getattr(c, key, None)
            if b_dim is None or c_dim is None:
                continue
            delta_val = comparison.dimension_deltas.get(key, 0.0)
            delta_str = f"{'+' if delta_val >= 0 else ''}{delta_val:.1f}"
            trend_icon = "" if abs(delta_val) < 0.5 else (" UP" if delta_val > 0 else " DOWN")
            lines.append(
                f"| {_DIMENSION_LABELS.get(key, key)} "
                f"| {b_dim.score:.1f} "
                f"| {c_dim.score:.1f} "
                f"| {delta_str}{trend_icon} "
                f"| {b_dim.max_score:.0f} |"
            )

        lines += [
            "",
            "</details>",
            "",
        ]

        if comparison.regression:
            lines += [
                "### Regression Details",
                "",
                "The following dimensions regressed:",
                "",
            ]
            for detail in comparison.regression_details:
                lines.append(f"- {detail}")
            lines += [
                "",
                "> **This PR is blocked until regressions are resolved.**",
                "",
            ]

        if comparison.new_vectors_covered:
            lines += [
                "<details>",
                f"<summary>New Vectors Covered (+{len(comparison.new_vectors_covered)})</summary>",
                "",
            ]
            for v in comparison.new_vectors_covered:
                lines.append(f"- `{v}`")
            lines += ["", "</details>", ""]

        lines += [
            "---",
            "_VXIS Capability Scoring System — automated benchmark_",
        ]

        return "\n".join(lines)
