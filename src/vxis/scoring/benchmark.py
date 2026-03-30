"""BenchmarkRunner — CI용 벤치마크 실행기.

1. 레퍼런스 타겟에 대해 스캔 실행
2. Score 계산
3. 저장된 baseline과 비교
4. 결과 리포트 생성

사용 예시:
    runner = BenchmarkRunner(baseline_path="tools/benchmark/baseline.json")
    score = await runner.run_benchmark("web", "https://example.com")
    comparison = runner.compare_with_baseline(score)
    reporter = ScoreReporter()
    print(reporter.generate_markdown(comparison))
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from vxis.scoring.engine import DimensionScore, ScoringEngine, VXISScore
from vxis.scoring.reporter import ScoreComparison, ScoreReporter
from vxis.scoring.tracker import ScoreTracker

logger = logging.getLogger(__name__)

_VALID_TARGET_TYPES = ("web", "game", "mobile")


class BaselineNotFoundError(Exception):
    """베이스라인 파일이 없거나 해당 타겟 타입의 데이터가 없을 때."""


class BenchmarkRunner:
    """CI용 벤치마크 실행기.

    baseline.json에서 베이스라인을 로드하고,
    새 스캔 결과와 비교하여 회귀 여부를 판단한다.
    """

    def __init__(self, baseline_path: str) -> None:
        self.baseline_path = Path(baseline_path)
        self._reporter = ScoreReporter()

    # ─────────────────────────────────────────────────────────────────────
    # Core Public API
    # ─────────────────────────────────────────────────────────────────────

    async def run_benchmark(
        self,
        target_type: str,
        target_url: str,
        scan_id: str | None = None,
    ) -> VXISScore:
        """레퍼런스 타겟에 대해 스캔을 실행하고 VXISScore를 반환한다.

        실제 스캔 파이프라인을 호출한다. 파이프라인은 ScanContext에
        ScoreTracker를 포함하고 있어야 한다.

        Args:
            target_type: "web" | "game" | "mobile"
            target_url: 레퍼런스 타겟 URL 또는 식별자.
            scan_id: 스캔 ID (없으면 자동 생성).

        Returns:
            계산된 VXISScore.
        """
        if target_type not in _VALID_TARGET_TYPES:
            raise ValueError(
                f"Invalid target_type: {target_type!r}. "
                f"Must be one of: {_VALID_TARGET_TYPES}"
            )

        _scan_id = scan_id or _generate_scan_id(target_type)

        logger.info(
            "[BENCHMARK] Starting %s benchmark scan on %s (id=%s)",
            target_type, target_url, _scan_id,
        )

        # 파이프라인 임포트 (순환 의존성 방지를 위해 지연 임포트)
        ctx = await self._execute_pipeline(
            target_type=target_type,
            target_url=target_url,
            scan_id=_scan_id,
        )

        engine = ScoringEngine(target_type)
        score = engine.calculate(
            tracker=ctx.score_tracker,
            findings=ctx.findings,
            scan_id=_scan_id,
        )

        logger.info(
            "[BENCHMARK] Score: %.1f [%s] for %s on %s",
            score.total, score.grade, target_type, target_url,
        )
        return score

    def calculate_from_tracker(
        self,
        tracker: ScoreTracker,
        findings: list,
        scan_id: str = "",
    ) -> VXISScore:
        """이미 완료된 ScoreTracker로부터 직접 점수를 계산한다.

        파이프라인 실행 없이 기존 스캔 결과로 점수를 계산할 때 사용한다.
        """
        engine = ScoringEngine(tracker.target_type)
        return engine.calculate(
            tracker=tracker,
            findings=findings,
            scan_id=scan_id or _generate_scan_id(tracker.target_type),
        )

    def load_baseline(self, target_type: str | None = None) -> dict[str, VXISScore] | VXISScore | None:
        """베이스라인 파일을 로드한다.

        Args:
            target_type: 지정 시 해당 타입의 VXISScore만 반환.
                         None이면 전체 dict를 반환.

        Returns:
            target_type 지정 시: VXISScore | None
            target_type 없음: dict[str, VXISScore]
        """
        if not self.baseline_path.exists():
            logger.warning("[BENCHMARK] Baseline file not found: %s", self.baseline_path)
            if target_type is not None:
                return None
            return {}

        try:
            with self.baseline_path.open("r", encoding="utf-8") as f:
                raw: dict = json.load(f)
        except json.JSONDecodeError as exc:
            logger.error("[BENCHMARK] Failed to parse baseline JSON: %s", exc)
            if target_type is not None:
                return None
            return {}

        all_scores: dict[str, VXISScore] = {}
        for ttype, data in raw.items():
            if not isinstance(data, dict):
                continue
            try:
                all_scores[ttype] = _dict_to_vxis_score(data)
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning(
                    "[BENCHMARK] Failed to deserialize baseline for %s: %s",
                    ttype, exc,
                )

        if target_type is not None:
            return all_scores.get(target_type)
        return all_scores

    def save_baseline(self, score: VXISScore) -> None:
        """VXISScore를 baseline.json에 저장한다.

        기존 파일이 있으면 해당 target_type의 데이터만 업데이트한다.
        """
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)

        # 기존 데이터 로드
        existing: dict = {}
        if self.baseline_path.exists():
            try:
                with self.baseline_path.open("r", encoding="utf-8") as f:
                    existing = json.load(f)
            except (json.JSONDecodeError, OSError):
                existing = {}

        # 업데이트
        score_dict = score.to_dict()
        score_dict["updated_at"] = datetime.now(timezone.utc).isoformat()
        existing[score.target_type] = score_dict

        with self.baseline_path.open("w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)

        logger.info(
            "[BENCHMARK] Baseline saved for %s: %.1f [%s]",
            score.target_type, score.total, score.grade,
        )

    def compare_with_baseline(
        self,
        current: VXISScore,
    ) -> ScoreComparison:
        """현재 점수를 저장된 베이스라인과 비교한다.

        베이스라인이 없으면 현재 점수를 베이스라인으로 사용한다 (첫 실행).
        """
        baseline = self.load_baseline(target_type=current.target_type)

        if baseline is None:
            logger.info(
                "[BENCHMARK] No baseline found for %s — using current as baseline",
                current.target_type,
            )
            baseline = current  # type: ignore[assignment]

        engine = ScoringEngine(current.target_type)
        return engine.compare(baseline, current)  # type: ignore[arg-type]

    def generate_report(
        self,
        comparison: ScoreComparison,
        format: str = "markdown",
    ) -> str:
        """비교 결과를 지정된 형식으로 리포트를 생성한다.

        Args:
            comparison: ScoreComparison 객체.
            format: "markdown" | "telegram" | "github"

        Returns:
            리포트 문자열.
        """
        if format == "markdown":
            return self._reporter.generate_markdown(comparison)
        elif format == "telegram":
            return self._reporter.generate_telegram_message(comparison)
        elif format == "github":
            return self._reporter.generate_github_comment(comparison)
        else:
            raise ValueError(
                f"Unknown report format: {format!r}. "
                f"Must be one of: markdown, telegram, github"
            )

    def is_regression(self, comparison: ScoreComparison) -> bool:
        """CI 종료 코드 결정을 위한 회귀 여부 반환."""
        return comparison.regression

    # ─────────────────────────────────────────────────────────────────────
    # Private Helpers
    # ─────────────────────────────────────────────────────────────────────

    async def _execute_pipeline(
        self,
        target_type: str,
        target_url: str,
        scan_id: str,
    ):
        """타겟 타입에 맞는 파이프라인을 실행하고 ScanContext를 반환한다."""
        brain_mode = os.environ.get("VXIS_BRAIN_MODE", "api")
        if brain_mode == "claude-code":
            from vxis.agent.brain_filebased import FileBasedBrain
            brain = FileBasedBrain()
            logger.info("[BENCHMARK] Brain mode: claude-code (FileBasedBrain)")
        else:
            from vxis.agent.brain import AgentBrain
            brain = AgentBrain()
            logger.info("[BENCHMARK] Brain mode: api (AgentBrain)")

        if target_type == "web":
            from vxis.pipeline.pipeline import ScanPipeline
            pipeline = ScanPipeline(brain=brain)
            ctx = await pipeline.run(target=target_url)
        elif target_type == "game":
            # game_pipeline은 아직 미구현 — web 파이프라인으로 fallback
            from vxis.pipeline.pipeline import ScanPipeline
            pipeline = ScanPipeline(brain=brain)
            ctx = await pipeline.run(target=target_url)
        elif target_type == "mobile":
            from vxis.pipeline.mobile_pipeline import MobilePipeline
            pipeline = MobilePipeline()
            ctx = await pipeline.run(target=target_url)
        else:
            raise ValueError(f"Unknown target_type: {target_type!r}")

        if brain_mode == "claude-code" and hasattr(brain, "mark_done"):
            brain.mark_done()

        return ctx


# ─────────────────────────────────────────────────────────────────────
# Serialization Helpers
# ─────────────────────────────────────────────────────────────────────

def _generate_scan_id(target_type: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    pid = os.getpid()
    return f"BENCH-{target_type.upper()}-{ts}-{pid}"


def _dict_to_dimension_score(key: str, data: dict) -> DimensionScore:
    """dict를 DimensionScore로 역직렬화한다."""
    return DimensionScore(
        name=data["name"],
        name_ko=data["name_ko"],
        score=float(data["score"]),
        max_score=float(data["max_score"]),
        percentage=float(data["percentage"]),
        details=data.get("details", {}),
    )


def _dict_to_vxis_score(data: dict) -> VXISScore:
    """dict를 VXISScore로 역직렬화한다."""
    dims = data["dimensions"]

    vc = _dict_to_dimension_score("vector_coverage", dims["vector_coverage"])
    er = _dict_to_dimension_score("exploitation_reach", dims["exploitation_reach"])
    ci = _dict_to_dimension_score("chain_intelligence", dims["chain_intelligence"])
    fp = _dict_to_dimension_score("finding_precision", dims["finding_precision"])
    co = _dict_to_dimension_score("completeness", dims["completeness"])

    return VXISScore(
        total=float(data["total"]),
        grade=data["grade"],
        target_type=data["target_type"],
        scan_id=data.get("scan_id", ""),
        timestamp=data.get("timestamp", ""),
        vector_coverage=vc,
        exploitation_reach=er,
        chain_intelligence=ci,
        finding_precision=fp,
        completeness=co,
    )


def vxis_score_from_dict(data: dict) -> VXISScore:
    """공개 역직렬화 함수 — baseline.json 파싱에 사용."""
    return _dict_to_vxis_score(data)
