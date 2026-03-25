"""VXIS Token Router — 모델 티어별 작업 라우팅 + 토큰 비용 최적화.

공장의 원가관리처럼, 작업 유형에 따라 최적의 모델 등급을 선택한다.

Tier Architecture:
    ┌─────────────────────────────────────────────────┐
    │ Tier 0: CODE          — 토큰 $0, 즉시 실행       │
    │   규칙 기반 파싱, 정규식 매칭, 결과 정규화           │
    ├─────────────────────────────────────────────────┤
    │ Tier 1: COMPILED      — 토큰 $0, 즉시 실행       │
    │   과거 학습된 패턴 기반 판단 (KnowledgeStore)       │
    ├─────────────────────────────────────────────────┤
    │ Tier 2: HAIKU         — 토큰 $0.25/M             │
    │   단순 분류, 패턴 확인, 데이터 요약                  │
    ├─────────────────────────────────────────────────┤
    │ Tier 3: SONNET        — 토큰 $3/M                │
    │   취약점 분석, 복잡한 데이터 해석                    │
    ├─────────────────────────────────────────────────┤
    │ Tier 4: OPUS          — 토큰 $15/M               │
    │   전략 수립, 공격 체인 추론, 새로운 상황 판단         │
    └─────────────────────────────────────────────────┘

핵심: Opus는 "진짜 생각이 필요할 때만" 호출.
      나머지 95%는 Code + Compiled + Haiku로 처리.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ModelTier(str, Enum):
    """모델 등급. 위로 갈수록 저렴하고 빠름."""

    CODE = "code"  # LLM 불필요, 코드로 처리
    COMPILED = "compiled"  # 컴파일된 패턴으로 처리
    HAIKU = "haiku"  # 경량 LLM
    SONNET = "sonnet"  # 중간 LLM
    OPUS = "opus"  # 최강 LLM


class TaskType(str, Enum):
    """작업 유형 분류."""

    # Tier 0: CODE
    PARSE_OUTPUT = "parse_output"  # 도구 출력 파싱
    NORMALIZE = "normalize"  # 결과 정규화
    DEDUPLICATE = "deduplicate"  # 중복 제거

    # Tier 1: COMPILED
    PATTERN_MATCH = "pattern_match"  # 컴파일된 패턴 매칭
    TOOL_SELECTION = "tool_selection"  # 도구 선택 (학습된 패턴)

    # Tier 2: HAIKU
    CLASSIFY = "classify"  # 서비스/취약점 분류
    SUMMARIZE = "summarize"  # 결과 요약
    CONFIRM_PATTERN = "confirm_pattern"  # 패턴 매칭 확인

    # Tier 3: SONNET
    ANALYZE_VULN = "analyze_vuln"  # 취약점 심층 분석
    DECODE_OBFUSCATED = "decode_obfuscated"  # 난독화 해제
    ANALYZE_BINARY = "analyze_binary"  # 바이너리 분석

    # Tier 4: OPUS
    STRATEGY = "strategy"  # 전략 수립
    CHAIN_REASONING = "chain_reasoning"  # 공격 체인 추론
    UNKNOWN_SITUATION = "unknown_situation"  # 새로운/예상 못한 상황
    HYPOTHESIS = "hypothesis"  # 가설 생성
    REFLECTION = "reflection"  # 자기 평가 + 전략 전환


# 작업 유형 → 모델 등급 매핑
_TASK_TIER_MAP: dict[TaskType, ModelTier] = {
    TaskType.PARSE_OUTPUT: ModelTier.CODE,
    TaskType.NORMALIZE: ModelTier.CODE,
    TaskType.DEDUPLICATE: ModelTier.CODE,
    TaskType.PATTERN_MATCH: ModelTier.COMPILED,
    TaskType.TOOL_SELECTION: ModelTier.COMPILED,
    TaskType.CLASSIFY: ModelTier.HAIKU,
    TaskType.SUMMARIZE: ModelTier.HAIKU,
    TaskType.CONFIRM_PATTERN: ModelTier.HAIKU,
    TaskType.ANALYZE_VULN: ModelTier.SONNET,
    TaskType.DECODE_OBFUSCATED: ModelTier.SONNET,
    TaskType.ANALYZE_BINARY: ModelTier.SONNET,
    TaskType.STRATEGY: ModelTier.OPUS,
    TaskType.CHAIN_REASONING: ModelTier.OPUS,
    TaskType.UNKNOWN_SITUATION: ModelTier.OPUS,
    TaskType.HYPOTHESIS: ModelTier.OPUS,
    TaskType.REFLECTION: ModelTier.OPUS,
}

# 모델 등급별 비용 (토큰 1M당 USD, input 기준)
_TIER_COST: dict[ModelTier, float] = {
    ModelTier.CODE: 0.0,
    ModelTier.COMPILED: 0.0,
    ModelTier.HAIKU: 0.25,
    ModelTier.SONNET: 3.0,
    ModelTier.OPUS: 15.0,
}

# 모델 등급별 기본 모델 ID
# Anthropic 기본값 + Together.ai 대체 모델
_TIER_MODEL_ID: dict[ModelTier, str] = {
    ModelTier.CODE: "",  # LLM 불필요
    ModelTier.COMPILED: "",  # LLM 불필요
    ModelTier.HAIKU: "claude-haiku-4-5-20251001",
    ModelTier.SONNET: "claude-sonnet-4-6",
    ModelTier.OPUS: "claude-opus-4-6",
}

# Together.ai 대체 모델 (Anthropic 사용 불가 시)
_TOGETHER_FALLBACK_MODEL: dict[ModelTier, str] = {
    ModelTier.CODE: "",
    ModelTier.COMPILED: "",
    ModelTier.HAIKU: "meta-llama/Llama-3.3-70B-Instruct-Turbo",  # $0.88/M
    ModelTier.SONNET: "zai-org/GLM-5",  # $1.00/M, agent 특화
    ModelTier.OPUS: "moonshotai/Kimi-K2.5",  # $0.50/M, 1T params 추론 특화
}


@dataclass
class TokenUsage:
    """토큰 사용량 추적."""

    tier: ModelTier
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    task_type: str = ""

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class RoutingDecision:
    """라우팅 결정 결과."""

    tier: ModelTier
    model_id: str
    reasoning: str
    estimated_cost: float  # 예상 비용 (USD)
    can_skip_llm: bool  # LLM 호출 없이 처리 가능 여부


class TokenRouter:
    """작업을 최적의 모델 등급으로 라우팅하는 엔진.

    Usage:
        router = TokenRouter()
        decision = router.route(TaskType.STRATEGY, context)

        if decision.can_skip_llm:
            # 코드/컴파일 패턴으로 처리
            result = handle_locally(...)
        else:
            # LLM 호출
            result = call_llm(decision.model_id, ...)

        router.record_usage(decision.tier, input_tokens, output_tokens)
    """

    def __init__(self) -> None:
        self._usage_history: list[TokenUsage] = []
        self._total_cost: float = 0.0
        self._tier_counts: dict[ModelTier, int] = {t: 0 for t in ModelTier}

    def route(
        self,
        task_type: TaskType,
        context: dict[str, Any] | None = None,
    ) -> RoutingDecision:
        """작업 유형과 맥락을 기반으로 최적의 모델 등급을 결정한다.

        Args:
            task_type: 작업 유형
            context: 추가 맥락 (optional)
                - compiled_pattern_available: bool
                - confidence: float
                - complexity: str ("low", "medium", "high")

        Returns:
            RoutingDecision
        """
        context = context or {}
        tier = _TASK_TIER_MAP.get(task_type, ModelTier.SONNET)

        # 동적 승격/강등
        tier = self._adjust_tier(tier, task_type, context)

        model_id = self._get_model_id(tier)
        can_skip_llm = tier in (ModelTier.CODE, ModelTier.COMPILED)
        estimated_cost = self._estimate_cost(tier, context)

        decision = RoutingDecision(
            tier=tier,
            model_id=model_id,
            reasoning=self._build_reasoning(tier, task_type, context),
            estimated_cost=estimated_cost,
            can_skip_llm=can_skip_llm,
        )

        self._tier_counts[tier] += 1

        logger.debug(
            "라우팅: %s → %s (모델: %s, 예상비용: $%.4f)",
            task_type.value, tier.value, model_id, estimated_cost,
        )

        return decision

    def _adjust_tier(
        self,
        base_tier: ModelTier,
        task_type: TaskType,
        context: dict[str, Any],
    ) -> ModelTier:
        """맥락에 따라 동적으로 등급을 조정한다."""
        # 컴파일된 패턴이 있으면 CODE/COMPILED로 강등
        if (
            context.get("compiled_pattern_available")
            and context.get("confidence", 0) > 0.85
        ):
            return ModelTier.COMPILED

        # 컴파일 패턴 신뢰도가 중간이면 Haiku로 확인만
        if (
            context.get("compiled_pattern_available")
            and context.get("confidence", 0) > 0.5
        ):
            return ModelTier.HAIKU

        # 복잡도가 낮으면 한 등급 강등
        if context.get("complexity") == "low" and base_tier in (
            ModelTier.OPUS, ModelTier.SONNET,
        ):
            tiers = list(ModelTier)
            idx = tiers.index(base_tier)
            return tiers[max(0, idx - 1)]

        # 새로운 상황이면 무조건 Opus로 승격
        if context.get("is_novel_situation"):
            return ModelTier.OPUS

        return base_tier

    def _get_model_id(self, tier: ModelTier) -> str:
        """환경 변수 오버라이드를 지원하는 모델 ID 조회.

        우선순위:
        1. 환경변수 오버라이드 (VXIS_MODEL_OPUS 등)
        2. CLI 구독 (claude/gemini/codex CLI 감지 시 → $0)
        3. Anthropic 기본 모델
        4. Together.ai 대체 모델
        """
        import shutil

        env_key = f"VXIS_MODEL_{tier.value.upper()}"
        env_override = os.environ.get(env_key)
        if env_override:
            return env_override

        # CLI 구독 우선 — $0 (Tier 2+ 에서만, CODE/COMPILED은 LLM 불필요)
        if tier not in (ModelTier.CODE, ModelTier.COMPILED):
            if shutil.which("claude"):
                return "claude-cli"
            if shutil.which("gemini"):
                return "gemini-cli"
            if shutil.which("codex"):
                return "codex-cli"

        # Anthropic 키가 있으면 기본 모델 사용
        if os.environ.get("ANTHROPIC_API_KEY"):
            return _TIER_MODEL_ID.get(tier, "")

        # Together.ai 대체 모델
        if os.environ.get("TOGETHER_API_KEY"):
            return _TOGETHER_FALLBACK_MODEL.get(tier, "")

        return _TIER_MODEL_ID.get(tier, "")

    @staticmethod
    def _estimate_cost(
        tier: ModelTier, context: dict[str, Any],
    ) -> float:
        """예상 토큰 비용을 계산한다."""
        base_cost = _TIER_COST.get(tier, 0.0)
        estimated_tokens = context.get("estimated_tokens", 2000)
        return base_cost * estimated_tokens / 1_000_000

    @staticmethod
    def _build_reasoning(
        tier: ModelTier,
        task_type: TaskType,
        context: dict[str, Any],
    ) -> str:
        """라우팅 판단의 이유를 설명."""
        reasons = {
            ModelTier.CODE: "규칙 기반으로 처리 가능 → LLM 불필요",
            ModelTier.COMPILED: "컴파일된 패턴 매칭 → LLM 불필요",
            ModelTier.HAIKU: "단순 분류/확인 작업 → 경량 모델 사용",
            ModelTier.SONNET: "분석 필요하지만 창의적 추론은 불필요",
            ModelTier.OPUS: "전략적 판단/체인 추론 필요 → 최강 모델 사용",
        }
        return reasons.get(tier, f"{task_type.value} → {tier.value}")

    # ── Usage Tracking ───────────────────────────────────────────

    def record_usage(
        self,
        tier: ModelTier,
        input_tokens: int = 0,
        output_tokens: int = 0,
        task_type: str = "",
    ) -> None:
        """토큰 사용량을 기록한다."""
        cost = _TIER_COST.get(tier, 0.0) * (input_tokens + output_tokens) / 1_000_000
        usage = TokenUsage(
            tier=tier,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            task_type=task_type,
        )
        self._usage_history.append(usage)
        self._total_cost += cost

    def get_usage_stats(self) -> dict[str, Any]:
        """전체 토큰 사용 통계."""
        tier_stats: dict[str, dict[str, Any]] = {}

        for tier in ModelTier:
            tier_usages = [u for u in self._usage_history if u.tier == tier]
            total_tokens = sum(u.total_tokens for u in tier_usages)
            total_cost = sum(u.cost_usd for u in tier_usages)
            tier_stats[tier.value] = {
                "calls": len(tier_usages),
                "total_tokens": total_tokens,
                "total_cost_usd": round(total_cost, 4),
            }

        return {
            "total_cost_usd": round(self._total_cost, 4),
            "total_calls": len(self._usage_history),
            "tier_breakdown": tier_stats,
            "tier_distribution": {
                tier.value: self._tier_counts[tier]
                for tier in ModelTier
            },
            "savings_estimate": self._estimate_savings(),
        }

    def _estimate_savings(self) -> dict[str, Any]:
        """모든 작업을 Opus로 했을 때 대비 절약된 비용 추정."""
        opus_cost_per_token = _TIER_COST[ModelTier.OPUS]
        hypothetical_cost = sum(
            opus_cost_per_token * u.total_tokens / 1_000_000
            for u in self._usage_history
        )
        actual_cost = self._total_cost
        saved = hypothetical_cost - actual_cost

        return {
            "if_all_opus_usd": round(hypothetical_cost, 4),
            "actual_cost_usd": round(actual_cost, 4),
            "saved_usd": round(saved, 4),
            "savings_percent": (
                round(saved / hypothetical_cost * 100, 1)
                if hypothetical_cost > 0
                else 0.0
            ),
        }

    def format_usage_report(self) -> str:
        """사용량 리포트를 포맷팅한다."""
        stats = self.get_usage_stats()
        lines = ["## Token Usage Report"]
        lines.append(f"총 비용: ${stats['total_cost_usd']}")
        lines.append(f"총 호출: {stats['total_calls']}회")

        savings = stats["savings_estimate"]
        if savings["savings_percent"] > 0:
            lines.append(
                f"절약: ${savings['saved_usd']} "
                f"({savings['savings_percent']}% — 전부 Opus 대비)"
            )

        lines.append("\n### 등급별 분포")
        for tier, data in stats["tier_breakdown"].items():
            if data["calls"] > 0:
                lines.append(
                    f"- {tier}: {data['calls']}회, "
                    f"{data['total_tokens']:,} tokens, "
                    f"${data['total_cost_usd']}"
                )

        return "\n".join(lines)
