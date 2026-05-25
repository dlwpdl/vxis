"""VXIS Knowledge Store — 능력별 지식 축적 + 컴파일된 패턴 시스템.

에이전트가 실행할 때마다 유의미한 결과를 축적하고,
반복되는 패턴을 "컴파일"하여 LLM 호출 없이 재사용한다.

Architecture:
    ┌─────────────────────────────────────────┐
    │  Knowledge Store                         │
    ├─────────────────────────────────────────┤
    │  ExecutionRecord   — 개별 도구 실행 기록  │
    │  CompiledPattern   — 컴파일된 판단 패턴   │
    │  CapabilityProfile — 능력별 누적 지식     │
    │  CorrelationRule   — 서비스 간 상관관계   │
    └─────────────────────────────────────────┘

Storage: ~/.vxis/knowledge_store.json

핵심 원칙:
    - 의미 있는 결과만 저장 (노이즈 제거)
    - 패턴이 반복되면 자동 컴파일 (LLM 호출 절약)
    - 쓸수록 강해지는 구조 (Day 1: 비쌈 → Day 100: 저렴 & 최강)
"""

from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_DEFAULT_STORE_PATH = "~/.vxis/knowledge_store.json"
_MAX_RECORDS = 2000
_COMPILE_THRESHOLD = 3  # 동일 패턴 3회 반복 시 컴파일


# ── Data Models ──────────────────────────────────────────────────


@dataclass
class ExecutionRecord:
    """단일 도구 실행의 핵심 요약."""

    tool: str
    context_signature: str  # 실행 맥락의 해시 (e.g. "nginx+mysql+port80")
    args_summary: str  # 주요 인자 요약
    effectiveness: float  # 0.0~1.0 (발견 기여도)
    findings_produced: int
    finding_types: list[str]  # ["sqli", "xss", ...]
    target_tech: list[str]  # 타겟의 기술 스택
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionRecord:
        return cls(
            tool=data.get("tool", ""),
            context_signature=data.get("context_signature", ""),
            args_summary=data.get("args_summary", ""),
            effectiveness=data.get("effectiveness", 0.0),
            findings_produced=data.get("findings_produced", 0),
            finding_types=data.get("finding_types", []),
            target_tech=data.get("target_tech", []),
            timestamp=data.get("timestamp", ""),
        )


@dataclass
class CompiledPattern:
    """LLM이 발견한 판단 패턴을 코드로 컴파일한 것.

    다음번에 같은 상황이면 LLM 호출 없이 이 패턴을 사용한다.
    """

    id: str
    context_signature: str  # 매칭 조건 (e.g. "nginx+mysql")
    action_tool: str  # 실행할 도구
    action_args: dict[str, Any]  # 도구 인자
    reasoning: str  # 왜 이 판단을 했는지
    confidence: float  # 0.0~1.0 (패턴 신뢰도)
    hit_count: int  # 이 패턴이 매칭된 횟수
    success_count: int  # 성공한 횟수
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_used: str = ""

    @property
    def success_rate(self) -> float:
        return self.success_count / self.hit_count if self.hit_count > 0 else 0.0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CompiledPattern:
        return cls(
            id=data.get("id", ""),
            context_signature=data.get("context_signature", ""),
            action_tool=data.get("action_tool", ""),
            action_args=data.get("action_args", {}),
            reasoning=data.get("reasoning", ""),
            confidence=data.get("confidence", 0.0),
            hit_count=data.get("hit_count", 0),
            success_count=data.get("success_count", 0),
            created_at=data.get("created_at", ""),
            last_used=data.get("last_used", ""),
        )


@dataclass
class CorrelationRule:
    """서비스 간 상관관계 규칙.

    예: "MongoDB 있으면 Node.js 확률 80%"
    """

    if_present: list[str]  # 조건 (e.g. ["mongodb"])
    then_likely: list[str]  # 추론 (e.g. ["nodejs", "express"])
    probability: float  # 0.0~1.0
    observed_count: int  # 관찰 횟수
    source: str  # "compiled" | "manual"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CorrelationRule:
        return cls(
            if_present=data.get("if_present", []),
            then_likely=data.get("then_likely", []),
            probability=data.get("probability", 0.0),
            observed_count=data.get("observed_count", 0),
            source=data.get("source", "compiled"),
        )


@dataclass
class CapabilityProfile:
    """특정 능력(도구)의 누적 성과 프로필."""

    tool: str
    total_runs: int = 0
    total_findings: int = 0
    avg_effectiveness: float = 0.0
    best_against: list[str] = field(default_factory=list)  # 잘 먹히는 기술 스택
    worst_against: list[str] = field(default_factory=list)  # 안 먹히는 기술 스택
    best_args: dict[str, Any] = field(default_factory=dict)  # 가장 효과적인 인자
    avg_cost_tokens: int = 0  # 평균 토큰 소비

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CapabilityProfile:
        return cls(
            tool=data.get("tool", ""),
            total_runs=data.get("total_runs", 0),
            total_findings=data.get("total_findings", 0),
            avg_effectiveness=data.get("avg_effectiveness", 0.0),
            best_against=data.get("best_against", []),
            worst_against=data.get("worst_against", []),
            best_args=data.get("best_args", {}),
            avg_cost_tokens=data.get("avg_cost_tokens", 0),
        )


# ── Knowledge Store ──────────────────────────────────────────────


class KnowledgeStore:
    """능력별 지식 축적 + 컴파일된 패턴 관리 시스템.

    Usage:
        store = KnowledgeStore()

        # 실행 결과 기록
        store.record_execution(record)

        # 컴파일된 패턴 조회 (LLM 호출 절약)
        pattern = store.match_pattern(context_sig)
        if pattern and pattern.confidence > 0.85:
            # LLM 없이 바로 실행
            execute(pattern.action_tool, pattern.action_args)

        # 능력 프로필 조회
        profile = store.get_capability_profile("nuclei")
    """

    def __init__(self, store_path: str = _DEFAULT_STORE_PATH) -> None:
        self._path = Path(os.path.expanduser(store_path)).resolve()
        self._records: list[ExecutionRecord] = []
        self._patterns: list[CompiledPattern] = []
        self._correlations: list[CorrelationRule] = []
        self._profiles: dict[str, CapabilityProfile] = {}
        self._pending_compilations: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._load()

    # ── Recording ────────────────────────────────────────────────

    def record_execution(self, record: ExecutionRecord) -> None:
        """도구 실행 결과를 기록하고, 패턴 컴파일 조건을 확인한다."""
        # 무의미한 결과 필터링 (effectiveness가 0이고 발견도 없으면 스킵)
        if record.effectiveness <= 0 and record.findings_produced <= 0:
            # 실패한 시도도 "이건 안 먹힌다"는 지식이 됨
            self._record_negative(record)
            return

        self._records.append(record)

        # 최대 크기 관리
        if len(self._records) > _MAX_RECORDS:
            removed = len(self._records) - _MAX_RECORDS
            self._records = self._records[removed:]

        # 능력 프로필 업데이트
        self._update_profile(record)

        # 패턴 컴파일 후보 추가
        self._pending_compilations[record.context_signature].append(
            {
                "tool": record.tool,
                "args": record.args_summary,
                "effectiveness": record.effectiveness,
                "finding_types": record.finding_types,
            }
        )

        # 컴파일 조건 확인: 같은 맥락에서 3회 이상 동일 도구가 효과적
        self._try_compile(record.context_signature)

        # 상관관계 학습
        self._learn_correlation(record)

        self._save()

    def _record_negative(self, record: ExecutionRecord) -> None:
        """효과 없던 실행도 지식으로 축적 (worst_against 업데이트)."""
        profile = self._profiles.get(record.tool)
        if profile is None:
            profile = CapabilityProfile(tool=record.tool)
            self._profiles[record.tool] = profile

        profile.total_runs += 1

        for tech in record.target_tech:
            tech_lower = tech.lower()
            if tech_lower not in profile.worst_against:
                # 3회 이상 실패해야 worst_against에 추가
                fail_count = sum(
                    1
                    for r in self._records
                    if r.tool == record.tool
                    and tech_lower in [t.lower() for t in r.target_tech]
                    and r.effectiveness <= 0
                )
                if fail_count >= 3:
                    profile.worst_against.append(tech_lower)

    # ── Pattern Compilation ──────────────────────────────────────

    def _try_compile(self, context_sig: str) -> None:
        """반복된 성공 패턴을 컴파일된 패턴으로 승격시킨다."""
        candidates = self._pending_compilations.get(context_sig, [])
        if len(candidates) < _COMPILE_THRESHOLD:
            return

        # 도구별 성공률 집계
        tool_stats: dict[str, list[float]] = defaultdict(list)
        tool_args: dict[str, list[str]] = defaultdict(list)

        for c in candidates:
            tool_stats[c["tool"]].append(c["effectiveness"])
            tool_args[c["tool"]].append(c["args"])

        for tool, scores in tool_stats.items():
            avg_score = sum(scores) / len(scores)
            if avg_score >= 0.5 and len(scores) >= _COMPILE_THRESHOLD:
                # 이미 같은 패턴이 있는지 확인
                existing = self._find_pattern(context_sig, tool)
                if existing:
                    existing.hit_count += 1
                    existing.confidence = min(0.99, existing.confidence + 0.05)
                    existing.last_used = datetime.now(timezone.utc).isoformat()
                else:
                    # 새 패턴 컴파일
                    most_common_args = (
                        max(
                            set(tool_args[tool]),
                            key=tool_args[tool].count,
                        )
                        if tool_args[tool]
                        else ""
                    )

                    pattern = CompiledPattern(
                        id=f"{context_sig}:{tool}:{len(self._patterns)}",
                        context_signature=context_sig,
                        action_tool=tool,
                        action_args={"summary": most_common_args},
                        reasoning=f"Auto-compiled: {tool} shows {avg_score:.0%} effectiveness in context '{context_sig}' over {len(scores)} runs",
                        confidence=min(0.95, avg_score),
                        hit_count=len(scores),
                        success_count=sum(1 for s in scores if s > 0),
                    )
                    self._patterns.append(pattern)
                    logger.info(
                        "패턴 컴파일: %s → %s (신뢰도 %.0f%%, %d회 관찰)",
                        context_sig,
                        tool,
                        pattern.confidence * 100,
                        len(scores),
                    )

    def _find_pattern(
        self,
        context_sig: str,
        tool: str,
    ) -> Optional[CompiledPattern]:
        for p in self._patterns:
            if p.context_signature == context_sig and p.action_tool == tool:
                return p
        return None

    # ── Pattern Matching ─────────────────────────────────────────

    def match_patterns(self, context_sig: str) -> list[CompiledPattern]:
        """주어진 맥락에 매칭되는 컴파일된 패턴을 반환한다.

        Args:
            context_sig: 현재 맥락 시그니처 (e.g. "nginx+mysql+port80")

        Returns:
            매칭된 패턴 목록 (confidence 내림차순)
        """
        matched = []
        sig_parts = set(context_sig.lower().split("+"))

        for pattern in self._patterns:
            pattern_parts = set(pattern.context_signature.lower().split("+"))

            # 부분 매칭도 허용 (70% 이상 겹치면)
            if not pattern_parts:
                continue

            overlap = len(sig_parts & pattern_parts) / len(pattern_parts)
            if overlap >= 0.7:
                matched.append(pattern)

        matched.sort(key=lambda p: p.confidence, reverse=True)
        return matched

    def record_pattern_outcome(
        self,
        pattern_id: str,
        success: bool,
    ) -> None:
        """패턴 실행 결과를 피드백하여 신뢰도를 조정한다."""
        for p in self._patterns:
            if p.id == pattern_id:
                p.hit_count += 1
                if success:
                    p.success_count += 1
                    p.confidence = min(0.99, p.confidence + 0.02)
                else:
                    p.confidence = max(0.1, p.confidence - 0.1)
                p.last_used = datetime.now(timezone.utc).isoformat()

                # 신뢰도가 너무 낮으면 패턴 제거
                if p.confidence < 0.2 and p.hit_count >= 5:
                    self._patterns.remove(p)
                    logger.info("패턴 폐기 (신뢰도 %.0f%%): %s", p.confidence * 100, p.id)

                self._save()
                return

    # ── Finding Recording ────────────────────────────────────────

    def record_finding(self, finding: Any) -> None:
        """취약점 Finding을 ExecutionRecord로 변환하여 지식 축적.

        Finding의 source_plugin, finding_type, severity 등을
        KnowledgeStore의 패턴 컴파일 시스템에 태운다.
        다음 스캔 시 동일 tech_stack에서 효과적인 도구/벡터를 추천 가능.
        """
        # Finding → ExecutionRecord 변환
        source = getattr(finding, "source_plugin", "unknown")
        ftype = getattr(finding, "finding_type", "vulnerability")
        severity = getattr(finding, "severity", None)
        sev_str = severity.value if hasattr(severity, "value") else str(severity or "")
        getattr(finding, "target", "")
        component = getattr(finding, "affected_component", "")

        # effectiveness: severity 기반 (critical=1.0, high=0.8, medium=0.5, low=0.3, info=0.1)
        sev_score = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
            "informational": 0.1,
        }.get(sev_str, 0.3)

        # context_signature: target의 tech_stack 또는 component 기반
        ctx_parts = [p for p in [source, component, ftype] if p]
        context_sig = "+".join(ctx_parts) if ctx_parts else source

        record = ExecutionRecord(
            tool=source,
            context_signature=context_sig,
            args_summary=f"{ftype}:{sev_str}",
            effectiveness=sev_score,
            findings_produced=1,
            finding_types=[ftype],
            target_tech=[component] if component else [],
        )
        self.record_execution(record)

    # ── Correlation Learning ─────────────────────────────────────

    def _learn_correlation(self, record: ExecutionRecord) -> None:
        """실행 기록에서 기술 간 상관관계를 학습한다."""
        if len(record.target_tech) < 2:
            return

        tech_set = [t.lower() for t in record.target_tech]

        # 모든 2-조합에 대해 상관관계 업데이트
        for i, tech_a in enumerate(tech_set):
            for tech_b in tech_set[i + 1 :]:
                self._update_correlation([tech_a], [tech_b])

    def _update_correlation(
        self,
        if_present: list[str],
        then_likely: list[str],
    ) -> None:
        """상관관계 규칙을 업데이트하거나 새로 생성한다."""
        for rule in self._correlations:
            if set(rule.if_present) == set(if_present) and set(rule.then_likely) == set(
                then_likely
            ):
                rule.observed_count += 1
                # 관찰 횟수에 따라 확률 점진적 조정
                rule.probability = min(0.95, rule.probability + 0.02)
                return

        # 새 규칙 (초기 확률 낮게 시작)
        self._correlations.append(
            CorrelationRule(
                if_present=if_present,
                then_likely=then_likely,
                probability=0.3,
                observed_count=1,
                source="compiled",
            )
        )

    def get_correlations(self, tech_stack: list[str]) -> list[CorrelationRule]:
        """주어진 기술 스택에서 추론 가능한 상관관계를 반환한다."""
        tech_lower = {t.lower() for t in tech_stack}
        matched = []

        for rule in self._correlations:
            if set(rule.if_present).issubset(tech_lower):
                if rule.probability >= 0.5 and rule.observed_count >= 3:
                    matched.append(rule)

        matched.sort(key=lambda r: r.probability, reverse=True)
        return matched

    # ── Capability Profiles ──────────────────────────────────────

    def _update_profile(self, record: ExecutionRecord) -> None:
        """도구 실행 기록으로 능력 프로필을 업데이트한다."""
        profile = self._profiles.get(record.tool)
        if profile is None:
            profile = CapabilityProfile(tool=record.tool)
            self._profiles[record.tool] = profile

        profile.total_runs += 1
        profile.total_findings += record.findings_produced

        # 이동 평균으로 effectiveness 업데이트
        alpha = 0.3  # 최근 데이터에 더 많은 가중치
        profile.avg_effectiveness = (
            alpha * record.effectiveness + (1 - alpha) * profile.avg_effectiveness
        )

        # best_against / worst_against 업데이트
        for tech in record.target_tech:
            tech_lower = tech.lower()
            if record.effectiveness >= 0.6:
                if tech_lower not in profile.best_against:
                    profile.best_against.append(tech_lower)
                    # worst에서 제거 (승격)
                    if tech_lower in profile.worst_against:
                        profile.worst_against.remove(tech_lower)

    def get_capability_profile(self, tool: str) -> Optional[CapabilityProfile]:
        """특정 도구의 능력 프로필을 반환한다."""
        return self._profiles.get(tool)

    def get_recommended_tools(
        self,
        tech_stack: list[str],
        top_n: int = 5,
    ) -> list[tuple[str, float]]:
        """기술 스택에 가장 효과적인 도구를 추천한다.

        Returns:
            (도구명, 예상 효과) 튜플 리스트 (내림차순)
        """
        tech_lower = {t.lower() for t in tech_stack}
        scored: list[tuple[str, float]] = []

        for tool, profile in self._profiles.items():
            if profile.total_runs < 2:
                continue

            # 기본 점수 = 평균 효과
            score = profile.avg_effectiveness

            # best_against 보너스
            best_overlap = len(tech_lower & set(profile.best_against))
            score += best_overlap * 0.15

            # worst_against 페널티
            worst_overlap = len(tech_lower & set(profile.worst_against))
            score -= worst_overlap * 0.2

            score = max(0.0, min(1.0, score))
            scored.append((tool, round(score, 3)))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_n]

    def get_tools_to_skip(self, tech_stack: list[str]) -> list[str]:
        """주어진 기술 스택에서 효과 없을 도구를 반환한다."""
        tech_lower = {t.lower() for t in tech_stack}
        skip = []

        for tool, profile in self._profiles.items():
            if profile.total_runs < 3:
                continue

            # 전체 효과가 낮고, worst_against에 현재 기술이 있으면
            if (
                profile.avg_effectiveness < 0.15
                and len(tech_lower & set(profile.worst_against)) > 0
            ):
                skip.append(tool)

        return skip

    # ── Context Signature Builder ────────────────────────────────

    @staticmethod
    def build_context_signature(
        tech_stack: list[str],
        open_ports: list[int] | None = None,
        services: list[str] | None = None,
    ) -> str:
        """현재 맥락의 시그니처를 생성한다.

        동일한 맥락은 동일한 시그니처를 생성하여 패턴 매칭에 사용.
        """
        parts = sorted(t.lower().strip() for t in tech_stack if t.strip())

        if open_ports:
            # 대표 포트만 포함 (너무 상세하면 매칭이 안 됨)
            notable_ports = {
                80: "http",
                443: "https",
                22: "ssh",
                3306: "mysql",
                5432: "postgres",
                27017: "mongodb",
                6379: "redis",
                8080: "proxy",
                8443: "alt-https",
                3389: "rdp",
                445: "smb",
                21: "ftp",
                25: "smtp",
                53: "dns",
            }
            for port in open_ports:
                if port in notable_ports:
                    parts.append(notable_ports[port])

        if services:
            parts.extend(s.lower().strip() for s in services if s.strip())

        # 중복 제거 + 정렬
        unique_parts = sorted(set(parts))
        return "+".join(unique_parts) if unique_parts else "unknown"

    # ── Statistics ───────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Knowledge Store 전체 통계."""
        return {
            "total_records": len(self._records),
            "compiled_patterns": len(self._patterns),
            "correlation_rules": len(self._correlations),
            "capability_profiles": len(self._profiles),
            "avg_pattern_confidence": (
                round(sum(p.confidence for p in self._patterns) / len(self._patterns), 2)
                if self._patterns
                else 0.0
            ),
            "top_tools": [
                (t, p.avg_effectiveness)
                for t, p in sorted(
                    self._profiles.items(),
                    key=lambda x: x[1].avg_effectiveness,
                    reverse=True,
                )[:5]
            ],
        }

    def format_for_brain(
        self,
        context_sig: str,
        tech_stack: list[str],
    ) -> str:
        """Brain LLM 프롬프트에 삽입할 지식 요약을 생성한다.

        토큰 절약을 위해 최소한의 핵심 정보만 포함.
        """
        lines: list[str] = []

        # 1. 컴파일된 패턴 (이미 알고 있는 것)
        patterns = self.match_patterns(context_sig)
        if patterns:
            lines.append("## 컴파일된 지식")
            for p in patterns[:3]:
                lines.append(f"- {p.action_tool}: {p.reasoning} (신뢰도 {p.confidence:.0%})")

        # 2. 추천 도구
        recommended = self.get_recommended_tools(tech_stack)
        if recommended:
            lines.append("\n## 추천 도구 (과거 경험 기반)")
            for tool, score in recommended[:3]:
                lines.append(f"- {tool}: 예상 효과 {score:.0%}")

        # 3. 스킵 추천
        skip = self.get_tools_to_skip(tech_stack)
        if skip:
            lines.append(f"\n## 효과 낮을 도구: {', '.join(skip[:3])}")

        # 4. 상관관계 추론
        correlations = self.get_correlations(tech_stack)
        if correlations:
            lines.append("\n## 추론된 상관관계")
            for rule in correlations[:3]:
                lines.append(
                    f"- {', '.join(rule.if_present)} → "
                    f"{', '.join(rule.then_likely)} "
                    f"(확률 {rule.probability:.0%})"
                )

        return "\n".join(lines) if lines else ""

    # ── Persistence ──────────────────────────────────────────────

    def _load(self) -> None:
        if not self._path.exists():
            return

        try:
            raw = self._path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict):
                return

            self._records = [ExecutionRecord.from_dict(r) for r in data.get("records", [])]
            self._patterns = [CompiledPattern.from_dict(p) for p in data.get("patterns", [])]
            self._correlations = [
                CorrelationRule.from_dict(c) for c in data.get("correlations", [])
            ]
            self._profiles = {
                k: CapabilityProfile.from_dict(v) for k, v in data.get("profiles", {}).items()
            }
            self._pending_compilations = defaultdict(
                list,
                data.get("pending_compilations", {}),
            )
            logger.debug(
                "Knowledge Store 로드: %d records, %d patterns, %d correlations",
                len(self._records),
                len(self._patterns),
                len(self._correlations),
            )
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Knowledge Store 로드 실패: %s", exc)

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(
                {
                    "records": [asdict(r) for r in self._records],
                    "patterns": [asdict(p) for p in self._patterns],
                    "correlations": [asdict(c) for c in self._correlations],
                    "profiles": {k: asdict(v) for k, v in self._profiles.items()},
                    "pending_compilations": dict(self._pending_compilations),
                },
                ensure_ascii=False,
                indent=2,
            )
            self._path.write_text(payload, encoding="utf-8")
        except OSError as exc:
            logger.error("Knowledge Store 저장 실패: %s", exc)
