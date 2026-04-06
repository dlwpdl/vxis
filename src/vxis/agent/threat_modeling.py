"""Threat Modeling — STRIDE + Attack Tree generation via Brain.

Brain-First: STRIDE 카테고리와 attack tree는 Brain LLM이 동적으로 생성한다.
하드코딩된 위협 목록 금지. Brain 미가용 시 graceful skip.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── STRIDE → Vector Prefix 매핑 (Phase 5 prioritization) ──
STRIDE_TO_VECTOR_PREFIXES: dict[str, list[str]] = {
    "spoofing": ["WEB-AUTH-", "WEB-SESS-", "WEB-IDENT-"],
    "tampering": ["WEB-INJECT-", "WEB-SQLI-", "WEB-XSS-", "WEB-DESER-"],
    "repudiation": ["WEB-LOG-", "WEB-AUDIT-"],
    "information_disclosure": ["WEB-API-", "WEB-CRYPTO-", "WEB-INFO-", "WEB-MISCONF-"],
    "dos": ["WEB-DOS-", "WEB-RATE-"],
    "elevation_of_privilege": ["WEB-AC-", "WEB-PRIV-", "WEB-IDOR-"],
}


@dataclass
class STRIDEModel:
    """STRIDE 위협 모델."""

    spoofing: list[str] = field(default_factory=list)
    tampering: list[str] = field(default_factory=list)
    repudiation: list[str] = field(default_factory=list)
    information_disclosure: list[str] = field(default_factory=list)
    dos: list[str] = field(default_factory=list)
    elevation_of_privilege: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "spoofing": self.spoofing,
            "tampering": self.tampering,
            "repudiation": self.repudiation,
            "information_disclosure": self.information_disclosure,
            "dos": self.dos,
            "elevation_of_privilege": self.elevation_of_privilege,
        }

    def total_threats(self) -> int:
        return sum(len(v) for v in self.to_dict().values())

    def priority_vector_prefixes(self) -> list[str]:
        """위협이 많은 STRIDE 카테고리부터 vector prefix를 반환한다."""
        ordered = sorted(
            self.to_dict().items(),
            key=lambda kv: len(kv[1]),
            reverse=True,
        )
        prefixes: list[str] = []
        for cat, threats in ordered:
            if not threats:
                continue
            prefixes.extend(STRIDE_TO_VECTOR_PREFIXES.get(cat, []))
        return prefixes


@dataclass
class AttackTree:
    """공격 트리 — root goal → sub-goals → leaf attacks."""

    root: str = ""
    nodes: list[str] = field(default_factory=list)  # sub-goals
    leaves: list[str] = field(default_factory=list)  # concrete attacks

    def to_dict(self) -> dict[str, Any]:
        return {"root": self.root, "nodes": self.nodes, "leaves": self.leaves}


def _extract_json(raw: str) -> dict[str, Any] | None:
    """LLM 응답에서 JSON 객체를 robust하게 추출."""
    if not raw:
        return None
    # ```json ... ``` 코드블록 제거
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if m:
        raw = m.group(1)
    else:
        m = re.search(r"(\{.*\})", raw, re.DOTALL)
        if m:
            raw = m.group(1)
    try:
        return json.loads(raw)
    except Exception as exc:
        logger.debug("[ThreatModeler] JSON parse failed: %s", exc)
        return None


def _coerce_str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(x) for x in value if x]
    if isinstance(value, str) and value:
        return [value]
    return []


class ThreatModeler:
    """Brain 기반 STRIDE / Attack Tree 생성기."""

    STRIDE_SYSTEM = (
        "You are a senior threat modeling expert. Given a target web application, "
        "identify concrete threats in the STRIDE categories: Spoofing, Tampering, "
        "Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege. "
        "Output STRICT JSON with keys: spoofing, tampering, repudiation, "
        "information_disclosure, dos, elevation_of_privilege. Each value MUST be a list "
        "of short threat descriptions (strings). No prose outside JSON."
    )

    TREE_SYSTEM = (
        "You are an attack tree expert. Given a single attacker goal, produce an attack tree. "
        "Output STRICT JSON with keys: root (string), nodes (list of sub-goal strings), "
        "leaves (list of concrete attack strings). No prose outside JSON."
    )

    async def generate_stride(
        self,
        target: str,
        tech_stack: list[str] | None,
        brain: Any,
    ) -> STRIDEModel:
        """Brain에게 STRIDE 모델을 요청한다. 실패 시 빈 모델 반환."""
        if brain is None:
            logger.info("[ThreatModeler] brain unavailable — skipping STRIDE")
            return STRIDEModel()

        stack_str = ", ".join(tech_stack or []) or "unknown"
        user_prompt = (
            f"Target: {target}\n"
            f"Tech stack: {stack_str}\n"
            f"Industry: web application\n"
            "Generate STRIDE model:"
        )

        raw = await self._ask_brain(brain, self.STRIDE_SYSTEM, user_prompt)
        data = _extract_json(raw or "")
        if not data:
            return STRIDEModel()

        model = STRIDEModel(
            spoofing=_coerce_str_list(data.get("spoofing")),
            tampering=_coerce_str_list(data.get("tampering")),
            repudiation=_coerce_str_list(data.get("repudiation")),
            information_disclosure=_coerce_str_list(
                data.get("information_disclosure") or data.get("info_disclosure")
            ),
            dos=_coerce_str_list(data.get("dos") or data.get("denial_of_service")),
            elevation_of_privilege=_coerce_str_list(
                data.get("elevation_of_privilege") or data.get("eop")
            ),
        )
        logger.info("[ThreatModeler] STRIDE generated: %d threats", model.total_threats())
        return model

    async def generate_attack_tree(self, goal: str, brain: Any) -> AttackTree:
        """Brain에게 attack tree를 요청한다."""
        if brain is None:
            return AttackTree(root=goal)

        user_prompt = (
            f"Goal: {goal}\n"
            "Generate an attack tree with sub-goals and concrete leaf attacks. "
            "Output JSON only."
        )
        raw = await self._ask_brain(brain, self.TREE_SYSTEM, user_prompt)
        data = _extract_json(raw or "")
        if not data:
            return AttackTree(root=goal)

        return AttackTree(
            root=str(data.get("root") or goal),
            nodes=_coerce_str_list(data.get("nodes")),
            leaves=_coerce_str_list(data.get("leaves")),
        )

    def stride_to_hypotheses(self, stride: STRIDEModel) -> list[dict[str, Any]]:
        """STRIDE 위협을 ctx.hypotheses 포맷으로 변환."""
        hypotheses: list[dict[str, Any]] = []
        severity_map = {
            "spoofing": "high",
            "tampering": "high",
            "repudiation": "medium",
            "information_disclosure": "high",
            "dos": "medium",
            "elevation_of_privilege": "critical",
        }
        for category, threats in stride.to_dict().items():
            for threat in threats:
                hypotheses.append(
                    {
                        "source": "threat_model",
                        "category": category,
                        "stride": category,
                        "hypothesis": threat,
                        "severity": severity_map.get(category, "medium"),
                        "vector_prefixes": STRIDE_TO_VECTOR_PREFIXES.get(category, []),
                        "confidence": 0.6,
                    }
                )
        return hypotheses

    @staticmethod
    async def _ask_brain(brain: Any, system_prompt: str, user_prompt: str) -> str | None:
        """Brain의 LLM 호출 — claude -p 우선, LLM API 폴백."""
        try:
            fn = getattr(brain, "_call_llm_with_fallback", None)
            if fn is None:
                return None
            result = fn(system_prompt, user_prompt)
            # 일부 구현은 coroutine 반환 가능
            if hasattr(result, "__await__"):
                result = await result
            return str(result) if result is not None else None
        except Exception as exc:
            logger.debug("[ThreatModeler] brain call failed: %s", exc)
            return None
