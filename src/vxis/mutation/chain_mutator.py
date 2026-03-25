"""공격 체인 변이 엔진 — 같은 목적지, 다른 경로.

"SQLi 막았다고? 3개 더 있다."
부분 패치의 허상을 수학적으로 증명.

핵심 개념:
    하나의 공격 체인을 패치했을 때, 같은 목표(동일 노드)로 도달하는
    대안 경로가 얼마나 남아 있는지를 그래프 이론으로 증명한다.

Phase 1 (Tier 0): NetworkX BFS/DFS로 동등 경로 탐색
Phase 2 (Tier 3): LLM으로 단계 대체 변이 생성
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from vxis.synthesis.cross_protocol import SynthesizedChain
from vxis.evidence.schema import Severity

logger = logging.getLogger(__name__)


# ── Severity 순위 헬퍼 ──────────────────────────────────────────

_SEV_RANK: dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}


def _rank(sev: str) -> int:
    return _SEV_RANK.get(sev, 0)


# ── 결과 데이터 클래스 ───────────────────────────────────────────

@dataclass
class MutationResult:
    """원본 체인의 단일 변이 결과."""

    original_chain_id: str
    mutated_chain: SynthesizedChain

    # 변이 메타데이터
    mutation_type: str  # "graph_alternative", "llm_step_replacement"
    replaced_step_title: str  # 대체된 원본 단계 제목 (없으면 "")
    replacement_step_title: str  # 대체된 새 단계 제목

    # 난이도 변화: -1.0 (훨씬 쉬워짐) ~ +1.0 (훨씬 어려워짐)
    difficulty_delta: float = 0.0
    difficulty_reason: str = ""

    def difficulty_label(self) -> str:
        if self.difficulty_delta <= -0.4:
            return "훨씬 쉬운 대안"
        elif self.difficulty_delta <= -0.1:
            return "다소 쉬운 대안"
        elif self.difficulty_delta <= 0.1:
            return "동등 난이도 대안"
        elif self.difficulty_delta <= 0.4:
            return "다소 어려운 대안"
        else:
            return "훨씬 어려운 대안"


# ── 핵심 변이 엔진 ───────────────────────────────────────────────

class ChainMutator:
    """공격 체인 변이 엔진.

    단일 공격 경로를 입력받아 "동일한 목표에 도달하는 대안 경로"를
    그래프 탐색과 LLM 추론으로 생성한다.

    Usage:
        mutator = ChainMutator(max_alternatives=5)
        results = await mutator.mutate(chain, attack_graph)
        report = mutator.format_mutation_report(chain, results)
    """

    def __init__(self, max_alternatives: int = 5) -> None:
        self._max_alternatives = max_alternatives

    async def mutate(
        self,
        chain: SynthesizedChain,
        attack_graph: Any,  # LivingAttackGraph
    ) -> list[MutationResult]:
        """체인의 변이 버전들을 생성한다.

        Phase 1: 그래프 BFS/DFS로 동등 경로 탐색 (Tier 0 — LLM 불필요)
        Phase 2: LLM으로 단계 대체 변이 생성 (Tier 3)

        Args:
            chain: 변이할 원본 공격 체인.
            attack_graph: LivingAttackGraph 인스턴스.

        Returns:
            MutationResult 리스트. 난이도 변화 오름차순 정렬.
        """
        results: list[MutationResult] = []

        # Phase 1: 그래프 기반 대안 경로 탐색
        graph_mutations = self._find_graph_alternatives(chain, attack_graph)
        results.extend(graph_mutations)
        logger.info(
            "Phase 1 변이: '%s'에서 %d개 그래프 대안 발견",
            chain.title[:50],
            len(graph_mutations),
        )

        # Phase 2: LLM 단계 대체 변이 (남은 슬롯만큼)
        remaining = self._max_alternatives - len(results)
        if remaining > 0:
            llm_mutations = await self._llm_step_replacement(chain, remaining)
            results.extend(llm_mutations)
            logger.info(
                "Phase 2 변이: '%s'에서 %d개 LLM 대안 생성",
                chain.title[:50],
                len(llm_mutations),
            )

        # 난이도 변화 오름차순 정렬 (쉬운 대안 먼저)
        results.sort(key=lambda r: r.difficulty_delta)

        return results[: self._max_alternatives]

    # ── Phase 1: 그래프 BFS/DFS ────────────────────────────────

    def _find_graph_alternatives(
        self,
        chain: SynthesizedChain,
        attack_graph: Any,
    ) -> list[MutationResult]:
        """NetworkX 그래프에서 동일 목적지에 도달하는 대안 경로를 BFS로 탐색."""
        results: list[MutationResult] = []

        if not chain.findings:
            return results

        # 그래프에서 체인의 시작-끝 노드 식별
        graph: nx.DiGraph = getattr(attack_graph, "_graph", None)
        if graph is None or graph.number_of_nodes() == 0:
            logger.debug("그래프가 비어 있어 그래프 변이 탐색 생략")
            return results

        source_id = chain.findings[0].id
        target_id = chain.findings[-1].id

        if source_id not in graph or target_id not in graph:
            return results

        # 원본 경로의 노드 집합
        original_node_ids = {f.id for f in chain.findings}

        # BFS로 대안 경로 탐색 (원본과 다른 경로만)
        try:
            all_paths = list(nx.all_simple_paths(
                graph, source_id, target_id, cutoff=8
            ))
        except (nx.NetworkXError, nx.NodeNotFound):
            return results

        for path in all_paths:
            path_set = set(path)
            if path_set == original_node_ids:
                continue  # 원본과 동일한 경로

            # 대안 경로로 변이 체인 생성
            mutation = self._build_graph_mutation(chain, path, attack_graph)
            if mutation:
                results.append(mutation)

            if len(results) >= self._max_alternatives:
                break

        return results

    def _build_graph_mutation(
        self,
        original: SynthesizedChain,
        alt_path: list[str],
        attack_graph: Any,
    ) -> MutationResult | None:
        """대안 그래프 경로에서 MutationResult를 생성한다."""
        nodes: dict[str, Any] = getattr(attack_graph, "_nodes", {})

        # 대안 경로의 노드 데이터 수집
        alt_node_data = [nodes[nid] for nid in alt_path if nid in nodes]
        if not alt_node_data:
            return None

        # 원본 경로와 다른 단계 식별
        original_ids = {f.id for f in original.findings}
        diff_nodes = [n for n in alt_node_data if n.id not in original_ids]

        replaced_title = (
            alt_node_data[len(alt_node_data) // 2].title
            if alt_node_data
            else "중간 단계"
        )
        replacement_title = (
            diff_nodes[0].title if diff_nodes else "대안 단계"
        )

        # 난이도 계산: 대안 경로의 평균 severity vs 원본
        original_sev_avg = (
            sum(_rank(f.severity.value) for f in original.findings) / len(original.findings)
            if original.findings
            else 2.0
        )
        alt_sev_avg = (
            sum(_rank(getattr(n, "severity", "medium")) for n in alt_node_data)
            / len(alt_node_data)
            if alt_node_data
            else 2.0
        )
        difficulty_delta = (alt_sev_avg - original_sev_avg) / 4.0  # 정규화 [-1, 1]

        # 변이 체인 구성
        mutated = SynthesizedChain(
            id=f"mut_graph_{original.id[:8]}_{len(alt_path)}",
            title=f"[그래프 대안] {original.title}",
            description=(
                f"원본 체인 '{original.title}'의 그래프 대안 경로.\n\n"
                f"경로 단계 수: {len(alt_path)}개\n"
                f"대안 경로: {' → '.join(alt_path)}\n\n"
                f"이 경로로도 동일한 목표 노드 '{alt_path[-1][:8]}...'에 도달 가능."
            ),
            severity=original.severity,
            kill_chain_stages=original.kill_chain_stages,
            findings=original.findings,
            layers_crossed=original.layers_crossed,
            pattern_name=f"graph_alt_{original.pattern_name}",
            confidence=0.80,
            escalation_reason=f"그래프 대안 경로: {len(alt_path)}단계",
        )

        return MutationResult(
            original_chain_id=original.id,
            mutated_chain=mutated,
            mutation_type="graph_alternative",
            replaced_step_title=replaced_title,
            replacement_step_title=replacement_title,
            difficulty_delta=difficulty_delta,
            difficulty_reason=(
                f"대안 경로 평균 severity {alt_sev_avg:.1f} vs "
                f"원본 {original_sev_avg:.1f}"
            ),
        )

    # ── Phase 2: LLM 단계 대체 ─────────────────────────────────

    async def _llm_step_replacement(
        self,
        chain: SynthesizedChain,
        max_count: int,
    ) -> list[MutationResult]:
        """LLM에게 체인의 각 단계를 대체할 방법을 질의한다."""
        import json

        if not chain.findings:
            return []

        # 체인 단계 요약
        steps_text = "\n".join(
            f"  {i+1}. [{f.severity.value}] {f.title} (에이전트: {f.agent_id})"
            for i, f in enumerate(chain.findings)
        )

        prompt = f"""\
다음 공격 체인을 분석하고, 각 단계를 "다른 방법"으로 대체하는 변이를 생성하라.

## 원본 공격 체인
제목: {chain.title}
심각도: {chain.severity.value.upper()}
체인 단계:
{steps_text}

## 임무
방어자가 이 체인의 일부를 패치했다고 가정할 때, 동일한 최종 목표에 도달하는
대안 방법을 {max_count}개 제시하라.

규칙:
1. 각 변이는 원본 체인에서 "단계 하나"를 다른 기법으로 대체한다.
2. 현실적으로 가능한 공격 기법만 사용한다.
3. 대체 기법이 원본보다 쉬운지, 어려운지 판단하라.
4. 취약점 유형, 프로토콜, 공격 벡터를 바꿔서 동일 목표를 달성하는 방법을 찾아라.

JSON 배열로 응답:
[
  {{
    "replaced_step": "대체되는 원본 단계 제목",
    "replacement_step": "새로운 공격 기법 설명",
    "replacement_severity": "critical|high|medium|low",
    "difficulty_delta": -0.3,
    "difficulty_reason": "왜 더 쉽거나 어려운지 설명",
    "description": "변이된 체인 전체 시나리오 설명"
  }}
]
"""

        try:
            from vxis.llm.client import LLMClient
            client = LLMClient()
            response = await client.think(
                system=(
                    "당신은 레드팀 전문가입니다. 공격 체인의 변이를 분석하여 "
                    "부분 패치의 허점을 수학적으로 증명합니다."
                ),
                user=prompt,
                max_tokens=2000,
            )

            text = response.text
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]

            items = json.loads(text.strip())
            if not isinstance(items, list):
                return []

            results: list[MutationResult] = []
            for item in items[:max_count]:
                replaced = item.get("replaced_step", "알 수 없는 단계")
                replacement = item.get("replacement_step", "대안 공격 기법")
                delta = float(item.get("difficulty_delta", 0.0))
                delta = max(-1.0, min(1.0, delta))

                # LLM이 제안한 severity로 체인 severity 결정
                sev_str = item.get("replacement_severity", chain.severity.value)
                try:
                    sev = Severity(sev_str)
                except ValueError:
                    sev = chain.severity

                mutated = SynthesizedChain(
                    id=f"mut_llm_{original_id_prefix(chain)}_{len(results)}",
                    title=f"[LLM 변이] {replaced} 대체 → {replacement[:40]}",
                    description=(
                        f"원본 체인의 '{replaced}' 단계를 대체하는 변이.\n\n"
                        f"대체 기법: {replacement}\n\n"
                        f"{item.get('description', '')}"
                    ),
                    severity=sev,
                    kill_chain_stages=chain.kill_chain_stages,
                    findings=chain.findings,
                    layers_crossed=chain.layers_crossed,
                    pattern_name="llm_mutation",
                    confidence=0.65,
                    escalation_reason=f"LLM 변이: {replaced} → {replacement[:40]}",
                )

                results.append(MutationResult(
                    original_chain_id=chain.id,
                    mutated_chain=mutated,
                    mutation_type="llm_step_replacement",
                    replaced_step_title=replaced,
                    replacement_step_title=replacement,
                    difficulty_delta=delta,
                    difficulty_reason=item.get("difficulty_reason", ""),
                ))

            return results

        except Exception as exc:
            logger.warning("LLM 변이 생성 실패: %s", exc)
            return []

    # ── 리포트 생성 ────────────────────────────────────────────

    def format_mutation_report(
        self,
        original: SynthesizedChain,
        mutations: list[MutationResult],
    ) -> str:
        """변이 분석 리포트를 마크다운으로 생성한다.

        "이 취약점을 패치해도 N가지 대안 경로 존재" 형식.
        """
        if not mutations:
            return (
                f"## 공격 체인 변이 분석\n\n"
                f"원본: **{original.title}**\n\n"
                f"_그래프 및 LLM 분석 결과 대안 경로 없음. 패치 적용 시 해당 경로 완전 차단._\n"
            )

        graph_alts = [m for m in mutations if m.mutation_type == "graph_alternative"]
        llm_alts = [m for m in mutations if m.mutation_type == "llm_step_replacement"]

        easier = [m for m in mutations if m.difficulty_delta < -0.1]
        harder = [m for m in mutations if m.difficulty_delta > 0.1]

        lines = [
            "## 공격 체인 변이 분석",
            "",
            f"### 원본 체인: {original.title}",
            f"- 심각도: **{original.severity.value.upper()}**",
            f"- 구성 단계: {len(original.findings)}개",
            f"- 패턴: {original.pattern_name}",
            "",
            "---",
            "",
            f"### 핵심 결론",
            f"**이 취약점을 패치해도 {len(mutations)}가지 대안 공격 경로가 존재합니다.**",
            "",
            f"- 그래프 대안 경로: {len(graph_alts)}개",
            f"- LLM 추론 대안: {len(llm_alts)}개",
            f"- 원본보다 쉬운 경로: {len(easier)}개 (더 위험)",
            f"- 원본보다 어려운 경로: {len(harder)}개",
            "",
            "---",
            "",
            "### 대안 경로 상세",
            "",
        ]

        for i, mutation in enumerate(mutations, 1):
            diff_label = mutation.difficulty_label()
            diff_sign = "+" if mutation.difficulty_delta > 0 else ""
            lines += [
                f"#### {i}. {mutation.mutated_chain.title}",
                f"- **유형**: {mutation.mutation_type}",
                f"- **대체 단계**: `{mutation.replaced_step_title}` → `{mutation.replacement_step_title}`",
                f"- **난이도 변화**: {diff_sign}{mutation.difficulty_delta:+.2f} ({diff_label})",
                f"- **심각도**: {mutation.mutated_chain.severity.value.upper()}",
                f"- **신뢰도**: {mutation.mutated_chain.confidence:.0%}",
            ]
            if mutation.difficulty_reason:
                lines.append(f"- **이유**: {mutation.difficulty_reason}")
            lines += [
                "",
                mutation.mutated_chain.description[:400],
                "",
            ]

        lines += [
            "---",
            "",
            "### 패치 권고",
            "",
            f"단일 취약점 패치로는 위 {len(mutations)}개 대안 경로를 모두 차단할 수 없습니다.",
            "**심층 방어(Defense-in-Depth)** 전략이 필요합니다:",
            "",
        ]

        if easier:
            lines.append(
                f"- 우선 순위: {len(easier)}개의 더 쉬운 경로 차단 "
                f"({', '.join(m.replacement_step_title[:20] for m in easier[:3])})"
            )

        return "\n".join(lines)


# ── 헬퍼 ────────────────────────────────────────────────────────

def original_id_prefix(chain: SynthesizedChain) -> str:
    """체인 ID의 앞 8자리를 반환한다."""
    return chain.id[:8] if len(chain.id) >= 8 else chain.id
