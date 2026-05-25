"""Chain Builder — 다중 경로 공격 트리 탐색 + LLM 분기 추론.

핵심 아이디어:
    하나의 발견에서 시작하여 "이걸로 뭘 더 할 수 있는가?"를 반복적으로 질문.
    각 답변이 새로운 분기가 되고, 그 분기에서 다시 질문.
    이 과정에서 서로 다른 레이어의 발견이 연결되면 크로스-레이어 체인이 된다.

동작:
    1. 모든 발견을 "시드"로 놓는다
    2. 각 시드에서 "이 발견 + 이미 알려진 다른 발견 → 뭘 할 수 있나?" LLM 질의
    3. LLM이 가능한 다음 단계를 제시 (0~N개 분기)
    4. 각 분기를 다시 시드로 놓고 반복 (최대 depth까지)
    5. depth > 2이고 레이어가 2개 이상 걸치면 "크로스-레이어 체인"으로 등록

Architecture:
    ┌────────────────────────────────────────────┐
    │  Attack Tree                                │
    │                                            │
    │  [DNS 취약점] ──┬── [세션 탈취]              │
    │                 ├── [SSL 인증서 발급]         │
    │                 └── [피싱 호스팅] ──┬── [S3] │
    │                                    └── [VPN]│
    │                                            │
    │  각 노드 = Finding or Hypothesis            │
    │  각 엣지 = LLM이 추론한 "이어지는 공격"       │
    └────────────────────────────────────────────┘
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from vxis.evidence.schema import Evidence, Severity
from .cross_protocol import OSILayer, AttackCategory, SynthesizedChain

logger = logging.getLogger(__name__)


@dataclass
class AttackTreeNode:
    """공격 트리의 한 노드."""

    id: str
    title: str
    description: str
    severity: Severity
    layer: OSILayer
    category: AttackCategory
    depth: int  # 루트에서의 거리
    source_finding: Evidence | None = None  # 실제 발견 (없으면 LLM 추론)
    is_hypothetical: bool = False  # LLM이 추론한 가상 노드
    children: list["AttackTreeNode"] = field(default_factory=list)
    parent_id: str = ""


@dataclass
class AttackTree:
    """하나의 시드에서 시작하는 공격 트리."""

    root: AttackTreeNode
    all_nodes: list[AttackTreeNode] = field(default_factory=list)
    max_depth_reached: int = 0
    layers_involved: set[OSILayer] = field(default_factory=set)

    @property
    def is_cross_layer(self) -> bool:
        """2개 이상 레이어를 넘나드는 트리인가."""
        return len(self.layers_involved) >= 2

    @property
    def depth(self) -> int:
        return self.max_depth_reached

    def get_chains(self) -> list[list[AttackTreeNode]]:
        """리프 노드까지의 모든 경로를 체인으로 반환."""
        chains = []
        self._collect_paths(self.root, [self.root], chains)
        return chains

    def _collect_paths(
        self,
        node: AttackTreeNode,
        current_path: list[AttackTreeNode],
        chains: list[list[AttackTreeNode]],
    ) -> None:
        if not node.children:
            if len(current_path) >= 2:
                chains.append(list(current_path))
            return
        for child in node.children:
            self._collect_paths(child, current_path + [child], chains)


class ChainBuilder:
    """다중 경로 공격 트리를 구축하는 엔진.

    Usage:
        builder = ChainBuilder(max_depth=4)
        builder.set_findings(all_findings)
        trees = await builder.build_trees()
        cross_layer_chains = builder.extract_cross_layer_chains()
    """

    def __init__(self, max_depth: int = 4, max_branches: int = 3) -> None:
        self._max_depth = max_depth
        self._max_branches = max_branches  # 각 노드에서 최대 분기 수
        self._findings: list[Evidence] = []
        self._trees: list[AttackTree] = []

    def set_findings(self, findings: list[Evidence]) -> None:
        """분석할 발견 목록을 설정한다."""
        self._findings = findings

    async def build_trees(self) -> list[AttackTree]:
        """각 주요 발견에서 시작하는 공격 트리를 구축한다."""
        from .cross_protocol import _AGENT_LAYER_MAP

        trees = []

        # high/critical severity 또는 credential/access 관련 발견만 시드로
        seeds = [
            f
            for f in self._findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        ]

        # 발견이 적으면 전부 시드로
        if len(seeds) < 3:
            seeds = self._findings

        for finding in seeds:
            layer = _AGENT_LAYER_MAP.get(finding.agent_id, OSILayer.APPLICATION)
            cats = self._get_categories(finding)

            root = AttackTreeNode(
                id=finding.id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                layer=layer,
                category=cats[0] if cats else AttackCategory.RECONNAISSANCE,
                depth=0,
                source_finding=finding,
            )

            tree = AttackTree(
                root=root,
                all_nodes=[root],
                layers_involved={layer},
            )

            # Expand tree recursively
            await self._expand_node(root, tree, 1)

            if tree.is_cross_layer or tree.depth >= 2:
                trees.append(tree)

        self._trees = trees

        logger.info(
            "공격 트리 %d개 구축 (크로스-레이어: %d개)",
            len(trees),
            sum(1 for t in trees if t.is_cross_layer),
        )

        return trees

    async def _expand_node(
        self,
        node: AttackTreeNode,
        tree: AttackTree,
        depth: int,
    ) -> None:
        """노드에서 가능한 다음 공격을 LLM으로 추론하여 확장한다."""
        if depth > self._max_depth:
            return

        # 다른 발견 중 이 노드와 연결 가능한 것 찾기
        connected = self._find_connectable_findings(node, tree)

        # LLM에게 추가 분기 질의
        hypothetical = await self._ask_llm_next_steps(node, tree)

        # 실제 발견 기반 분기
        for finding in connected[: self._max_branches]:
            from .cross_protocol import _AGENT_LAYER_MAP

            layer = _AGENT_LAYER_MAP.get(finding.agent_id, OSILayer.APPLICATION)
            cats = self._get_categories(finding)

            child = AttackTreeNode(
                id=finding.id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                layer=layer,
                category=cats[0] if cats else AttackCategory.RECONNAISSANCE,
                depth=depth,
                source_finding=finding,
                parent_id=node.id,
            )

            node.children.append(child)
            tree.all_nodes.append(child)
            tree.layers_involved.add(layer)
            tree.max_depth_reached = max(tree.max_depth_reached, depth)

            # Recurse
            await self._expand_node(child, tree, depth + 1)

        # LLM 추론 기반 가상 분기
        for hyp in hypothetical[: self._max_branches]:
            child = AttackTreeNode(
                id=f"hyp_{node.id[:8]}_{depth}_{len(node.children)}",
                title=hyp.get("title", "추론된 공격 단계"),
                description=hyp.get("description", ""),
                severity=Severity(hyp.get("severity", "medium")),
                layer=OSILayer(hyp.get("layer", "L7_application")),
                category=AttackCategory(hyp.get("category", "lateral_movement")),
                depth=depth,
                is_hypothetical=True,
                parent_id=node.id,
            )

            node.children.append(child)
            tree.all_nodes.append(child)
            tree.layers_involved.add(child.layer)
            tree.max_depth_reached = max(tree.max_depth_reached, depth)

            # 가상 노드에서는 더 이상 확장하지 않음 (실제 발견이 아니므로)

    def _find_connectable_findings(
        self,
        node: AttackTreeNode,
        tree: AttackTree,
    ) -> list[Evidence]:
        """이 노드와 연결 가능한 다른 발견을 찾는다."""
        existing_ids = {n.id for n in tree.all_nodes}

        connectable = []
        for finding in self._findings:
            if finding.id in existing_ids:
                continue

            # 연결 가능성 판단:
            # 1. 같은 타겟/호스트
            # 2. 관련 카테고리 (credential → access, access → data 등)
            # 3. 다른 레이어 (크로스-레이어)

            score = self._connection_score(node, finding)
            if score > 0.3:
                connectable.append((score, finding))

        # 점수 순 정렬
        connectable.sort(key=lambda x: x[0], reverse=True)
        return [f for _, f in connectable]

    def _connection_score(
        self,
        node: AttackTreeNode,
        finding: Evidence,
    ) -> float:
        """두 노드 간 연결 가능성 점수 (0.0~1.0)."""
        from .cross_protocol import _AGENT_LAYER_MAP

        score = 0.0
        finding_layer = _AGENT_LAYER_MAP.get(finding.agent_id, OSILayer.APPLICATION)

        # 다른 레이어면 가산 (크로스-레이어 보너스)
        if finding_layer != node.layer:
            score += 0.4

        # 카테고리 흐름이 자연스러우면 가산
        node_cats = self._get_categories_from_text(node.title + " " + node.description)
        finding_cats = self._get_categories_from_text(finding.title + " " + finding.description)

        # credential → access, access → data 같은 자연 흐름
        natural_flows = {
            AttackCategory.RECONNAISSANCE: {AttackCategory.INITIAL_ACCESS},
            AttackCategory.INITIAL_ACCESS: {
                AttackCategory.CREDENTIAL_HARVEST,
                AttackCategory.LATERAL_MOVEMENT,
            },
            AttackCategory.CREDENTIAL_HARVEST: {
                AttackCategory.LATERAL_MOVEMENT,
                AttackCategory.PRIVILEGE_ESCALATION,
            },
            AttackCategory.LATERAL_MOVEMENT: {
                AttackCategory.DATA_EXFILTRATION,
                AttackCategory.PRIVILEGE_ESCALATION,
            },
            AttackCategory.PRIVILEGE_ESCALATION: {
                AttackCategory.DATA_EXFILTRATION,
                AttackCategory.PERSISTENCE,
            },
        }

        for nc in node_cats:
            next_cats = natural_flows.get(nc, set())
            if next_cats & set(finding_cats):
                score += 0.3

        # severity가 높으면 가산 (high-value target)
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            score += 0.2

        return min(score, 1.0)

    async def _ask_llm_next_steps(
        self,
        node: AttackTreeNode,
        tree: AttackTree,
    ) -> list[dict]:
        """LLM에게 "이 발견에서 다음에 뭘 할 수 있나?" 질의."""
        import json

        # 트리의 현재 경로 구성
        path_text = f"현재 위치: [{node.severity.value}] {node.title} (레이어: {node.layer.value})"

        # 이미 알려진 다른 발견 목록
        other_findings = [
            f"- [{f.severity.value}] {f.title} (에이전트: {f.agent_id})"
            for f in self._findings
            if f.id not in {n.id for n in tree.all_nodes}
        ][:10]

        if not other_findings:
            return []

        prompt = f"""\
현재 공격 트리 위치:
{path_text}

아직 활용하지 않은 다른 발견들:
{chr(10).join(other_findings)}

질문: 현재 위치에서 다음으로 가능한 공격 단계는? (0~3개)
다른 레이어로 넘어가는 경로를 우선 제시하라.

JSON 배열로 응답 (빈 배열 가능):
[
  {{
    "title": "다음 공격 단계 (한국어)",
    "description": "구체적 설명",
    "severity": "critical|high|medium|low",
    "layer": "L1_physical|L2_data_link|...|cloud|supply_chain|data",
    "category": "initial_access|credential_harvest|lateral_movement|..."
  }}
]
"""

        try:
            from vxis.llm.client import LLMClient

            client = LLMClient()
            response = await client.think(
                system="당신은 레드팀 전문가입니다. 현재 공격 위치에서 가능한 다음 단계를 추론합니다.",
                user=prompt,
                max_tokens=1000,
            )

            text = response.text
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]

            return json.loads(text.strip())

        except Exception as exc:
            logger.debug("LLM 분기 추론 실패: %s", exc)
            return []

    def extract_cross_layer_chains(self) -> list[SynthesizedChain]:
        """구축된 트리에서 크로스-레이어 체인을 추출한다."""
        chains = []

        for tree in self._trees:
            if not tree.is_cross_layer:
                continue

            for path in tree.get_chains():
                if len(path) < 2:
                    continue

                # 경로의 레이어 수집
                layers = list(dict.fromkeys(n.layer for n in path))  # 순서 유지 중복 제거
                if len(layers) < 2:
                    continue

                # 체인 severity 결정: 경로 중 가장 높은 severity
                max(path, key=lambda n: _severity_rank(n.severity))

                # 실제 발견만 추출
                real_findings = [n.source_finding for n in path if n.source_finding]

                # 개별 severity 합계
                individual = " + ".join(n.severity.value for n in path)

                chain = SynthesizedChain(
                    id=f"tree_chain_{tree.root.id[:8]}_{len(chains)}",
                    title=f"{path[0].title} → ... → {path[-1].title}",
                    description=_build_chain_narrative(path),
                    severity=_escalate_severity(path),
                    kill_chain_stages=[n.category.value for n in path],
                    findings=real_findings,
                    layers_crossed=layers,
                    pattern_name="tree_traversal",
                    confidence=0.7 if any(n.is_hypothetical for n in path) else 0.9,
                    individual_severity_sum=individual,
                    escalation_reason=(
                        f"{len(layers)}개 레이어를 넘나드는 체인: "
                        f"{' → '.join(layer.value for layer in layers)}. "
                        f"개별 {individual} → 체인 {_escalate_severity(path).value.upper()}"
                    ),
                )
                chains.append(chain)

        return chains

    @staticmethod
    def _get_categories(finding: Evidence) -> list[AttackCategory]:
        """Finding에서 공격 카테고리를 추출."""
        from .cross_protocol import _KEYWORD_CATEGORY_MAP

        text = f"{finding.title} {finding.description}".lower()
        cats = []
        for kw, cat in _KEYWORD_CATEGORY_MAP.items():
            if kw in text and cat not in cats:
                cats.append(cat)
        return cats or [AttackCategory.RECONNAISSANCE]

    @staticmethod
    def _get_categories_from_text(text: str) -> list[AttackCategory]:
        from .cross_protocol import _KEYWORD_CATEGORY_MAP

        text = text.lower()
        cats = []
        for kw, cat in _KEYWORD_CATEGORY_MAP.items():
            if kw in text and cat not in cats:
                cats.append(cat)
        return cats


def _severity_rank(sev: Severity) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev.value, 0)


def _escalate_severity(path: list[AttackTreeNode]) -> Severity:
    """경로의 체인 severity를 결정한다.

    규칙:
    - 경로 길이 3+이고 2+ 레이어 → 최소 HIGH
    - 경로 길이 4+이고 3+ 레이어 → CRITICAL
    - credential → data_exfiltration 흐름 → CRITICAL
    """
    layers = set(n.layer for n in path)
    max_individual = max(_severity_rank(n.severity) for n in path)

    # 3+ 단계, 2+ 레이어 → 최소 HIGH
    if len(path) >= 3 and len(layers) >= 2:
        return Severity.CRITICAL if len(path) >= 4 and len(layers) >= 3 else Severity.HIGH

    # credential → data 흐름 → CRITICAL
    categories = [n.category for n in path]
    if (
        AttackCategory.CREDENTIAL_HARVEST in categories
        and AttackCategory.DATA_EXFILTRATION in categories
    ):
        return Severity.CRITICAL

    # 기본: 가장 높은 개별 severity
    return {4: Severity.CRITICAL, 3: Severity.HIGH, 2: Severity.MEDIUM, 1: Severity.LOW}.get(
        max_individual, Severity.MEDIUM
    )


def _build_chain_narrative(path: list[AttackTreeNode]) -> str:
    """경로를 서사적 공격 시나리오로 변환한다."""
    lines = ["### 공격 시나리오\n"]

    for i, node in enumerate(path, 1):
        marker = (
            "🔴"
            if node.severity == Severity.CRITICAL
            else "🟠"
            if node.severity == Severity.HIGH
            else "🟡"
        )
        hyp_tag = " *(추론)*" if node.is_hypothetical else ""

        lines.append(
            f"**단계 {i}:** {marker} {node.title}{hyp_tag}\n"
            f"  레이어: `{node.layer.value}` | "
            f"카테고리: `{node.category.value}` | "
            f"심각도: `{node.severity.value}`\n"
        )

        if node.description:
            desc = node.description[:200]
            if len(node.description) > 200:
                desc += "..."
            lines.append(f"  {desc}\n")

        if i < len(path):
            lines.append("  ↓ *다음 단계로 연결*\n")

    return "\n".join(lines)
