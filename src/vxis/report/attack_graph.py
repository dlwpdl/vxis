"""Attack Path Graph — 공격 경로 시각화.

Brain이 체이닝한 공격 경로를 SVG 그래프로 렌더링한다.
리포트에 인라인으로 삽입되어 공격자가 어떻게
초기 진입 → 횡이동 → 권한상승 → Crown Jewel에 도달했는지 보여준다.

순수 SVG + networkx 레이아웃. 외부 JS 의존성 없음.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── 색상 팔레트 ──────────────────────────────────────────────────

_NODE_COLOURS: dict[str, str] = {
    "entry": "#3498DB",        # 파란색 — 초기 진입점
    "vulnerability": "#E67E22",  # 주황색 — 취약점
    "exploit": "#C0392B",      # 빨간색 — 익스플로잇 성공
    "pivot": "#8E44AD",        # 보라색 — 횡이동/피봇
    "escalation": "#E74C3C",   # 진한 빨강 — 권한 상승
    "crown_jewel": "#FFD700",  # 금색 — Crown Jewel 도달
    "blocked": "#95A5A6",      # 회색 — 차단됨
}

_EDGE_COLOURS: dict[str, str] = {
    "success": "#27AE60",    # 초록 — 성공
    "attempted": "#BDC3C7",  # 연회색 — 시도만
    "blocked": "#E74C3C",    # 빨강 — 차단됨
}

_SEVERITY_BORDER: dict[str, str] = {
    "critical": "#7B2C34",
    "high": "#C0392B",
    "medium": "#E67E22",
    "low": "#2ECC71",
    "informational": "#3498DB",
}


# ── 데이터 모델 ──────────────────────────────────────────────────


@dataclass
class AttackNode:
    """공격 그래프의 노드 — 하나의 공격 단계."""

    id: str
    label: str
    label_ko: str = ""
    node_type: str = "vulnerability"
    # "entry" | "vulnerability" | "exploit" | "pivot" | "escalation" | "crown_jewel" | "blocked"
    severity: str = "medium"
    finding_id: str = ""
    description: str = ""
    depth_level: int = 0  # 0=recon, 1=vuln, 2=exploit, 3=post, 4=crown


@dataclass
class AttackEdge:
    """공격 그래프의 엣지 — 단계 간 전이."""

    source: str  # node id
    target: str  # node id
    label: str = ""
    label_ko: str = ""
    edge_type: str = "success"  # "success" | "attempted" | "blocked"
    technique: str = ""  # MITRE ATT&CK 등


@dataclass
class AttackPath:
    """하나의 공격 경로 (노드 + 엣지 체인)."""

    name: str
    name_ko: str = ""
    nodes: list[AttackNode] = field(default_factory=list)
    edges: list[AttackEdge] = field(default_factory=list)
    max_depth: int = 0  # 최대 도달 깊이 (0~4)
    crown_jewel_reached: bool = False


@dataclass
class AttackGraphData:
    """전체 공격 그래프 — 여러 경로 포함."""

    paths: list[AttackPath] = field(default_factory=list)
    all_nodes: list[AttackNode] = field(default_factory=list)
    all_edges: list[AttackEdge] = field(default_factory=list)

    def add_path(self, path: AttackPath) -> None:
        """경로 추가 + 전체 노드/엣지 병합."""
        self.paths.append(path)
        existing_ids = {n.id for n in self.all_nodes}
        for node in path.nodes:
            if node.id not in existing_ids:
                self.all_nodes.append(node)
                existing_ids.add(node.id)
        existing_edges = {(e.source, e.target) for e in self.all_edges}
        for edge in path.edges:
            if (edge.source, edge.target) not in existing_edges:
                self.all_edges.append(edge)
                existing_edges.add((edge.source, edge.target))

    @property
    def max_depth_reached(self) -> int:
        """전체 경로 중 최대 도달 깊이."""
        if not self.paths:
            return 0
        return max(p.max_depth for p in self.paths)

    @property
    def has_crown_jewel(self) -> bool:
        """Crown Jewel에 도달한 경로가 있는지."""
        return any(p.crown_jewel_reached for p in self.paths)


# ── SVG 렌더러 ───────────────────────────────────────────────────


def render_attack_graph_svg(
    graph: AttackGraphData,
    width: int = 900,
    lang: str = "en",
) -> str:
    """공격 그래프를 SVG 문자열로 렌더링.

    Args:
        graph: 공격 그래프 데이터.
        width: SVG 너비 (px).
        lang: "en" | "ko" — 노드/엣지 라벨 언어.

    Returns:
        인라인 삽입 가능한 SVG 문자열.
    """
    if not graph.all_nodes:
        return _empty_graph_svg(width, lang)

    # ── 레이아웃 계산 (깊이 기반 계층 배치) ──
    positions = _compute_layout(graph, width)
    height = _compute_height(positions)

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" '
        f'style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; '
        f'background: #1a1a2e; border-radius: 8px;">'
    )

    # 배경 그라데이션
    parts.append(
        '<defs>'
        '<linearGradient id="bg-grad" x1="0%" y1="0%" x2="100%" y2="100%">'
        '<stop offset="0%" style="stop-color:#1a1a2e"/>'
        '<stop offset="100%" style="stop-color:#16213e"/>'
        '</linearGradient>'
        '<marker id="arrow" viewBox="0 0 10 6" refX="10" refY="3" '
        'markerWidth="8" markerHeight="6" orient="auto-start-reverse">'
        '<path d="M 0 0 L 10 3 L 0 6 z" fill="#6c757d"/>'
        '</marker>'
        '<marker id="arrow-success" viewBox="0 0 10 6" refX="10" refY="3" '
        'markerWidth="8" markerHeight="6" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 3 L 0 6 z" fill="{_EDGE_COLOURS["success"]}"/>'
        '</marker>'
        '<marker id="arrow-blocked" viewBox="0 0 10 6" refX="10" refY="3" '
        'markerWidth="8" markerHeight="6" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 3 L 0 6 z" fill="{_EDGE_COLOURS["blocked"]}"/>'
        '</marker>'
        '</defs>'
    )

    # 타이틀
    title = "Attack Path Graph" if lang == "en" else "공격 경로 그래프"
    parts.append(
        f'<text x="{width // 2}" y="30" text-anchor="middle" '
        f'fill="#ecf0f1" font-size="16" font-weight="bold">{title}</text>'
    )

    # 깊이 레벨 라벨
    depth_labels = {
        0: ("Recon", "정찰"),
        1: ("Vulnerability", "취약점 확인"),
        2: ("Exploit", "익스플로잇"),
        3: ("Post-Exploit", "포스트 익스플로잇"),
        4: ("Crown Jewel", "Crown Jewel"),
    }
    depths_used = sorted({n.depth_level for n in graph.all_nodes})
    for depth in depths_used:
        label_en, label_ko = depth_labels.get(depth, (f"L{depth}", f"L{depth}"))
        label = label_ko if lang == "ko" else label_en
        y_pos = 60 + depth * 120
        parts.append(
            f'<text x="15" y="{y_pos}" fill="#6c757d" font-size="11" '
            f'font-style="italic">{label}</text>'
        )
        parts.append(
            f'<line x1="10" y1="{y_pos + 5}" x2="{width - 10}" y2="{y_pos + 5}" '
            f'stroke="#2c3e50" stroke-width="1" stroke-dasharray="5,5"/>'
        )

    # ── 엣지 렌더링 ──
    for edge in graph.all_edges:
        src_pos = positions.get(edge.source)
        tgt_pos = positions.get(edge.target)
        if not src_pos or not tgt_pos:
            continue

        colour = _EDGE_COLOURS.get(edge.edge_type, "#6c757d")
        marker = f"arrow-{edge.edge_type}" if edge.edge_type in ("success", "blocked") else "arrow"
        dash = 'stroke-dasharray="6,4"' if edge.edge_type == "attempted" else ""
        stroke_w = "2.5" if edge.edge_type == "success" else "1.5"

        # 커브 경로 계산
        sx, sy = src_pos
        tx, ty = tgt_pos
        mx = (sx + tx) / 2
        my = (sy + ty) / 2
        # 약간의 커브 추가
        cx = mx + (ty - sy) * 0.15
        cy = my - (tx - sx) * 0.15

        parts.append(
            f'<path d="M {sx} {sy} Q {cx} {cy} {tx} {ty}" '
            f'fill="none" stroke="{colour}" stroke-width="{stroke_w}" '
            f'{dash} marker-end="url(#{marker})"/>'
        )

        # 엣지 라벨
        if edge.label or edge.label_ko:
            elabel = edge.label_ko if lang == "ko" and edge.label_ko else edge.label
            if elabel:
                parts.append(
                    f'<text x="{cx}" y="{cy - 5}" text-anchor="middle" '
                    f'fill="#8e99a4" font-size="9">{_svg_escape(elabel)}</text>'
                )

    # ── 노드 렌더링 ──
    for node in graph.all_nodes:
        pos = positions.get(node.id)
        if not pos:
            continue
        x, y = pos
        parts.append(_render_node(node, x, y, lang))

    # 범례
    parts.append(_render_legend(width, height, lang))

    parts.append("</svg>")
    return "\n".join(parts)


# ── 레이아웃 ─────────────────────────────────────────────────────


def _compute_layout(
    graph: AttackGraphData, width: int
) -> dict[str, tuple[float, float]]:
    """깊이 기반 계층 레이아웃 계산."""
    positions: dict[str, tuple[float, float]] = {}

    # 깊이별 노드 그룹
    by_depth: dict[int, list[AttackNode]] = {}
    for node in graph.all_nodes:
        by_depth.setdefault(node.depth_level, []).append(node)

    y_start = 80
    y_gap = 120

    for depth, nodes in sorted(by_depth.items()):
        y = y_start + depth * y_gap
        x_gap = (width - 100) / (len(nodes) + 1)
        for i, node in enumerate(nodes):
            x = 80 + (i + 1) * x_gap
            positions[node.id] = (x, y)

    return positions


def _compute_height(positions: dict[str, tuple[float, float]]) -> int:
    """레이아웃에 필요한 SVG 높이 계산."""
    if not positions:
        return 200
    max_y = max(y for _, y in positions.values())
    return int(max_y + 120)


# ── 노드 렌더링 ──────────────────────────────────────────────────


def _render_node(node: AttackNode, x: float, y: float, lang: str) -> str:
    """단일 노드를 SVG로 렌더링."""
    fill = _NODE_COLOURS.get(node.node_type, "#34495e")
    border = _SEVERITY_BORDER.get(node.severity, "#555")
    label = node.label_ko if lang == "ko" and node.label_ko else node.label

    # 아이콘
    icon = _node_icon(node.node_type)

    # Crown Jewel은 특별 처리 (별 모양 + 글로우)
    glow = ""
    if node.node_type == "crown_jewel":
        glow = (
            f'<circle cx="{x}" cy="{y}" r="38" fill="none" '
            f'stroke="#FFD700" stroke-width="2" opacity="0.4">'
            f'<animate attributeName="r" values="38;42;38" dur="2s" repeatCount="indefinite"/>'
            f'<animate attributeName="opacity" values="0.4;0.8;0.4" dur="2s" repeatCount="indefinite"/>'
            f'</circle>'
        )

    # 노드 본체
    r = 30 if node.node_type == "crown_jewel" else 25
    truncated = label[:18] + "..." if len(label) > 18 else label

    return (
        f'{glow}'
        f'<circle cx="{x}" cy="{y}" r="{r}" fill="{fill}" '
        f'stroke="{border}" stroke-width="2.5"/>'
        f'<text x="{x}" y="{y - 2}" text-anchor="middle" '
        f'fill="white" font-size="18">{icon}</text>'
        f'<text x="{x}" y="{y + r + 15}" text-anchor="middle" '
        f'fill="#ecf0f1" font-size="10" font-weight="500">'
        f'{_svg_escape(truncated)}</text>'
        f'<text x="{x}" y="{y + r + 27}" text-anchor="middle" '
        f'fill="#6c757d" font-size="8">L{node.depth_level}</text>'
    )


def _node_icon(node_type: str) -> str:
    """노드 타입별 아이콘."""
    icons = {
        "entry": "🔍",
        "vulnerability": "⚠️",
        "exploit": "💥",
        "pivot": "🔄",
        "escalation": "⬆️",
        "crown_jewel": "👑",
        "blocked": "🚫",
    }
    return icons.get(node_type, "•")


# ── 범례 ─────────────────────────────────────────────────────────


def _render_legend(width: int, height: int, lang: str) -> str:
    """그래프 범례."""
    lx = width - 200
    ly = height - 90

    labels = {
        "en": {
            "entry": "Entry Point",
            "vulnerability": "Vulnerability",
            "exploit": "Exploit",
            "pivot": "Pivot",
            "escalation": "Escalation",
            "crown_jewel": "Crown Jewel",
        },
        "ko": {
            "entry": "진입점",
            "vulnerability": "취약점",
            "exploit": "익스플로잇",
            "pivot": "횡이동",
            "escalation": "권한상승",
            "crown_jewel": "Crown Jewel",
        },
    }
    label_set = labels.get(lang, labels["en"])

    parts = [
        f'<rect x="{lx - 10}" y="{ly - 15}" width="200" height="85" '
        f'rx="5" fill="#0d1117" stroke="#30363d" stroke-width="1"/>',
    ]

    items = list(label_set.items())
    for i, (ntype, label) in enumerate(items):
        row = i // 2
        col = i % 2
        cx = lx + col * 95 + 10
        cy = ly + row * 22 + 5
        colour = _NODE_COLOURS.get(ntype, "#555")
        parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="5" fill="{colour}"/>'
            f'<text x="{cx + 10}" y="{cy + 4}" fill="#adb5bd" font-size="9">'
            f'{label}</text>'
        )

    return "\n".join(parts)


# ── 빈 그래프 ────────────────────────────────────────────────────


def _empty_graph_svg(width: int, lang: str) -> str:
    """공격 경로가 없을 때 빈 그래프."""
    msg = "No attack paths identified" if lang == "en" else "식별된 공격 경로 없음"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} 120" '
        f'width="{width}" height="120" '
        f'style="font-family: sans-serif; background: #1a1a2e; border-radius: 8px;">'
        f'<text x="{width // 2}" y="60" text-anchor="middle" '
        f'fill="#6c757d" font-size="14">{msg}</text>'
        f'</svg>'
    )


# ── 헬퍼 ─────────────────────────────────────────────────────────


def _svg_escape(text: str) -> str:
    """SVG/XML 이스케이프."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ── Finding → AttackGraph 변환 ───────────────────────────────────


def build_attack_graph_from_findings(
    findings: list,
    chains: list[list[str]] | None = None,
) -> AttackGraphData:
    """Finding 리스트와 체인 정보로 AttackGraphData를 생성.

    Args:
        findings: Finding 객체 리스트.
        chains: 공격 체인 (finding_id 리스트의 리스트).
                예: [["VXIS-001", "VXIS-003", "VXIS-007"]]

    Returns:
        렌더링 가능한 AttackGraphData.
    """
    graph = AttackGraphData()
    finding_map: dict[str, object] = {f.id: f for f in findings if hasattr(f, "id")}

    if not chains:
        # 체인이 없으면 개별 Finding을 독립 노드로
        path = AttackPath(name="Individual Findings", name_ko="개별 발견")
        for f in findings:
            if not hasattr(f, "id"):
                continue
            severity = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            depth = _severity_to_depth(severity)
            node = AttackNode(
                id=f.id,
                label=_split_bilingual(getattr(f, "title", f.id), "en"),
                label_ko=_split_bilingual(getattr(f, "title", f.id), "ko"),
                node_type=_depth_to_type(depth),
                severity=severity,
                finding_id=f.id,
                depth_level=depth,
            )
            path.nodes.append(node)
            path.max_depth = max(path.max_depth, depth)
        graph.add_path(path)
        return graph

    # 체인 기반 그래프 구성
    for chain_idx, chain in enumerate(chains):
        path = AttackPath(
            name=f"Attack Chain {chain_idx + 1}",
            name_ko=f"공격 체인 {chain_idx + 1}",
        )

        prev_id: str | None = None
        for step_idx, fid in enumerate(chain):
            f = finding_map.get(fid)
            if f is None:
                continue

            severity = f.severity.value if hasattr(f.severity, "value") else str(f.severity)

            # 첫 노드는 entry, 마지막은 depth 기반
            if step_idx == 0:
                ntype = "entry"
                depth = 0
            elif step_idx == len(chain) - 1:
                depth = min(step_idx + 1, 4)
                ntype = "crown_jewel" if depth == 4 else _depth_to_type(depth)
            else:
                depth = min(step_idx, 3)
                ntype = _depth_to_type(depth)

            node = AttackNode(
                id=f"{fid}-c{chain_idx}",
                label=_split_bilingual(getattr(f, "title", fid), "en"),
                label_ko=_split_bilingual(getattr(f, "title", fid), "ko"),
                node_type=ntype,
                severity=severity,
                finding_id=fid,
                depth_level=depth,
            )
            path.nodes.append(node)
            path.max_depth = max(path.max_depth, depth)

            if prev_id:
                edge = AttackEdge(
                    source=prev_id,
                    target=node.id,
                    label="chain",
                    edge_type="success",
                )
                path.edges.append(edge)

            prev_id = node.id

        path.crown_jewel_reached = path.max_depth >= 4
        graph.add_path(path)

    return graph


def _severity_to_depth(severity: str) -> int:
    """Severity → 깊이 레벨 추정."""
    mapping = {
        "critical": 3,
        "high": 2,
        "medium": 1,
        "low": 1,
        "informational": 0,
    }
    return mapping.get(severity, 0)


def _depth_to_type(depth: int) -> str:
    """깊이 → 노드 타입."""
    mapping = {
        0: "entry",
        1: "vulnerability",
        2: "exploit",
        3: "escalation",
        4: "crown_jewel",
    }
    return mapping.get(depth, "vulnerability")


def _split_bilingual(text: str, lang: str) -> str:
    """바이링구얼 텍스트에서 해당 언어 추출."""
    if "|||" in text:
        parts = text.split("|||", 1)
        return parts[1].strip() if lang == "ko" and len(parts) > 1 else parts[0].strip()
    return text
