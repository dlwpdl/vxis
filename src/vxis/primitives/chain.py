"""Chain primitives — attack graph construction and path analysis.

Algorithmic only — no LLM calls. Uses NetworkX when available, falls back to
an adjacency-dict implementation otherwise.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

try:
    import networkx as nx  # type: ignore

    _HAS_NX = True
except Exception:  # pragma: no cover
    nx = None  # type: ignore[assignment]
    _HAS_NX = False


_SEVERITY_WEIGHTS: dict[str, int] = {
    "informational": 1,
    "info": 1,
    "low": 2,
    "medium": 4,
    "high": 7,
    "critical": 10,
}


def chain_graph_from_findings(findings: list[dict]) -> dict:
    """Build a finding graph keyed by id → neighbors.

    Edges are inferred from shared affected_component, URL host, or
    finding_type synergy. Returns a dict (not an nx.Graph) for easy
    serialization, but mirrors an nx DiGraph if NetworkX is installed.
    """
    nodes: dict[str, dict] = {}
    adjacency: dict[str, list[str]] = {}

    for f in findings:
        fid = str(f.get("id") or f.get("finding_id") or "")
        if not fid:
            continue
        nodes[fid] = {
            "id": fid,
            "severity": str(f.get("severity", "low")).lower(),
            "finding_type": f.get("finding_type", ""),
            "affected_component": f.get("affected_component", ""),
            "target": f.get("target", ""),
            "title": f.get("title", ""),
        }
        adjacency.setdefault(fid, [])

    # Derive edges by shared component or host.
    ids = list(nodes.keys())
    for i, a_id in enumerate(ids):
        a = nodes[a_id]
        for b_id in ids[i + 1 :]:
            b = nodes[b_id]
            shared = False
            if a["affected_component"] and a["affected_component"] == b["affected_component"]:
                shared = True
            elif a["target"] and a["target"] == b["target"]:
                shared = True
            elif _synergy(a["finding_type"], b["finding_type"]):
                shared = True
            if shared:
                adjacency[a_id].append(b_id)
                adjacency[b_id].append(a_id)

    graph: dict[str, Any] = {"nodes": nodes, "adjacency": adjacency}

    if _HAS_NX:
        g = nx.DiGraph()
        for fid, data in nodes.items():
            g.add_node(fid, **data)
        for src, dsts in adjacency.items():
            for dst in dsts:
                g.add_edge(src, dst)
        graph["_nx"] = g

    return graph


def _synergy(type_a: str, type_b: str) -> bool:
    """Rule-based finding-type synergy: known exploit chain pairs."""
    if not type_a or not type_b:
        return False
    pairs: set[tuple[str, str]] = {
        ("sql_injection", "authentication_bypass"),
        ("xss", "csrf"),
        ("ssrf", "rce"),
        ("lfi", "rce"),
        ("xxe", "ssrf"),
        ("idor", "privilege_escalation"),
        ("open_redirect", "phishing"),
        ("information_disclosure", "privilege_escalation"),
        ("deserialization", "rce"),
        ("path_traversal", "information_disclosure"),
    }
    a, b = type_a.lower(), type_b.lower()
    return (a, b) in pairs or (b, a) in pairs


def find_chain_paths(
    graph: dict,
    source_id: str,
    target_severity: str = "critical",
) -> list[list[str]]:
    """Find paths from source_id to any node with severity ≥ target_severity.

    Uses BFS; returns up to 10 shortest paths.
    """
    nodes = graph.get("nodes", {})
    adjacency = graph.get("adjacency", {})
    if source_id not in nodes:
        return []

    target_weight = _SEVERITY_WEIGHTS.get(target_severity.lower(), 10)
    paths: list[list[str]] = []

    from collections import deque

    q: deque[list[str]] = deque([[source_id]])
    max_paths = 10
    max_depth = 6

    while q and len(paths) < max_paths:
        path = q.popleft()
        if len(path) > max_depth:
            continue
        last = path[-1]
        last_node = nodes.get(last, {})
        weight = _SEVERITY_WEIGHTS.get(last_node.get("severity", "low"), 1)
        if weight >= target_weight and len(path) > 1:
            paths.append(path)
            continue
        for neighbor in adjacency.get(last, []):
            if neighbor not in path:
                q.append(path + [neighbor])

    return paths


def chain_score(chain: list[dict]) -> int:
    """Compute a severity score for an attack chain (higher = worse).

    Sums per-step severity weights with a chain-length bonus.
    """
    if not chain:
        return 0
    total = 0
    for step in chain:
        sev = str(step.get("severity", "low")).lower()
        total += _SEVERITY_WEIGHTS.get(sev, 1)
    # Chain length bonus: longer chains indicate deeper compromise.
    total += max(0, len(chain) - 1) * 3
    return total


def chain_link(from_finding_id: str, to_finding_id: str, reasoning: str) -> dict:
    """Create an explicit chain link between two findings."""
    return {
        "from": from_finding_id,
        "to": to_finding_id,
        "reasoning": reasoning,
        "type": "explicit",
    }
