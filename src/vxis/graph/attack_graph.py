from __future__ import annotations
import networkx as nx
from .node import GraphNode, GraphEdge, NodeType
from ..evidence.schema import Evidence, Severity


class LivingAttackGraph:
    def __init__(self):
        self._graph = nx.DiGraph()
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []

    @property
    def nodes(self) -> dict[str, GraphNode]:
        return self._nodes

    @property
    def edges(self) -> list[GraphEdge]:
        return self._edges

    def add_finding(self, evidence: Evidence) -> None:
        node = GraphNode(
            id=evidence.id,
            title=evidence.title,
            severity=evidence.severity.value,
            node_type=NodeType.VULNERABILITY,
            agent_id=evidence.agent_id,
            description=evidence.description,
        )
        self._nodes[node.id] = node
        self._graph.add_node(node.id, data=node)

        if evidence.chained_from and evidence.chained_from in self._nodes:
            edge = GraphEdge(
                source_id=evidence.chained_from,
                target_id=evidence.id,
            )
            self._edges.append(edge)
            self._graph.add_edge(
                evidence.chained_from,
                evidence.id,
                label="leads_to",
            )

    def get_edges_from(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self._edges if e.source_id == node_id]

    def find_critical_chains(self) -> list[list[GraphNode]]:
        """Critical severity 노드로 끝나는 공격 체인 탐색"""
        critical_ids = {
            nid for nid, node in self._nodes.items()
            if node.severity == Severity.CRITICAL.value
        }
        chains = []
        for cid in critical_ids:
            for source in self._nodes:
                if source == cid:
                    continue
                try:
                    paths = list(nx.all_simple_paths(
                        self._graph, source, cid
                    ))
                    for path in paths:
                        if len(path) >= 2:
                            chain = [self._nodes[nid] for nid in path]
                            chains.append(chain)
                except (nx.NetworkXError, nx.NodeNotFound):
                    continue
        seen: set[tuple[str, ...]] = set()
        unique: list[list[GraphNode]] = []
        for chain in sorted(chains, key=len, reverse=True):
            key = tuple(n.id for n in chain)
            if key not in seen:
                seen.add(key)
                unique.append(chain)
        return unique

    def summary(self) -> dict:
        severity_counts: dict[str, int] = {}
        for node in self._nodes.values():
            severity_counts[node.severity] = (
                severity_counts.get(node.severity, 0) + 1
            )
        return {
            "total_findings": len(self._nodes),
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "total_chains": len(self.find_critical_chains()),
            "total_edges": len(self._edges),
        }
