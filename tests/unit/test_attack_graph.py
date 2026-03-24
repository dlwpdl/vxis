import pytest
from vxis.graph.attack_graph import LivingAttackGraph
from vxis.graph.node import GraphNode, NodeType
from vxis.evidence.schema import Evidence, Severity, EvidenceType


def make_evidence(title, severity=Severity.HIGH, agent="web"):
    return Evidence(
        agent_id=agent,
        title=title,
        severity=severity,
        evidence_type=EvidenceType.HTTP_EXCHANGE,
        description=title,
    )


def test_graph_add_node():
    graph = LivingAttackGraph()
    ev = make_evidence("S3 Public Access", Severity.HIGH, "cloud")
    graph.add_finding(ev)
    assert len(graph.nodes) == 1


def test_graph_chain_creates_edge():
    graph = LivingAttackGraph()
    ev1 = make_evidence("S3 Public", Severity.HIGH, "cloud")
    graph.add_finding(ev1)

    ev2 = Evidence(
        agent_id="secrets",
        title=".env in S3",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.SECRET,
        description="DB creds found",
        chained_from=ev1.id,
    )
    graph.add_finding(ev2)

    assert len(graph.edges) == 1
    edges = graph.get_edges_from(ev1.id)
    assert len(edges) == 1
    assert edges[0].target_id == ev2.id


def test_graph_critical_chain_detection():
    graph = LivingAttackGraph()
    ev1 = make_evidence("S3 Public", Severity.HIGH, "cloud")
    graph.add_finding(ev1)

    ev2 = Evidence(
        agent_id="secrets",
        title=".env DB Creds",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.SECRET,
        description="DB credentials",
        chained_from=ev1.id,
    )
    graph.add_finding(ev2)

    ev3 = Evidence(
        agent_id="database",
        title="Direct DB Access",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.EXPLOIT,
        description="Full DB access",
        chained_from=ev2.id,
    )
    graph.add_finding(ev3)

    chains = graph.find_critical_chains()
    assert len(chains) >= 1
    assert len(chains[0]) == 3


def test_graph_attack_surface_summary():
    graph = LivingAttackGraph()
    for title in ["Finding A", "Finding B", "Finding C"]:
        graph.add_finding(make_evidence(title, Severity.HIGH))

    summary = graph.summary()
    assert summary["total_findings"] == 3
    assert summary["critical"] == 0
    assert summary["high"] == 3
