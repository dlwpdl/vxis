import pytest
from vxis.graph.hypothesis import Hypothesis, HypothesisQueue, HypothesisStatus

def test_hypothesis_creation():
    h = Hypothesis(
        title="GraphQL introspection enabled",
        rationale="Target has /graphql endpoint",
        probability=0.75,
        impact=0.9,
        suggested_agent="api",
        suggested_tool="graphql_introspect",
    )
    assert h.priority_score == pytest.approx(0.75 * 0.9, rel=1e-3)
    assert h.status == HypothesisStatus.PENDING

def test_hypothesis_queue_ordering():
    queue = HypothesisQueue()
    h1 = Hypothesis(
        title="Low priority",
        rationale="test",
        probability=0.3,
        impact=0.3,
        suggested_agent="web",
    )
    h2 = Hypothesis(
        title="High priority",
        rationale="test",
        probability=0.9,
        impact=0.95,
        suggested_agent="cloud",
    )
    queue.push(h1)
    queue.push(h2)

    top = queue.pop()
    assert top.title == "High priority"

def test_hypothesis_accept_reject():
    queue = HypothesisQueue()
    h = Hypothesis(
        title="Test hypo",
        rationale="test",
        probability=0.5,
        impact=0.5,
        suggested_agent="web",
    )
    queue.push(h)
    top = queue.pop()
    top.accept(note="Confirmed XSS at /search")
    assert top.status == HypothesisStatus.CONFIRMED

def test_queue_generates_from_finding():
    from vxis.graph.hypothesis import HypothesisGenerator
    from vxis.evidence.schema import Evidence, Severity, EvidenceType

    ev = Evidence(
        agent_id="cloud",
        title="S3 bucket public",
        severity=Severity.HIGH,
        evidence_type=EvidenceType.MISCONFIGURATION,
        description="S3 bucket acme-dev is public",
    )
    generated = HypothesisGenerator.from_finding(ev)
    assert len(generated) >= 1
    assert any("secret" in h.suggested_agent or
               "supply_chain" in h.suggested_agent
               for h in generated)
