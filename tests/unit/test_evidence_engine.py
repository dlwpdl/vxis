import pytest
from vxis.evidence.engine import EvidenceEngine
from vxis.evidence.schema import Evidence, Severity, EvidenceType


def test_evidence_schema():
    ev = Evidence(
        agent_id="web",
        title="SQL Injection in /login",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.HTTP_EXCHANGE,
        description="Login endpoint vulnerable to SQLi",
        request="POST /login HTTP/1.1\n...",
        response="HTTP/1.1 500 Internal Server Error\n...",
        cvss_score=9.8,
    )
    assert ev.id is not None
    assert ev.timestamp is not None
    assert ev.hash is not None


def test_evidence_hash_immutable():
    ev = Evidence(
        agent_id="web",
        title="XSS",
        severity=Severity.HIGH,
        evidence_type=EvidenceType.HTTP_EXCHANGE,
        description="Reflected XSS",
    )
    ev2 = Evidence(
        agent_id="web",
        title="XSS",
        severity=Severity.HIGH,
        evidence_type=EvidenceType.HTTP_EXCHANGE,
        description="Reflected XSS",
    )
    assert ev.hash == ev2.hash


@pytest.mark.asyncio
async def test_engine_save_and_retrieve(tmp_path):
    engine = EvidenceEngine(db_path=str(tmp_path / "evidence.db"))
    await engine.init()

    ev = Evidence(
        agent_id="cloud",
        title="S3 Bucket Public",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.MISCONFIGURATION,
        description="S3 bucket acme-dev is publicly accessible",
    )
    await engine.save(ev)

    results = await engine.get_by_severity(Severity.CRITICAL)
    assert len(results) == 1
    assert results[0].title == "S3 Bucket Public"


@pytest.mark.asyncio
async def test_engine_chain_linking(tmp_path):
    engine = EvidenceEngine(db_path=str(tmp_path / "evidence.db"))
    await engine.init()

    parent = Evidence(
        agent_id="cloud",
        title="S3 Public",
        severity=Severity.HIGH,
        evidence_type=EvidenceType.MISCONFIGURATION,
        description="S3 public access",
    )
    await engine.save(parent)

    child = Evidence(
        agent_id="secrets",
        title=".env found in S3",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.SECRET,
        description="DB credentials in .env",
        chained_from=parent.id,
    )
    await engine.save(child)

    chain = await engine.get_chain(parent.id)
    assert len(chain) == 1
    assert chain[0].id == child.id
