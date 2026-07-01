"""Helpers for converting stored findings back to domain models."""

from __future__ import annotations


def convert_finding_records(records) -> list:
    """Convert FindingRecord ORM rows to Pydantic Finding models."""
    from vxis.models.finding import (
        CVSSVector,
        Evidence,
        Finding,
        FindingStatus,
        MitreAttack,
        Reference,
        Severity,
    )

    findings: list[Finding] = []
    for rec in records:
        cvss = None
        if rec.cvss_score is not None and rec.cvss_vector:
            cvss = CVSSVector(vector_string=rec.cvss_vector, base_score=rec.cvss_score)

        mitre = None
        if rec.mitre_attack:
            mitre = MitreAttack(**rec.mitre_attack)

        evidence = [Evidence(**e) for e in (rec.evidence or [])]
        references = [Reference(**r) for r in (rec.references or [])]

        findings.append(
            Finding(
                id=str(rec.id),
                scan_id=str(rec.scan_id),
                title=rec.title,
                description=rec.description,
                severity=Severity(rec.severity),
                status=FindingStatus(rec.status),
                target=rec.target,
                affected_component=rec.affected_component or "",
                port=rec.port,
                protocol=rec.protocol,
                finding_type=rec.finding_type,
                cvss=cvss,
                cve_ids=rec.cve_ids or [],
                cwe_ids=rec.cwe_ids or [],
                mitre_attack=mitre,
                source_plugin=rec.source_plugin,
                source_plugins=rec.source_plugins or [],
                confidence=rec.confidence,
                evidence=evidence,
                remediation=rec.remediation,
                references=references,
                analyst_severity=Severity(rec.analyst_severity)
                if rec.analyst_severity
                else None,
                analyst_notes=rec.analyst_notes,
                discovered_at=rec.discovered_at,
                updated_at=rec.updated_at,
            )
        )
    return findings
