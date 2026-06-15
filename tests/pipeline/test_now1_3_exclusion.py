"""NOW-1/1.3b — UNCONFIRMED status mapping + report exclusion.

The verifier verdict (stamped onto the finding dict in 1.3a) is mapped to
Finding.status in _build_finding_from_dict, and UNCONFIRMED findings are excluded
from the client-facing report (ctx.findings) by _should_include_in_report — while
staying in the raw _findings store for MITRE / scan-memory / retrospective.
"""
from vxis.models.finding import FindingStatus
from vxis.pipeline.scan_pipeline_v2 import (
    _build_finding_from_dict,
    _should_include_in_report,
)


def _fd(verdict=None) -> dict:
    d = {
        "id": "VXIS-0001",
        "title": "Reflected XSS",
        "severity": "medium",
        "finding_type": "xss",
        "affected_component": "/search",
        "description": "d",
        "impact": "i",
        "technical_analysis": "t",
        "poc_description": "p",
        "poc_script_code": "c",
        "evidence": "e",
        "remediation": "r",
        "cwe": "",
    }
    if verdict is not None:
        d["verifier_verdict"] = verdict
    return d


def test_finding_status_has_unconfirmed_member():
    assert FindingStatus.unconfirmed.value == "unconfirmed"


def test_build_finding_confirmed_maps_to_status_confirmed():
    f = _build_finding_from_dict(_fd("CONFIRMED"), "scan-1", "http://t")
    assert f.status == FindingStatus.confirmed


def test_build_finding_unconfirmed_maps_to_status_unconfirmed():
    f = _build_finding_from_dict(_fd("UNCONFIRMED"), "scan-1", "http://t")
    assert f.status == FindingStatus.unconfirmed


def test_build_finding_absent_verdict_maps_to_status_open():
    f = _build_finding_from_dict(_fd(None), "scan-1", "http://t")
    assert f.status == FindingStatus.open


def test_should_include_excludes_only_unconfirmed():
    # strict equality to UNCONFIRMED — no over-suppression of CONFIRMED / blank
    assert _should_include_in_report({"verifier_verdict": "UNCONFIRMED"}) is False
    assert _should_include_in_report({"verifier_verdict": "unconfirmed"}) is False  # case-insensitive
    assert _should_include_in_report({"verifier_verdict": "CONFIRMED"}) is True
    assert _should_include_in_report({"verifier_verdict": ""}) is True
    assert _should_include_in_report({}) is True  # blank / legacy / info kept
