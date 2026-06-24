"""NOW-1/1.3b — UNCONFIRMED status mapping + report exclusion.

The verifier verdict (stamped onto the finding dict in 1.3a) is mapped to
Finding.status in _build_finding_from_dict, and UNCONFIRMED findings are excluded
from the client-facing report (ctx.findings) by _should_include_in_report — while
staying in the raw _findings store for MITRE / scan-memory / retrospective.
"""
from vxis.models.finding import FindingStatus
from vxis.pipeline.scan_pipeline_v2 import (
    _build_finding_from_dict,
    _reconcile_chains,
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


def test_build_finding_needs_replay_gate_demotes_confirmed_high():
    d = _fd("CONFIRMED")
    d["severity"] = "high"
    d["acceptance_status"] = "needs_replay_gate"
    f = _build_finding_from_dict(d, "scan-1", "http://t")
    assert f.status == FindingStatus.unconfirmed


def test_build_finding_unconfirmed_maps_to_status_unconfirmed():
    f = _build_finding_from_dict(_fd("UNCONFIRMED"), "scan-1", "http://t")
    assert f.status == FindingStatus.unconfirmed


def test_build_finding_absent_verdict_maps_to_status_open():
    f = _build_finding_from_dict(_fd(None), "scan-1", "http://t")
    assert f.status == FindingStatus.open


def test_should_include_excludes_unconfirmed_only_at_high_critical():
    # F1 (review fix): exclude UNCONFIRMED only at high/critical, mirroring the
    # gate's own block (scan_loop_actions blocks UNCONFIRMED only at high/critical).
    # medium/low UNCONFIRMED are KEPT — the gate deliberately doesn't block them and
    # the verifier defaults UNCONFIRMED on parse drift, so dropping them over-suppresses.
    assert _should_include_in_report({"verifier_verdict": "UNCONFIRMED", "severity": "high"}) is False
    assert _should_include_in_report({"verifier_verdict": "UNCONFIRMED", "severity": "critical"}) is False
    assert _should_include_in_report({"verifier_verdict": "unconfirmed", "severity": "HIGH"}) is False
    assert _should_include_in_report({"verifier_verdict": "UNCONFIRMED", "severity": "medium"}) is True
    assert _should_include_in_report({"verifier_verdict": "UNCONFIRMED", "severity": "low"}) is True
    assert _should_include_in_report({"verifier_verdict": "CONFIRMED", "severity": "high"}) is True
    assert _should_include_in_report(
        {"verifier_verdict": "CONFIRMED", "severity": "high", "acceptance_status": "needs_replay_gate"}
    ) is False
    assert _should_include_in_report({"verifier_verdict": "", "severity": "high"}) is True
    assert _should_include_in_report({"severity": "critical"}) is True  # blank / legacy kept
    # F5: REFUTED never ships, at any severity (defense-in-depth)
    assert _should_include_in_report({"verifier_verdict": "REFUTED", "severity": "low"}) is False
    assert _should_include_in_report({"verifier_verdict": "refuted", "severity": "medium"}) is False


def test_reconcile_chains_drops_chains_through_excluded_findings():
    # F3 (review fix): a chain that pivots through a withheld (report-excluded)
    # finding must not be asserted as a fabricated edge in the attack graph.
    chains = [
        {"finding_ids": ["VXIS-0001", "VXIS-0002"]},
        {"finding_ids": ["VXIS-0001", "VXIS-0003", "VXIS-0004"]},  # 0003 excluded
    ]
    out = _reconcile_chains(chains, {"VXIS-0003"})
    assert len(out) == 1
    assert out[0]["finding_ids"] == ["VXIS-0001", "VXIS-0002"]


def test_reconcile_chains_keeps_all_when_nothing_excluded():
    chains = [{"finding_ids": ["A", "B"]}, {"finding_ids": ["C"]}]
    assert len(_reconcile_chains(chains, set())) == 2
