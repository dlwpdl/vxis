from __future__ import annotations

from vxis.agent.scan_loop_actions import ScanLoopActionMixin


def test_find_finding_by_id_returns_match() -> None:
    findings = [{"id": "F-1"}, {"id": "F-2"}]
    assert ScanLoopActionMixin._find_finding_by_id(findings, "F-2") == {"id": "F-2"}


def test_find_finding_by_id_returns_none_when_absent() -> None:
    # The auto-link-chain path looked the source finding up with a bare next(),
    # which raises StopIteration if the finding is gone. The lookup must return
    # None instead so the caller can bail gracefully.
    findings = [{"id": "F-1"}]
    assert ScanLoopActionMixin._find_finding_by_id(findings, "F-missing") is None


def test_find_finding_by_id_coerces_ids_to_str() -> None:
    findings = [{"id": 7}]
    assert ScanLoopActionMixin._find_finding_by_id(findings, "7") == {"id": 7}
