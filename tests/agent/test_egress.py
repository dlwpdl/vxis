from __future__ import annotations

from vxis.agent.egress import build_allowlist, check_violations


def test_strict_egress_blocks_metadata_and_unlisted_private_hosts(monkeypatch) -> None:
    monkeypatch.setenv("VXIS_EGRESS_STRICT", "1")
    allowlist = build_allowlist("http://localhost:8081")

    assert check_violations("curl http://169.254.169.254/latest/meta-data/", allowlist) == [
        "169.254.169.254"
    ]
    assert check_violations("nmap 10.0.0.8", allowlist) == ["10.0.0.8"]


def test_strict_egress_allows_only_target_and_explicit_hosts(monkeypatch) -> None:
    monkeypatch.setenv("VXIS_EGRESS_STRICT", "1")
    monkeypatch.setenv("VXIS_EGRESS_ALLOWLIST", "10.0.0.8")
    allowlist = build_allowlist("http://localhost:8081")

    assert check_violations("curl http://localhost:8081/health", allowlist) == []
    assert check_violations("nmap 10.0.0.8", allowlist) == []


def test_non_strict_egress_remains_disabled(monkeypatch) -> None:
    monkeypatch.delenv("VXIS_EGRESS_STRICT", raising=False)

    assert check_violations("curl https://example.net", set()) == []
