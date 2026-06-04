from __future__ import annotations

import pytest

from vxis.agent.memory import AgentMemory, ScanMemory, dual_write_scan
from vxis.pti.store import PTIStore


def test_dualwrite_writes_both_when_flag_on(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("VXIS_V3_MEMORY", "1")
    monkeypatch.setenv("VXIS_PTI_ROOT", str(tmp_path / "pti"))
    memory = AgentMemory(db_path=str(tmp_path / "legacy.json"))
    scan = ScanMemory(target="http://example.com:80", total_findings=0)

    dual_write_scan(memory, scan)

    assert memory.recall_similar("http://example.com:80")
    dossier = PTIStore(root=tmp_path / "pti").load_for_target(
        "http://example.com:80",
        create=False,
    )
    assert dossier.target_url == "http://example.com:80"


def test_dualwrite_legacy_only_when_flag_off(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VXIS_V3_MEMORY", raising=False)
    monkeypatch.setenv("VXIS_PTI_ROOT", str(tmp_path / "pti"))
    memory = AgentMemory(db_path=str(tmp_path / "legacy.json"))

    dual_write_scan(memory, ScanMemory(target="http://example.com:80"))

    assert memory.recall_similar("http://example.com:80")
    with pytest.raises(FileNotFoundError):
        PTIStore(root=tmp_path / "pti").load_for_target("http://example.com:80", create=False)
