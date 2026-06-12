from __future__ import annotations

from datetime import datetime, timezone

import pytest
import yaml

from vxis.pti import Dossier, PTIStore, StackEntry, target_hash_for_url


def test_store_persists_and_loads_dossier_under_target_hash(tmp_path) -> None:
    store = PTIStore(tmp_path / "data" / "pti")
    target_url = "https://example.com/app?secret=1"
    target_hash = target_hash_for_url(target_url)
    timestamp = datetime(2026, 6, 2, 12, 0, tzinfo=timezone.utc)
    dossier = Dossier(
        target_hash=target_hash,
        target_url=target_url,
        created_at=timestamp,
        updated_at=timestamp,
        scan_ids=["scan-1"],
        stack=[
            StackEntry(
                tech="rails",
                confidence=0.9,
                first_seen_scan="scan-1",
                last_seen_scan="scan-1",
                evidence=["header"],
            )
        ],
    )

    path = store.persist(dossier)
    loaded = store.load(target_hash)

    assert path == tmp_path / "data" / "pti" / target_hash / "dossier.yaml"
    assert loaded == dossier
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["target_url"] == (
        "https://example.com:443"
    )


def test_store_creates_empty_dossier_for_missing_target_when_requested(tmp_path) -> None:
    store = PTIStore(tmp_path / "data" / "pti")
    dossier = store.load_for_target("https://example.com/path?x=1")

    assert dossier.target_hash == target_hash_for_url("https://example.com")
    assert dossier.target_url == "https://example.com:443"
    assert dossier.stack == []


def test_store_missing_without_create_raises(tmp_path) -> None:
    store = PTIStore(tmp_path / "data" / "pti")

    with pytest.raises(FileNotFoundError):
        store.load(target_hash_for_url("https://example.com"))


def test_store_writes_korean_evidence_as_readable_unicode(tmp_path) -> None:
    store = PTIStore(tmp_path / "data" / "pti")
    target_url = "https://example.com/app"
    target_hash = target_hash_for_url(target_url)
    timestamp = datetime(2026, 6, 2, 12, 0, tzinfo=timezone.utc)
    korean_evidence = "관리자 세션 탈취 가능"
    dossier = Dossier(
        target_hash=target_hash,
        target_url=target_url,
        created_at=timestamp,
        updated_at=timestamp,
        scan_ids=["scan-1"],
        stack=[
            StackEntry(
                tech="rails",
                confidence=0.9,
                first_seen_scan="scan-1",
                last_seen_scan="scan-1",
                evidence=[korean_evidence],
            )
        ],
    )

    path = store.persist(dossier)
    raw = path.read_text(encoding="utf-8")

    # The human-facing dossier must hold readable Korean, not \uXXXX escapes.
    assert korean_evidence in raw
    assert "\\uc870" not in raw and "\\u" not in raw
