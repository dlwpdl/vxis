from __future__ import annotations

import json

from vxis.runtime.resource_manifest import ResourceManifest


def test_resource_manifest_records_file_hash_and_size(tmp_path) -> None:
    artifact = tmp_path / "probe.json"
    artifact.write_text('{"status": 200}', encoding="utf-8")
    manifest = ResourceManifest(scan_id="scan-1")

    record = manifest.add_file(
        artifact,
        kind="http_response",
        metadata={"url": "https://example.test/"},
        receipt_ids=["receipt_1"],
    )

    assert record.sha256.startswith("sha256:")
    assert record.size_bytes == artifact.stat().st_size
    assert record.receipt_ids == ["receipt_1"]
    assert manifest.verify() == []


def test_resource_manifest_round_trips_and_detects_file_mutation(tmp_path) -> None:
    artifact = tmp_path / "screenshot.txt"
    artifact.write_text("before", encoding="utf-8")
    manifest = ResourceManifest(scan_id="scan-1")
    manifest.add_file(artifact)
    out = manifest.write(tmp_path / "resources.json")

    restored = ResourceManifest.from_dict(json.loads(out.read_text(encoding="utf-8")))
    artifact.write_text("after", encoding="utf-8")

    assert any("sha256 mismatch" in issue for issue in restored.verify())
