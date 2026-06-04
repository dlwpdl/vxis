from __future__ import annotations

from vxis.evidence.receipts import EvidenceManifest, EvidenceReceipt


def test_evidence_manifest_hash_links_and_signs_events() -> None:
    manifest = EvidenceManifest(scan_id="scan-1", signing_key="test-signing-key")

    first = manifest.add_event(
        event_type="tool_started",
        actor_type="agent",
        tool_name="sense_probe",
        input_data={"url": "https://example.test/"},
    )
    second = manifest.add_event(
        event_type="tool_finished",
        actor_type="tool",
        tool_name="sense_probe",
        output_data={"status": 200},
    )

    assert second.parent_receipt_ids == [first.receipt_id]
    assert first.receipt_hash.startswith("sha256:")
    assert second.signature.startswith("hmac-sha256:")
    assert manifest.verify() == []


def test_evidence_manifest_verifier_detects_tampering() -> None:
    manifest = EvidenceManifest(scan_id="scan-1", signing_key="test-signing-key")
    manifest.add_event(event_type="tool_finished", output_data={"status": 200})
    data = manifest.to_dict()
    data["receipts"][0]["metadata"]["scan_id"] = "tampered"

    restored = EvidenceManifest.from_dict(data, signing_key="test-signing-key")

    assert any("receipt_hash mismatch" in issue for issue in restored.verify())
    assert any("signature mismatch" in issue for issue in restored.verify())


def test_evidence_manifest_verifier_detects_broken_parent_hash() -> None:
    manifest = EvidenceManifest(scan_id="scan-1", signing_key="test-signing-key")
    first = manifest.add_event(event_type="tool_started")
    second = manifest.add_event(event_type="tool_finished")
    second.parent_hash = first.receipt_hash

    issues = manifest.verify()

    assert any("parent_hash mismatch" in issue for issue in issues)


def test_evidence_receipt_round_trips_unknown_optional_fields() -> None:
    receipt = EvidenceReceipt.from_dict(
        {
            "receipt_id": "receipt_1",
            "parent_receipt_ids": ["receipt_0"],
            "event_type": "tool_finished",
            "actor_type": "tool",
            "created_at": "2026-06-01T00:00:00+00:00",
            "metadata": {"scan_id": "scan-1"},
        }
    )

    assert receipt.to_dict()["receipt_id"] == "receipt_1"
    assert receipt.to_dict()["parent_receipt_ids"] == ["receipt_0"]
