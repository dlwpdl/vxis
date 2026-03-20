"""Unit tests for the Evidence model and utility functions."""

from __future__ import annotations

import hashlib

import pytest

from vxis.models.evidence import (
    EvidenceItem,
    create_evidence,
    mask_secret,
    transfer_custody,
)


# ---------------------------------------------------------------------------
# create_evidence
# ---------------------------------------------------------------------------


class TestCreateEvidence:
    def test_sha256_hash_matches_content(self):
        content = b"SELECT * FROM users WHERE id = 1"
        item = create_evidence(content, "log", "plugin_sqlmap", "finding-001")

        expected_hash = hashlib.sha256(content).hexdigest()
        assert item.sha256_hash == expected_hash

    def test_sha256_hash_changes_with_different_content(self):
        item1 = create_evidence(b"content_a", "log", "tool", "finding-001")
        item2 = create_evidence(b"content_b", "log", "tool", "finding-001")
        assert item1.sha256_hash != item2.sha256_hash

    def test_finding_id_set_correctly(self):
        item = create_evidence(b"data", "screenshot", "tool", "finding-xyz")
        assert item.finding_id == "finding-xyz"

    def test_evidence_type_set_correctly(self):
        item = create_evidence(b"data", "packet_capture", "tool", "finding-001")
        assert item.evidence_type == "packet_capture"

    def test_captured_by_set_to_tool(self):
        item = create_evidence(b"data", "log", "nmap_plugin", "finding-001")
        assert item.captured_by == "nmap_plugin"

    def test_content_preserved(self):
        content = b"\x00\x01\x02binary\xff"
        item = create_evidence(content, "binary", "tool", "finding-001")
        assert item.content == content

    def test_evidence_id_is_non_empty_string(self):
        item = create_evidence(b"data", "log", "tool", "finding-001")
        assert isinstance(item.evidence_id, str)
        assert len(item.evidence_id) > 0

    def test_unique_evidence_ids(self):
        item1 = create_evidence(b"data", "log", "tool", "finding-001")
        item2 = create_evidence(b"data", "log", "tool", "finding-001")
        assert item1.evidence_id != item2.evidence_id

    def test_empty_content_hash(self):
        """SHA-256 of empty bytes is well-defined and should not raise."""
        item = create_evidence(b"", "log", "tool", "finding-001")
        expected = hashlib.sha256(b"").hexdigest()
        assert item.sha256_hash == expected

    def test_metadata_initialized_as_empty_dict(self):
        item = create_evidence(b"data", "log", "tool", "finding-001")
        assert item.metadata == {}


# ---------------------------------------------------------------------------
# chain_of_custody — initial record
# ---------------------------------------------------------------------------


class TestChainOfCustody:
    def test_initial_custody_has_one_entry(self):
        item = create_evidence(b"data", "log", "tool", "finding-001")
        assert len(item.chain_of_custody) == 1

    def test_initial_custody_action_is_captured(self):
        item = create_evidence(b"data", "log", "nmap_plugin", "finding-001")
        first = item.chain_of_custody[0]
        assert first["action"] == "captured"

    def test_initial_custody_actor_is_tool(self):
        item = create_evidence(b"data", "log", "nmap_plugin", "finding-001")
        first = item.chain_of_custody[0]
        assert first["actor"] == "nmap_plugin"

    def test_initial_custody_has_timestamp(self):
        item = create_evidence(b"data", "log", "tool", "finding-001")
        first = item.chain_of_custody[0]
        assert "timestamp" in first
        assert isinstance(first["timestamp"], str)
        # ISO 8601 timestamp must be non-empty
        assert len(first["timestamp"]) > 0


# ---------------------------------------------------------------------------
# transfer_custody
# ---------------------------------------------------------------------------


class TestTransferCustody:
    def test_transfer_appends_new_record(self):
        item = create_evidence(b"data", "log", "tool", "finding-001")
        assert len(item.chain_of_custody) == 1

        transfer_custody(item, "reviewed", "analyst_alice")

        assert len(item.chain_of_custody) == 2

    def test_transfer_record_has_correct_action(self):
        item = create_evidence(b"data", "log", "tool", "finding-001")
        transfer_custody(item, "exported", "analyst_bob")

        last = item.chain_of_custody[-1]
        assert last["action"] == "exported"

    def test_transfer_record_has_correct_actor(self):
        item = create_evidence(b"data", "log", "tool", "finding-001")
        transfer_custody(item, "transferred", "manager_carol")

        last = item.chain_of_custody[-1]
        assert last["actor"] == "manager_carol"

    def test_transfer_record_has_timestamp(self):
        item = create_evidence(b"data", "log", "tool", "finding-001")
        transfer_custody(item, "reviewed", "analyst_alice")

        last = item.chain_of_custody[-1]
        assert "timestamp" in last
        assert isinstance(last["timestamp"], str)

    def test_multiple_transfers_all_recorded(self):
        item = create_evidence(b"data", "log", "tool", "finding-001")
        transfer_custody(item, "reviewed", "alice")
        transfer_custody(item, "approved", "bob")
        transfer_custody(item, "archived", "carol")

        assert len(item.chain_of_custody) == 4  # 1 initial + 3 transfers

    def test_transfer_returns_same_item(self):
        item = create_evidence(b"data", "log", "tool", "finding-001")
        returned = transfer_custody(item, "reviewed", "alice")
        assert returned is item

    def test_transfer_preserves_initial_custody(self):
        item = create_evidence(b"data", "log", "tool", "finding-001")
        transfer_custody(item, "reviewed", "alice")

        first = item.chain_of_custody[0]
        assert first["action"] == "captured"
        assert first["actor"] == "tool"


# ---------------------------------------------------------------------------
# mask_secret
# ---------------------------------------------------------------------------


class TestMaskSecret:
    def test_short_string_fully_masked(self):
        """Strings of 8 chars or fewer are completely replaced with asterisks."""
        assert mask_secret("short") == "*****"
        assert mask_secret("12345678") == "********"

    def test_empty_string(self):
        assert mask_secret("") == ""

    def test_single_char(self):
        assert mask_secret("x") == "*"

    def test_8_chars_fully_masked(self):
        result = mask_secret("abcdefgh")
        assert result == "********"
        assert len(result) == 8

    def test_long_string_keeps_first_4(self):
        secret = "abcdefghij"  # 10 chars
        result = mask_secret(secret)
        assert result.startswith("abcd")

    def test_long_string_keeps_last_4(self):
        secret = "abcdefghij"  # 10 chars
        result = mask_secret(secret)
        assert result.endswith("ghij")

    def test_long_string_middle_is_asterisks(self):
        secret = "abcdefghij"  # 10 chars → middle 2 chars masked
        result = mask_secret(secret)
        middle = result[4:-4]
        assert middle == "**"
        assert all(c == "*" for c in middle)

    def test_long_string_length_preserved(self):
        secret = "supersecretpassword"  # 19 chars
        result = mask_secret(secret)
        assert len(result) == len(secret)

    def test_9_char_string(self):
        """9-char string: 4 visible + 1 masked + 4 visible."""
        secret = "123456789"
        result = mask_secret(secret)
        assert result == "1234*6789"

    def test_very_long_string(self):
        secret = "a" * 4 + "secret_middle" + "z" * 4  # 4 + 13 + 4 = 21 chars
        result = mask_secret(secret)
        assert result.startswith("aaaa")
        assert result.endswith("zzzz")
        assert len(result) == 21
        middle = result[4:-4]
        assert all(c == "*" for c in middle)

    def test_api_key_pattern(self):
        api_key = "sk-prod-abcdefghijklmnop"
        result = mask_secret(api_key)
        assert result.startswith("sk-p")
        assert result.endswith("mnop")
        assert len(result) == len(api_key)
