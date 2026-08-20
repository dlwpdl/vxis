from __future__ import annotations

import json
import multiprocessing
import sys
import time
import types
from pathlib import Path

import pytest

from vxis.agent.tools import memory_tools


def _record_in_process(kb_path: str, target: str) -> None:
    memory_tools._KB_PATH = Path(kb_path)
    original_load = memory_tools._load_kb

    def slow_load(*args, **kwargs):
        value = original_load(*args, **kwargs)
        time.sleep(0.05)
        return value

    memory_tools._load_kb = slow_load
    memory_tools.record_scan_result(
        target=target,
        scan_id=target.rsplit("-", 1)[-1],
        findings=[
            {
                "finding_type": "information_disclosure",
                "affected_component": "/debug",
                "severity": "low",
                "title": f"Debug disclosure on {target}",
            }
        ],
    )


def test_record_scan_result_persists_target_memory_profile(tmp_path, monkeypatch) -> None:
    kb_path = tmp_path / "scan_kb.json"
    monkeypatch.setattr(memory_tools, "_KB_PATH", kb_path)

    memory_tools.record_scan_result(
        target="http://localhost:3000",
        findings=[
            {
                "finding_type": "sql_injection",
                "affected_component": "/rest/products/search?q=",
                "severity": "critical",
                "title": "SQL injection on q",
            }
        ],
        fingerprint={"recommended_playbooks": ["juice_shop"]},
        confirmed_findings=[
            {
                "finding_type": "sql_injection",
                "affected_component": "/rest/products/search?q=",
                "title": "SQL injection on q",
                "confidence": "high",
                "reasoning": "Confirmed with transcript.",
            }
        ],
        refuted_findings=[
            {
                "finding_type": "error_oracle",
                "affected_component": "/api/foo",
                "title": "HTTP 500 on /api/foo",
                "reasoning": "Generic 500 page only.",
            }
        ],
        review_history=[
            {"stage": "verifier", "verdict": "CONFIRMED", "title": "SQL injection on q"}
        ],
        branches=[
            {
                "id": "branch-1",
                "vector_id": "WEB-SQLI-001",
                "title": "Dump product table",
                "role": "post_exploit_worker",
                "phase": "data_access",
                "objective": "Extract table rows",
                "next_step": "Run sqlmap --dump",
                "status": "active",
            }
        ],
    )

    profile = memory_tools.load_target_memory_profile("http://localhost:3000")
    assert profile["target_known"] is True
    assert profile["prior_scan_count"] == 1
    assert profile["known_findings"][0]["finding_type"] == "sql_injection"
    assert profile["refuted_patterns"][0]["finding_type"] == "error_oracle"
    assert profile["successful_tactics"][0]["finding_type"] == "sql_injection"
    assert profile["branch_leads"][0]["id"] == "branch-1"
    assert profile["aggregated_findings"][0]["canonical_key"].startswith("sql_injection::")

    raw = json.loads(kb_path.read_text(encoding="utf-8"))
    target_entry = raw["targets"]["http://localhost:3000"]
    assert target_entry["scans"][0]["review_history_tail"][0]["stage"] == "verifier"


def test_record_scan_result_skips_soft_refutation_reasons(tmp_path, monkeypatch) -> None:
    kb_path = tmp_path / "scan_kb.json"
    monkeypatch.setattr(memory_tools, "_KB_PATH", kb_path)

    memory_tools.record_scan_result(
        target="http://localhost:3000",
        findings=[],
        refuted_findings=[
            {
                "finding_type": "sql_injection",
                "affected_component": "/rest/user/login",
                "title": "SQLi on login",
                "reasoning": "verify_finding: REFUTED (high) — incomplete high-severity report contract",
            }
        ],
    )

    profile = memory_tools.load_target_memory_profile("http://localhost:3000")
    assert profile["refuted_patterns"] == []


def test_load_target_memory_profile_filters_legacy_soft_refutations(tmp_path, monkeypatch) -> None:
    kb_path = tmp_path / "scan_kb.json"
    monkeypatch.setattr(memory_tools, "_KB_PATH", kb_path)
    kb_path.write_text(
        json.dumps(
            {
                "targets": {
                    "http://localhost:3000": {
                        "refuted_patterns": [
                            {
                                "finding_type": "sql_injection",
                                "affected_component": "/rest/user/login",
                                "reasoning": "verify_finding: REFUTED (high) — incomplete high-severity report contract",
                            },
                            {
                                "finding_type": "error_oracle",
                                "affected_component": "/api/foo",
                                "reasoning": "Generic 500 page only.",
                            },
                        ],
                        "scans": [],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    profile = memory_tools.load_target_memory_profile("http://localhost:3000")
    assert len(profile["refuted_patterns"]) == 1
    assert profile["refuted_patterns"][0]["finding_type"] == "error_oracle"


def test_record_scan_result_aggregates_same_target_findings_across_runs(
    tmp_path, monkeypatch
) -> None:
    kb_path = tmp_path / "scan_kb.json"
    monkeypatch.setattr(memory_tools, "_KB_PATH", kb_path)

    memory_tools.record_scan_result(
        target="http://localhost:3000",
        scan_id="VXIS-1",
        findings=[
            {
                "finding_type": "sqli",
                "affected_component": "http://localhost:3000/rest/products/search?q=test",
                "severity": "critical",
                "title": "SQLi on q",
            }
        ],
    )
    memory_tools.record_scan_result(
        target="http://localhost:3000",
        scan_id="VXIS-2",
        findings=[
            {
                "finding_type": "sql_injection",
                "affected_component": "http://localhost:3000/rest/products/search?q=demo",
                "severity": "high",
                "title": "SQL injection on q",
            }
        ],
    )

    profile = memory_tools.load_target_memory_profile("http://localhost:3000")
    assert len(profile["aggregated_findings"]) == 1
    merged = profile["aggregated_findings"][0]
    assert merged["finding_type"] == "sql_injection"
    assert merged["occurrences"] == 2
    assert set(merged["source_scan_ids"]) == {"VXIS-1", "VXIS-2"}


def test_record_scan_result_collapses_git_variant_paths_into_single_aggregate(
    tmp_path, monkeypatch
) -> None:
    kb_path = tmp_path / "scan_kb.json"
    monkeypatch.setattr(memory_tools, "_KB_PATH", kb_path)

    memory_tools.record_scan_result(
        target="http://localhost:3000",
        scan_id="VXIS-1",
        findings=[
            {
                "finding_type": "misconfiguration",
                "affected_component": "http://localhost:3000/.git/description",
                "severity": "critical",
                "title": "Infrastructure exposure: git_exposed",
            }
        ],
    )
    memory_tools.record_scan_result(
        target="http://localhost:3000",
        scan_id="VXIS-2",
        findings=[
            {
                "finding_type": "misconfiguration",
                "affected_component": "http://localhost:3000/.git/COMMIT_EDITMSG",
                "severity": "critical",
                "title": "Infrastructure exposure: git_exposed",
            }
        ],
    )

    profile = memory_tools.load_target_memory_profile("http://localhost:3000")
    git_items = [
        item
        for item in profile["aggregated_findings"]
        if item["canonical_key"] == "misconfiguration::/.git"
    ]
    assert len(git_items) == 1
    assert git_items[0]["occurrences"] == 2


def test_migrate_scan_kb_rebuilds_legacy_aggregates(tmp_path, monkeypatch) -> None:
    kb_path = tmp_path / "scan_kb.json"
    monkeypatch.setattr(memory_tools, "_KB_PATH", kb_path)
    kb_path.write_text(
        json.dumps(
            {
                "targets": {
                    "http://localhost:3000": {
                        "scans": [
                            {
                                "timestamp": "2026-05-09T00:00:00+00:00",
                                "scan_id": "VXIS-1",
                                "finding_summaries": [
                                    {
                                        "finding_type": "misconfiguration",
                                        "affected_component": "http://localhost:3000/.git/description",
                                        "severity": "critical",
                                        "title": "Infrastructure exposure: git_exposed",
                                    },
                                    {
                                        "finding_type": "misconfiguration",
                                        "affected_component": "http://localhost:3000/.git/COMMIT_EDITMSG",
                                        "severity": "critical",
                                        "title": "Infrastructure exposure: git_exposed",
                                    },
                                ],
                            }
                        ],
                        "known_findings": [],
                        "aggregated_findings": [],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    result = memory_tools.migrate_scan_kb()
    assert result["targets"] == 1

    profile = memory_tools.load_target_memory_profile("http://localhost:3000")
    git_items = [
        item
        for item in profile["aggregated_findings"]
        if item["canonical_key"] == "misconfiguration::/.git"
    ]
    assert len(git_items) == 1
    assert git_items[0]["occurrences"] == 2


def test_migrate_scan_kb_prunes_stale_oneoff_noise(tmp_path, monkeypatch) -> None:
    kb_path = tmp_path / "scan_kb.json"
    monkeypatch.setattr(memory_tools, "_KB_PATH", kb_path)
    kb_path.write_text(
        json.dumps(
            {
                "targets": {
                    "http://localhost:3000": {
                        "scans": [
                            {
                                "timestamp": "2026-05-08T00:00:00+00:00",
                                "scan_id": "VXIS-1",
                                "finding_summaries": [
                                    {
                                        "finding_type": "nosql",
                                        "affected_component": "http://localhost:3000/rest/products/search?q=test",
                                        "severity": "medium",
                                        "title": "NoSQL on q",
                                    },
                                    {
                                        "finding_type": "ssti",
                                        "affected_component": "http://localhost:3000/rest/products/search?q=test",
                                        "severity": "medium",
                                        "title": "SSTI on q",
                                    },
                                    {
                                        "finding_type": "sql_injection",
                                        "affected_component": "http://localhost:3000/rest/products/search?q=test",
                                        "severity": "critical",
                                        "title": "SQLI on q",
                                    },
                                ],
                            }
                        ],
                        "known_findings": [],
                        "aggregated_findings": [],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    memory_tools.migrate_scan_kb()
    profile = memory_tools.load_target_memory_profile("http://localhost:3000")
    keys = {item["canonical_key"] for item in profile["aggregated_findings"]}
    assert "sql_injection::/rest/products/search" in keys
    assert "nosql::/rest/products/search" not in keys
    assert "ssti::/rest/products/search" not in keys


def test_record_scan_result_does_not_overwrite_corrupt_kb(tmp_path, monkeypatch) -> None:
    kb_path = tmp_path / "scan_kb.json"
    monkeypatch.setattr(memory_tools, "_KB_PATH", kb_path)
    corrupt = '{"targets": '
    kb_path.write_text(corrupt, encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        memory_tools.record_scan_result(
            target="http://example.test",
            findings=[
                {
                    "finding_type": "idor",
                    "affected_component": "/api/users/1",
                    "severity": "medium",
                    "title": "IDOR",
                }
            ],
        )

    assert kb_path.read_text(encoding="utf-8") == corrupt


def test_record_scan_result_surfaces_atomic_replace_failure(tmp_path, monkeypatch) -> None:
    kb_path = tmp_path / "scan_kb.json"
    monkeypatch.setattr(memory_tools, "_KB_PATH", kb_path)

    def fail_replace(_source, _destination):  # type: ignore[no-untyped-def]
        raise OSError("disk unavailable")

    monkeypatch.setattr(memory_tools.os, "replace", fail_replace)

    with pytest.raises(OSError, match="disk unavailable"):
        memory_tools.record_scan_result(
            target="http://localhost:3000",
            findings=[
                {
                    "finding_type": "information_disclosure",
                    "affected_component": "/debug",
                    "severity": "low",
                    "title": "Debug endpoint",
                }
            ],
        )

    assert not list(tmp_path.glob(".scan_kb.json.*.tmp"))


@pytest.mark.skipif("fork" not in multiprocessing.get_all_start_methods(), reason="needs fork")
def test_record_scan_result_serializes_cross_process_writers(tmp_path) -> None:
    kb_path = tmp_path / "scan_kb.json"
    process_context = multiprocessing.get_context("fork")
    processes = [
        process_context.Process(
            target=_record_in_process,
            args=(str(kb_path), f"http://target-{index}.test"),
        )
        for index in range(4)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)

    assert all(process.exitcode == 0 for process in processes)
    stored = json.loads(kb_path.read_text(encoding="utf-8"))
    assert set(stored["targets"]) == {
        "http://target-0.test",
        "http://target-1.test",
        "http://target-2.test",
        "http://target-3.test",
    }


def test_kb_write_lock_uses_windows_file_locking(tmp_path, monkeypatch) -> None:
    kb_path = tmp_path / "scan_kb.json"
    monkeypatch.setattr(memory_tools, "_KB_PATH", kb_path)
    modes: list[int] = []
    fake_msvcrt = types.ModuleType("msvcrt")
    fake_msvcrt.LK_LOCK = 1
    fake_msvcrt.LK_UNLCK = 2
    fake_msvcrt.locking = lambda _fd, mode, _size: modes.append(mode)
    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)
    monkeypatch.setattr(memory_tools.os, "name", "nt")

    with memory_tools._kb_write_lock():
        pass

    assert modes == [fake_msvcrt.LK_LOCK, fake_msvcrt.LK_UNLCK]
