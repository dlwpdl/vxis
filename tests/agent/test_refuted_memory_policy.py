from datetime import datetime, timedelta, timezone

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry


def _loop_with_refutation(item: dict) -> ScanAgentLoop:
    loop = ScanAgentLoop(
        target="http://example.test",
        registry=ToolRegistry(),
        max_iters=2,
    )
    loop._target_memory_profile = {"refuted_patterns": [item]}
    return loop


def _finding_args(**extra) -> dict:
    return {
        "finding_type": "error_oracle",
        "affected_component": "/api/foo",
        **extra,
    }


def test_stale_refutation_does_not_block_current_evidence() -> None:
    loop = _loop_with_refutation(
        {
            "finding_type": "error_oracle",
            "affected_component": "/api/foo",
            "last_seen": (datetime.now(timezone.utc) - timedelta(days=31)).isoformat(),
        }
    )

    assert loop._matches_refuted_memory_pattern(_finding_args()) is None


def test_materially_different_evidence_bypasses_recent_refutation() -> None:
    loop = _loop_with_refutation(
        {
            "finding_type": "error_oracle",
            "affected_component": "/api/foo",
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "evidence_fingerprint": "prior-evidence",
        }
    )

    assert (
        loop._matches_refuted_memory_pattern(
            _finding_args(evidence="Fresh request/control transcript with a different response.")
        )
        is None
    )


def test_recent_refutation_without_new_evidence_still_matches() -> None:
    item = {
        "finding_type": "error_oracle",
        "affected_component": "/api/foo",
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }
    loop = _loop_with_refutation(item)

    assert loop._matches_refuted_memory_pattern(_finding_args()) is item
