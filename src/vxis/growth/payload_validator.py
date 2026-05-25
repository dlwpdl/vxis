"""Payload smoke test — validate new payloads against benchmark targets.

Zero LLM cost: just sends HTTP requests and checks detect signatures.
Used by growth-loop to validate auto-added payloads and isolate
regressions to individual payloads instead of rolling back everything.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Benchmark targets (same as growth-loop Docker services)
DEFAULT_TARGETS = [
    "http://localhost:3000",  # Juice Shop
    "http://localhost:8081",  # DVWA
    "http://localhost:5001",  # VamPI
]


async def validate_payload(
    payload_data: dict,
    targets: list[str] | None = None,
) -> dict[str, Any]:
    """Test a single payload against benchmark targets.

    Args:
        payload_data: {"technique", "payload", "detect", "affected_tech"}
        targets: list of target URLs (defaults to benchmark targets)

    Returns:
        {
            "valid": bool,  # at least one target triggered a detect signature
            "results": [{"target", "status", "matched", "detect_hit"}, ...],
        }
    """
    from vxis.interaction.hands import SessionManager

    if targets is None:
        targets = DEFAULT_TARGETS

    technique = payload_data.get("technique", "")
    payload = payload_data.get("payload", "")
    detect = payload_data.get("detect", [])
    if isinstance(detect, str):
        detect = [detect]

    if not payload:
        return {"valid": False, "results": [], "reason": "empty payload"}

    results: list[dict] = []

    for target in targets:
        _mgr = SessionManager()
        try:
            _session = await _mgr.get_session(target)
            # Choose injection point based on technique
            if technique in ("sqli", "sql_injection", "nosql", "xss", "ssti", "cmdi"):
                test_url = f"{target}/search?q={payload}"
            elif technique in ("ssrf",):
                test_url = f"{target}/redirect?to={payload}"
            elif technique in ("path_traversal",):
                test_url = f"{target}/{payload}"
            else:
                test_url = f"{target}/?input={payload}"

            r = await _session.request("GET", test_url)
            body = r.text.lower()
            status = r.status

            # Check detect signatures
            matched = []
            for sig in detect:
                if isinstance(sig, str) and sig.lower() in body:
                    matched.append(sig)

            # Also check for generic error indicators
            error_indicators = status == 500 or "error" in body[:200].lower()

            results.append(
                {
                    "target": target,
                    "url": test_url[:100],
                    "status": status,
                    "size": r.body_length,
                    "matched_signatures": matched,
                    "error_triggered": error_indicators,
                }
            )

        except Exception as e:
            results.append(
                {
                    "target": target,
                    "url": target,
                    "status": -1,
                    "error": str(e)[:100],
                }
            )
        finally:
            try:
                await _mgr.close_all()
            except Exception:
                pass

    # Valid if any target had a signature match or error trigger
    valid = any(r.get("matched_signatures") or r.get("error_triggered") for r in results)

    return {"valid": valid, "results": results, "payload": payload[:60], "technique": technique}


async def validate_batch(
    proposals: list[dict],
    targets: list[str] | None = None,
) -> dict[str, Any]:
    """Validate multiple payload proposals. Returns per-payload results.

    Used for:
    1. Pre-apply validation: reject obviously broken payloads
    2. Regression isolation: find which specific payload caused issues
    """
    results: list[dict] = []
    valid_count = 0

    for p in proposals:
        cd = p.get("change_data", {})
        if not isinstance(cd, dict) or not cd.get("payload"):
            continue
        r = await validate_payload(cd, targets)
        r["proposal_id"] = p.get("proposal_id", "?")
        results.append(r)
        if r["valid"]:
            valid_count += 1

    return {
        "total": len(results),
        "valid": valid_count,
        "invalid": len(results) - valid_count,
        "results": results,
    }


async def isolate_regression(
    targets: list[str] | None = None,
) -> list[str]:
    """Find which auto-added payloads cause issues on benchmark targets.

    Reads applied/ proposals, tests each payload individually,
    returns proposal_ids that should be rolled back.

    This replaces the "rollback everything" approach with targeted removal.
    """
    applied_dir = Path(".vxis/signals/applied")
    if not applied_dir.exists():
        return []

    # Load skill_payload_add proposals
    skill_proposals = []
    for f in applied_dir.glob("*.json"):
        try:
            d = json.loads(f.read_text())
            if d.get("change_type") == "skill_payload_add":
                skill_proposals.append(d)
        except Exception:
            pass

    if not skill_proposals:
        return []

    # Test each payload
    batch_result = await validate_batch(skill_proposals, targets)

    # Proposals that triggered errors on ALL targets = likely problematic
    bad_proposals = []
    for r in batch_result["results"]:
        if not r["valid"]:
            # Payload didn't work on any target — not necessarily bad,
            # but if it's causing scan errors, flag it
            all_errors = all(res.get("status") in (-1, 500) for res in r.get("results", []))
            if all_errors:
                bad_proposals.append(r["proposal_id"])
                logger.info("Regression candidate: %s (%s)", r["proposal_id"], r["payload"])

    return bad_proposals
