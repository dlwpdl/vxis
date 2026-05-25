"""Apply proposals (dry-run default)|||제안 적용 (기본 dry-run)."""

from __future__ import annotations

import dataclasses as dc
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from vxis.growth.changelog import ChangeLog
from vxis.growth.classifier import classify_proposal, should_auto_apply
from vxis.growth.config import load_bootstrap_config
from vxis.growth.schemas import NewsIntelligence, Proposal

logger = logging.getLogger(__name__)

PROPOSALS_DIR = Path(".vxis/signals/proposals")
APPLIED_DIR = Path(".vxis/signals/applied")
PENDING_DIR = Path(".vxis/signals/pending")
REJECTED_DIR = Path(".vxis/signals/rejected")
TEST_PENDING_DIR = Path(".vxis/signals/test-pending")


def generate_proposals(intel: NewsIntelligence) -> list[Proposal]:
    """Turn NewsIntelligence into Proposals|||인텔리전스를 제안으로 변환."""
    proposals: list[Proposal] = []

    for i, v in enumerate(intel.proposed_vectors):
        proposals.append(
            Proposal(
                proposal_id=f"{intel.signal_id}-vec-{i}",
                source_signal_id=intel.signal_id,
                change_type="vector_add",
                target_file="src/vxis/scoring/vectors.py",
                change_data=v,
                confidence=intel.trust_score * 0.9,
                risk="low",
                rationale_en=(f"New vector from {intel.source_name}: {v.get('name_en', '')}"),
                rationale_ko=(f"{intel.source_name}에서 도출된 새 벡터: {v.get('name_ko', '')}"),
                source_url=intel.article_url,
            )
        )

    for i, pu in enumerate(intel.proposed_phase_updates):
        phase_id = pu.get("phase_id", "unknown")
        proposals.append(
            Proposal(
                proposal_id=f"{intel.signal_id}-phase-{i}",
                source_signal_id=intel.signal_id,
                change_type="guide_advice_append",
                target_file=(f"src/vxis/phases/guides/{phase_id.lower()}.py"),
                change_data=pu,
                confidence=intel.trust_score * 0.85,
                risk="low",
                rationale_en=f"Phase update from {intel.source_name}",
                rationale_ko=(f"{intel.source_name}에서 도출된 Phase 업데이트"),
                source_url=intel.article_url,
            )
        )

    for i, kp in enumerate(intel.proposed_kb_patterns):
        proposals.append(
            Proposal(
                proposal_id=f"{intel.signal_id}-kb-{i}",
                source_signal_id=intel.signal_id,
                change_type="kb_pattern_add",
                target_file="~/.vxis/knowledge_store.json",
                change_data=kp,
                confidence=intel.trust_score * 0.8,
                risk="low",
                rationale_en=f"KB pattern from {intel.source_name}",
                rationale_ko=(f"{intel.source_name}에서 도출된 KB 패턴"),
                source_url=intel.article_url,
            )
        )

    # Skill payload proposals — map KB patterns to JSON data files (ADR-007 Phase 10).
    for i, kb in enumerate(intel.proposed_kb_patterns):
        technique = kb.get("technique", "").lower()
        payload = kb.get("payload", "")
        if not payload:
            continue

        mapping = _TECHNIQUE_TARGETS.get(technique)
        if mapping is None:
            continue  # technique not mappable to a data file → skip
        json_basename, _mode, _arg = mapping
        target_file = f"src/vxis/data/payloads/{json_basename}.json"
        proposals.append(
            Proposal(
                proposal_id=f"{intel.signal_id}-skill-{i}",
                source_signal_id=intel.signal_id,
                change_type="skill_payload_add",
                target_file=target_file,
                change_data=kb,
                confidence=intel.trust_score * 0.8,
                risk="low",
                rationale_en=(f"New {technique} payload from {intel.source_name}: {payload[:60]}"),
                rationale_ko=(f"{intel.source_name}에서 새 {technique} 페이로드: {payload[:60]}"),
                source_url=intel.article_url,
            )
        )

    return [classify_proposal(p) for p in proposals]


_PAYLOAD_DATA_ROOT = Path("src/vxis/data/payloads")

# ADR-007 Phase 10 — technique → (json_basename, insert_mode, mode_arg).
#
# Modes map to the two JSON schemas the loader understands
# (see src/vxis/agent/skills/_payload_loader.py):
#   "round"          → append dict {type,payload,detect} to rounds[arg]
#   "dataset"        → append string to datasets[arg]
#   "dataset_triple" → append [path, severity, desc] to datasets[arg]
#   "dataset_tuple"  → append [user, pwd] to datasets[arg]
#
# Unknown techniques are dropped in generate_proposals — silent skip is
# correct because the growth loop shouldn't PR into files it can't
# schema-validate.
_TECHNIQUE_TARGETS: dict[str, tuple[str, str, str]] = {
    "sqli": ("injection", "round", "3"),
    "sql_injection": ("injection", "round", "3"),
    "xss": ("xss", "round", "3"),
    "rce": ("injection", "round", "3"),
    "ssrf": ("test_ssrf", "dataset", "ssrf_payloads"),
    "ssti": ("injection", "round", "3"),
    "cmdi": ("injection", "round", "3"),
    "nosql": ("injection", "round", "3"),
    "xxe": ("injection", "round", "3"),
    "path_traversal": ("test_sensitive_files", "dataset_triple", "sensitive_paths"),
    "auth_bypass": ("attempt_auth", "dataset_tuple", "default_creds"),
    "jwt": ("attempt_auth", "dataset_tuple", "default_creds"),
    "csrf": ("injection", "round", "3"),
}


def _apply_skill_payload(proposal: Proposal) -> bool:
    """Append a new payload/dataset entry to the skill's JSON data file.

    ADR-007 Phase 10: the skill `.py` files are frozen — growth loop
    writes only to `src/vxis/data/payloads/<skill>.json` and the pydantic
    schema (`_PayloadFile`) is the final gate before a write.

    Returns True if an entry was actually appended.
    """
    data = proposal.change_data
    if not isinstance(data, dict):
        return False

    payload = data.get("payload", "")
    technique = data.get("technique", "").lower()
    if not payload:
        return False

    mapping = _TECHNIQUE_TARGETS.get(technique)
    if mapping is None:
        return False
    json_basename, mode, mode_arg = mapping

    target = _PAYLOAD_DATA_ROOT / f"{json_basename}.json"
    if not target.exists():
        return False

    # Sanitize the raw payload — same rules as the legacy .py inserter
    # used, so regression isolation across the two paths is comparable.
    payload = payload.replace("\n", " ").replace("\r", "").strip()
    if len(payload) > 200:
        payload = payload[:200]

    try:
        content = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False

    if mode == "round":
        detect = data.get("detect", [])
        if not detect:
            detect = ["sql"] if "sql" in technique else []
        if isinstance(detect, list):
            detect = [str(d)[:60] for d in detect[:5]]
        entry = {"type": technique, "payload": payload, "detect": detect}
        bucket = content.setdefault("rounds", {}).setdefault(mode_arg, [])
        if any(isinstance(p, dict) and p.get("payload") == payload for p in bucket):
            return False
        bucket.append(entry)

    elif mode == "dataset":
        bucket = content.setdefault("datasets", {}).setdefault(mode_arg, [])
        if payload in bucket:
            return False
        bucket.append(payload)

    elif mode == "dataset_triple":
        severity = str(data.get("severity", "medium")).lower()
        desc = str(data.get("description", f"Auto-added {technique} path"))[:60]
        entry = [payload, severity, desc]
        bucket = content.setdefault("datasets", {}).setdefault(mode_arg, [])
        if any(isinstance(x, list) and x and x[0] == payload for x in bucket):
            return False
        bucket.append(entry)

    elif mode == "dataset_tuple":
        pwd = str(data.get("password", "x"))
        entry = [payload, pwd]
        bucket = content.setdefault("datasets", {}).setdefault(mode_arg, [])
        if any(isinstance(x, list) and list(x) == entry for x in bucket):
            return False
        bucket.append(entry)

    else:
        return False

    # Schema validate before writing — fail-closed.
    try:
        from vxis.agent.skills._payload_loader import (
            _PayloadFile,
            clear_cache,
        )

        _PayloadFile.model_validate(content)
    except Exception as e:
        logger.warning("Growth payload injection fails schema for %s: %s", target, e)
        return False

    target.write_text(
        json.dumps(content, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    clear_cache()  # next skill load reads the appended entry
    return True


def save_proposal(proposal: Proposal, directory: Path) -> Path:
    """Persist proposal as JSON|||제안 JSON 저장."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{proposal.proposal_id}.json"
    path.write_text(
        json.dumps(dc.asdict(proposal), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


def _load_pending_proposal_records() -> list[tuple[Path, dict]]:
    records: list[tuple[Path, dict]] = []
    if not PENDING_DIR.exists():
        return records
    for path in sorted(PENDING_DIR.glob("*.json")):
        try:
            records.append((path, json.loads(path.read_text(encoding="utf-8"))))
        except Exception:
            continue
    return records


def _proposal_is_test_artifact(proposal: Proposal | dict) -> bool:
    source_signal_id = (
        str(
            proposal.source_signal_id
            if isinstance(proposal, Proposal)
            else proposal.get("source_signal_id", "")
        )
        .strip()
        .lower()
    )
    proposal_id = (
        str(
            proposal.proposal_id
            if isinstance(proposal, Proposal)
            else proposal.get("proposal_id", "")
        )
        .strip()
        .lower()
    )
    return source_signal_id.startswith("test-") or proposal_id.startswith("test-")


def _proposal_meets_pending_threshold(
    proposal: Proposal | dict, config: dict | None = None
) -> bool:
    cfg = config or load_bootstrap_config()
    confidence = float(
        proposal.confidence if isinstance(proposal, Proposal) else proposal.get("confidence", 0.0)
    )
    return confidence >= float(cfg["apply"].get("pr_review_threshold", 0.7))


def list_reviewable_pending_proposals(config: dict | None = None) -> list[dict]:
    cfg = config or load_bootstrap_config()
    reviewable: list[dict] = []
    for _path, data in _load_pending_proposal_records():
        if _proposal_is_test_artifact(data):
            continue
        if not _proposal_meets_pending_threshold(data, cfg):
            continue
        reviewable.append(data)
    return reviewable


def count_reviewable_pending_proposals(config: dict | None = None) -> int:
    return len(list_reviewable_pending_proposals(config))


def prune_pending_proposals(config: dict | None = None) -> dict[str, int]:
    cfg = config or load_bootstrap_config()
    moved_test = 0
    moved_rejected = 0
    TEST_PENDING_DIR.mkdir(parents=True, exist_ok=True)
    REJECTED_DIR.mkdir(parents=True, exist_ok=True)
    for path, data in _load_pending_proposal_records():
        if _proposal_is_test_artifact(data):
            path.replace(TEST_PENDING_DIR / path.name)
            moved_test += 1
            continue
        if not _proposal_meets_pending_threshold(data, cfg):
            data["status"] = "rejected"
            data["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
            target = REJECTED_DIR / path.name
            target.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            path.unlink(missing_ok=True)
            moved_rejected += 1
    return {
        "moved_test_artifacts": moved_test,
        "moved_rejected": moved_rejected,
        "pending_reviewable": count_reviewable_pending_proposals(cfg),
    }


def apply_proposals(proposals: list[Proposal]) -> dict:
    """Apply proposals with confidence-tiered strategy.

    🟢 HIGH (≥ auto_apply_threshold): auto-apply + daily digest
    🟡 MEDIUM (≥ pr_review_threshold): save to pending/ for PR review
    🔴 LOW (< pr_review_threshold): discard silently

    Dry-run mode: everything goes to pending/ regardless of confidence.
    """
    config = load_bootstrap_config()
    log = ChangeLog()
    is_dry_run = bool(config["apply"]["dry_run"])
    auto_threshold = float(config["apply"].get("auto_apply_threshold", 0.9))
    pr_threshold = float(config["apply"].get("pr_review_threshold", 0.7))

    results = {
        "total": len(proposals),
        "auto_applied": 0,
        "pending_review": 0,
        "discarded": 0,
        "skill_files_modified": 0,
        "dry_run": is_dry_run,
    }

    for proposal in proposals:
        if is_dry_run:
            # Dry-run: everything to pending
            save_proposal(proposal, PENDING_DIR)
            results["pending_review"] += 1
            continue

        if proposal.confidence >= auto_threshold and should_auto_apply(proposal, config):
            # 🟢 HIGH confidence: auto-apply
            if proposal.change_type == "skill_payload_add":
                applied = _apply_skill_payload(proposal)
                if applied:
                    results["skill_files_modified"] += 1
                    log.record(
                        "skill_payload_applied",
                        {
                            "proposal_id": proposal.proposal_id,
                            "target_file": proposal.target_file,
                            "payload": str(proposal.change_data.get("payload", ""))[:60],
                        },
                    )

            save_proposal(proposal, APPLIED_DIR)
            proposal.status = "auto_applied"
            proposal.applied_at = datetime.now(timezone.utc).isoformat()
            log.record(
                "proposal_auto_applied",
                {
                    "proposal_id": proposal.proposal_id,
                    "change_type": proposal.change_type,
                    "confidence": proposal.confidence,
                    "tier": "high",
                },
            )
            results["auto_applied"] += 1

        elif proposal.confidence >= pr_threshold:
            # 🟡 MEDIUM confidence: pending for PR review
            save_proposal(proposal, PENDING_DIR)
            proposal.status = "pending_review"
            log.record(
                "proposal_pending_review",
                {
                    "proposal_id": proposal.proposal_id,
                    "change_type": proposal.change_type,
                    "confidence": proposal.confidence,
                    "tier": "medium",
                },
            )
            results["pending_review"] += 1

        else:
            # 🔴 LOW confidence: discard
            log.record(
                "proposal_discarded",
                {
                    "proposal_id": proposal.proposal_id,
                    "confidence": proposal.confidence,
                    "tier": "low",
                },
            )
            results["discarded"] += 1

    return results


def process_signal_to_proposals(signal_id: str) -> dict:
    """Load cached intel → generate → apply|||캐시된 인텔로 제안 생성/적용."""
    from vxis.growth.cache import ExtractionCache

    cache = ExtractionCache()
    cached = cache.get(signal_id)
    if not cached:
        return {"total": 0, "auto_applied": 0, "pending_review": 0}
    try:
        intel = NewsIntelligence(**cached)
    except TypeError:
        return {"total": 0, "auto_applied": 0, "pending_review": 0}
    proposals = generate_proposals(intel)
    return apply_proposals(proposals)
