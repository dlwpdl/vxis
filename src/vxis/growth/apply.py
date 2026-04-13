"""Apply proposals (dry-run default)|||제안 적용 (기본 dry-run)."""

from __future__ import annotations

import dataclasses as dc
import json
from datetime import datetime, timezone
from pathlib import Path

from vxis.growth.changelog import ChangeLog
from vxis.growth.classifier import classify_proposal, should_auto_apply
from vxis.growth.config import load_bootstrap_config
from vxis.growth.schemas import NewsIntelligence, Proposal

PROPOSALS_DIR = Path(".vxis/signals/proposals")
APPLIED_DIR = Path(".vxis/signals/applied")
PENDING_DIR = Path(".vxis/signals/pending")


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
                rationale_en=(
                    f"New vector from {intel.source_name}: "
                    f"{v.get('name_en', '')}"
                ),
                rationale_ko=(
                    f"{intel.source_name}에서 도출된 새 벡터: "
                    f"{v.get('name_ko', '')}"
                ),
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
                target_file=(
                    f"src/vxis/phases/guides/{phase_id.lower()}.py"
                ),
                change_data=pu,
                confidence=intel.trust_score * 0.85,
                risk="low",
                rationale_en=f"Phase update from {intel.source_name}",
                rationale_ko=(
                    f"{intel.source_name}에서 도출된 Phase 업데이트"
                ),
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
                rationale_ko=(
                    f"{intel.source_name}에서 도출된 KB 패턴"
                ),
                source_url=intel.article_url,
            )
        )

    # Skill payload proposals — map KB patterns to skill files
    for i, kb in enumerate(intel.proposed_kb_patterns):
        technique = kb.get("technique", "").lower()
        payload = kb.get("payload", "")
        if not payload:
            continue

        skill_map = {
            "sqli": "src/vxis/agent/skills/test_injection.py",
            "sql_injection": "src/vxis/agent/skills/test_injection.py",
            "xss": "src/vxis/agent/skills/test_injection.py",
            "rce": "src/vxis/agent/skills/test_injection.py",
            "ssrf": "src/vxis/agent/skills/test_injection.py",
            "path_traversal": "src/vxis/agent/skills/test_sensitive_files.py",
            "auth_bypass": "src/vxis/agent/skills/attempt_auth.py",
            "idor": "src/vxis/agent/skills/test_idor.py",
        }
        target_file = skill_map.get(technique, "")
        if target_file:
            proposals.append(
                Proposal(
                    proposal_id=f"{intel.signal_id}-skill-{i}",
                    source_signal_id=intel.signal_id,
                    change_type="skill_payload_add",
                    target_file=target_file,
                    change_data=kb,
                    confidence=intel.trust_score * 0.8,
                    risk="low",
                    rationale_en=(
                        f"New {technique} payload from "
                        f"{intel.source_name}: {payload[:60]}"
                    ),
                    rationale_ko=(
                        f"{intel.source_name}에서 새 {technique} "
                        f"페이로드: {payload[:60]}"
                    ),
                    source_url=intel.article_url,
                )
            )

    return [classify_proposal(p) for p in proposals]


_AUTO_MARKER = "# --- AUTO-UPDATED"


def _apply_skill_payload(proposal: Proposal) -> bool:
    """Actually insert a payload into a skill Python file.

    Finds the AUTO-UPDATED marker line and inserts the new payload
    entry just before it. Returns True if successful.
    """
    import re

    target = Path(proposal.target_file)
    if not target.exists():
        return False

    data = proposal.change_data
    if not isinstance(data, dict):
        return False

    payload = data.get("payload", "")
    technique = data.get("technique", "").lower()
    if not payload:
        return False

    content = target.read_text(encoding="utf-8")
    if _AUTO_MARKER not in content:
        return False

    # Build the new entry based on file type
    if "test_injection" in str(target):
        # PAYLOADS list format: {"type": "...", "payload": "...", "detect": [...]}
        detect = data.get("detect", [])
        if not detect:
            detect = ["sql"] if "sql" in technique else []
        escaped = payload.replace("\\", "\\\\").replace('"', '\\"')
        new_line = f'    {{"type": "{technique}", "payload": "{escaped}", "detect": {detect}}},  # auto-added'
    elif "test_sensitive_files" in str(target):
        # SENSITIVE_PATHS format: ("path", "severity", "description")
        severity = data.get("severity", "medium")
        desc = data.get("description", f"Auto-added {technique} path")[:60]
        new_line = f'    ("{payload}", "{severity}", "{desc}"),  # auto-added'
    elif "attempt_auth" in str(target):
        # SQLI_CREDS format: ("email_payload", "password")
        pwd = data.get("password", "x")
        escaped = payload.replace("\\", "\\\\").replace('"', '\\"')
        new_line = f'    ("{escaped}", "{pwd}"),  # auto-added'
    else:
        return False

    # Check for duplicates
    if payload in content:
        return False  # already exists

    # Insert before the marker line
    lines = content.split("\n")
    for i, line in enumerate(lines):
        if _AUTO_MARKER in line:
            lines.insert(i, new_line)
            break
    else:
        return False

    target.write_text("\n".join(lines), encoding="utf-8")
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
                    log.record("skill_payload_applied", {
                        "proposal_id": proposal.proposal_id,
                        "target_file": proposal.target_file,
                        "payload": str(proposal.change_data.get("payload", ""))[:60],
                    })

            save_proposal(proposal, APPLIED_DIR)
            proposal.status = "auto_applied"
            proposal.applied_at = datetime.now(timezone.utc).isoformat()
            log.record("proposal_auto_applied", {
                "proposal_id": proposal.proposal_id,
                "change_type": proposal.change_type,
                "confidence": proposal.confidence,
                "tier": "high",
            })
            results["auto_applied"] += 1

        elif proposal.confidence >= pr_threshold:
            # 🟡 MEDIUM confidence: pending for PR review
            save_proposal(proposal, PENDING_DIR)
            proposal.status = "pending_review"
            log.record("proposal_pending_review", {
                "proposal_id": proposal.proposal_id,
                "change_type": proposal.change_type,
                "confidence": proposal.confidence,
                "tier": "medium",
            })
            results["pending_review"] += 1

        else:
            # 🔴 LOW confidence: discard
            log.record("proposal_discarded", {
                "proposal_id": proposal.proposal_id,
                "confidence": proposal.confidence,
                "tier": "low",
            })
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
