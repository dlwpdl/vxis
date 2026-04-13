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
    """Apply proposals under bootstrap rules|||Bootstrap 규칙에 따라 제안 적용.

    Dry-run: everything lands in pending/.
    Active: low-risk + high-confidence → applied/, else pending/.
    Even 'auto_applied' only means recorded — bootstrap never mutates code.
    """
    config = load_bootstrap_config()
    log = ChangeLog()

    results = {
        "total": len(proposals),
        "auto_applied": 0,
        "pending_review": 0,
        "dry_run": bool(config["apply"]["dry_run"]),
    }

    for proposal in proposals:
        if should_auto_apply(proposal, config):
            save_proposal(proposal, APPLIED_DIR)
            proposal.status = "auto_applied"
            proposal.applied_at = datetime.now(timezone.utc).isoformat()
            log.record(
                "proposal_auto_applied",
                {
                    "proposal_id": proposal.proposal_id,
                    "change_type": proposal.change_type,
                    "confidence": proposal.confidence,
                },
            )
            results["auto_applied"] += 1
        else:
            save_proposal(proposal, PENDING_DIR)
            log.record(
                "proposal_pending",
                {
                    "proposal_id": proposal.proposal_id,
                    "change_type": proposal.change_type,
                    "risk": proposal.risk,
                    "reason": (
                        "dry_run"
                        if config["apply"]["dry_run"]
                        else "manual_review"
                    ),
                },
            )
            results["pending_review"] += 1

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
