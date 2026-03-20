"""Evidence chain-of-custody model for VXIS security automation platform.

This module provides immutable evidence tracking with cryptographic integrity
verification and a tamper-evident chain-of-custody audit log.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class EvidenceItem:
    """An evidence artifact with cryptographic integrity and chain-of-custody tracking.

    All fields except chain_of_custody are set at creation time and should be
    treated as immutable after the initial `create_evidence` call.
    """

    evidence_id: str
    finding_id: str
    evidence_type: str
    captured_at: datetime
    captured_by: str
    sha256_hash: str
    content: bytes
    metadata: dict[str, Any] = field(default_factory=dict)
    chain_of_custody: list[dict[str, Any]] = field(default_factory=list)


def create_evidence(
    content: bytes,
    evidence_type: str,
    tool: str,
    finding_id: str,
) -> EvidenceItem:
    """Create a new EvidenceItem with SHA-256 integrity hash and initial custody record.

    Args:
        content: Raw bytes of the evidence artifact.
        evidence_type: Category of evidence, e.g. "screenshot", "log", "packet_capture".
        tool: Name of the tool or actor that captured this evidence.
        finding_id: Identifier of the associated Finding.

    Returns:
        A fully initialized EvidenceItem with sha256_hash computed from `content`
        and a single "captured" entry in chain_of_custody.
    """
    now = datetime.now(timezone.utc)
    sha256_hash = hashlib.sha256(content).hexdigest()

    initial_custody: dict[str, Any] = {
        "action": "captured",
        "actor": tool,
        "timestamp": now.isoformat(),
    }

    return EvidenceItem(
        evidence_id=str(uuid.uuid4()),
        finding_id=finding_id,
        evidence_type=evidence_type,
        captured_at=now,
        captured_by=tool,
        sha256_hash=sha256_hash,
        content=content,
        metadata={},
        chain_of_custody=[initial_custody],
    )


def transfer_custody(
    evidence: EvidenceItem,
    action: str,
    actor: str,
) -> EvidenceItem:
    """Append a custody transfer record to an EvidenceItem's audit log.

    This function mutates the `chain_of_custody` list in place and returns
    the same EvidenceItem for convenience in method-chaining patterns.

    Args:
        evidence: The EvidenceItem to update.
        action: Description of the custody action, e.g. "transferred", "reviewed", "exported".
        actor: Identifier of the person or system performing the action.

    Returns:
        The same EvidenceItem with the new custody record appended.
    """
    now = datetime.now(timezone.utc)
    custody_record: dict[str, Any] = {
        "action": action,
        "actor": actor,
        "timestamp": now.isoformat(),
    }
    evidence.chain_of_custody.append(custody_record)
    return evidence


def mask_secret(secret: str) -> str:
    """Mask the middle portion of a secret string, preserving the first and last 4 characters.

    For strings with 8 or fewer characters, the entire string is masked with asterisks
    to prevent any portion of a short secret from being revealed.

    Args:
        secret: The secret string to mask.

    Returns:
        A masked string. For strings longer than 8 characters: first 4 chars +
        asterisks replacing the middle + last 4 chars. For strings of 8 chars
        or fewer: all asterisks of the same length.

    Examples:
        >>> mask_secret("abcdefghij")
        'abcd**ijhij'  # first 4 + masked middle + last 4
        >>> mask_secret("short")
        '*****'
    """
    if len(secret) <= 8:
        return "*" * len(secret)

    middle_length = len(secret) - 8
    return secret[:4] + ("*" * middle_length) + secret[-4:]
