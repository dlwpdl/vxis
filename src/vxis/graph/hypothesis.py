from __future__ import annotations
import heapq
import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
from ..evidence.schema import Evidence, EvidenceType


class HypothesisStatus(str, Enum):
    PENDING = "pending"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


@dataclass
class Hypothesis:
    title: str
    rationale: str
    probability: float
    impact: float
    suggested_agent: str
    suggested_tool: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: HypothesisStatus = HypothesisStatus.PENDING
    note: str = ""

    @property
    def priority_score(self) -> float:
        return self.probability * self.impact

    def accept(self, note: str = "") -> None:
        self.status = HypothesisStatus.CONFIRMED
        self.note = note

    def reject(self, note: str = "") -> None:
        self.status = HypothesisStatus.REJECTED
        self.note = note

    def __lt__(self, other: "Hypothesis") -> bool:
        return self.priority_score > other.priority_score


class HypothesisQueue:
    def __init__(self) -> None:
        self._heap: list[Hypothesis] = []
        self._seen: set[str] = set()

    def push(self, h: Hypothesis) -> None:
        if h.title not in self._seen:
            self._seen.add(h.title)
            heapq.heappush(self._heap, h)

    def pop(self) -> Optional[Hypothesis]:
        while self._heap:
            h = heapq.heappop(self._heap)
            if h.status == HypothesisStatus.PENDING:
                h.status = HypothesisStatus.TESTING
                return h
        return None

    def size(self) -> int:
        return sum(1 for h in self._heap if h.status == HypothesisStatus.PENDING)


_FINDING_HYPOTHESIS_MAP: dict[str, list[dict[str, object]]] = {
    "s3": [
        {
            "title": "Secrets in S3 bucket",
            "agent": "secrets_lifecycle",
            "probability": 0.85,
            "impact": 0.95,
        },
        {
            "title": "S3 used in CI/CD pipeline",
            "agent": "supply_chain",
            "probability": 0.6,
            "impact": 0.7,
        },
    ],
    "graphql": [
        {
            "title": "GraphQL allows unauthorized queries",
            "agent": "api",
            "probability": 0.8,
            "impact": 0.85,
        },
    ],
    "credential": [
        {
            "title": "Credential reuse on other services",
            "agent": "identity_ad",
            "probability": 0.7,
            "impact": 0.9,
        },
        {
            "title": "DB direct access via leaked creds",
            "agent": "database",
            "probability": 0.8,
            "impact": 0.95,
        },
    ],
    "jwt": [
        {
            "title": "JWT algorithm confusion attack",
            "agent": "crypto_tls",
            "probability": 0.65,
            "impact": 0.9,
        },
    ],
}


class HypothesisGenerator:
    @classmethod
    def from_finding(cls, evidence: Evidence) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []
        title_lower = evidence.title.lower()
        desc_lower = evidence.description.lower()

        for keyword, templates in _FINDING_HYPOTHESIS_MAP.items():
            if keyword in title_lower or keyword in desc_lower:
                for t in templates:
                    hypotheses.append(
                        Hypothesis(
                            title=str(t["title"]),
                            rationale=f"Derived from: {evidence.title}",
                            probability=float(t["probability"]),  # type: ignore[arg-type]
                            impact=float(t["impact"]),  # type: ignore[arg-type]
                            suggested_agent=str(t["agent"]),
                        )
                    )
        return hypotheses
