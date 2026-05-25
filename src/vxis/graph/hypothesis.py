from __future__ import annotations
import heapq
import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
from ..evidence.schema import Evidence


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
    # --- Cloud / Infrastructure ---
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
    "aws": [
        {
            "title": "AWS IAM privilege escalation",
            "agent": "cloud",
            "probability": 0.7,
            "impact": 0.95,
        },
        {
            "title": "Lateral movement via AWS role chaining",
            "agent": "lateral_move",
            "probability": 0.6,
            "impact": 0.9,
        },
    ],
    "lambda": [
        {
            "title": "Lambda function code injection",
            "agent": "cloud",
            "probability": 0.5,
            "impact": 0.85,
        },
    ],
    "docker": [
        {
            "title": "Container escape via Docker misconfiguration",
            "agent": "container_k8s",
            "probability": 0.7,
            "impact": 1.0,
        },
    ],
    "kubernetes": [
        {
            "title": "K8s RBAC privilege escalation",
            "agent": "container_k8s",
            "probability": 0.65,
            "impact": 0.95,
        },
    ],
    # --- API / Web ---
    "graphql": [
        {
            "title": "GraphQL allows unauthorized queries",
            "agent": "api",
            "probability": 0.8,
            "impact": 0.85,
        },
        {
            "title": "GraphQL depth-based DoS",
            "agent": "dos_resilience",
            "probability": 0.6,
            "impact": 0.7,
        },
    ],
    "swagger": [
        {
            "title": "API schema exposure enables targeted attacks",
            "agent": "api",
            "probability": 0.75,
            "impact": 0.8,
        },
    ],
    "websocket": [
        {
            "title": "WebSocket injection / hijacking",
            "agent": "api",
            "probability": 0.6,
            "impact": 0.8,
        },
    ],
    "wordpress": [
        {
            "title": "WordPress plugin vulnerabilities",
            "agent": "cms_biz_platform",
            "probability": 0.8,
            "impact": 0.8,
        },
    ],
    # --- Identity / Credentials ---
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
        {
            "title": "Lateral movement via credential reuse",
            "agent": "lateral_move",
            "probability": 0.75,
            "impact": 0.9,
        },
    ],
    "kerberos": [
        {
            "title": "Kerberoasting / AS-REP roasting",
            "agent": "identity_ad",
            "probability": 0.75,
            "impact": 0.9,
        },
    ],
    "ntlm": [
        {"title": "NTLM relay attack", "agent": "identity_ad", "probability": 0.7, "impact": 0.85},
    ],
    "jwt": [
        {
            "title": "JWT algorithm confusion attack",
            "agent": "crypto_tls",
            "probability": 0.65,
            "impact": 0.9,
        },
    ],
    # --- Exploitation ---
    "rce": [
        {
            "title": "OS access via remote code execution",
            "agent": "os_host",
            "probability": 0.9,
            "impact": 1.0,
        },
        {
            "title": "Lateral movement after RCE",
            "agent": "lateral_move",
            "probability": 0.8,
            "impact": 0.95,
        },
    ],
    "sqli": [
        {
            "title": "Database exfiltration via SQL injection",
            "agent": "database",
            "probability": 0.85,
            "impact": 0.95,
        },
    ],
    "ssrf": [
        {
            "title": "Cloud metadata access via SSRF",
            "agent": "cloud",
            "probability": 0.7,
            "impact": 0.9,
        },
        {
            "title": "Internal service discovery via SSRF",
            "agent": "network",
            "probability": 0.6,
            "impact": 0.8,
        },
    ],
    "deserialization": [
        {"title": "RCE via deserialization", "agent": "os_host", "probability": 0.8, "impact": 1.0},
    ],
    "smuggling": [
        {
            "title": "Cache poisoning via request smuggling",
            "agent": "http_protocol",
            "probability": 0.7,
            "impact": 0.9,
        },
        {
            "title": "Credential theft via smuggling + CORS",
            "agent": "web",
            "probability": 0.6,
            "impact": 0.85,
        },
    ],
    # --- Network / Infrastructure ---
    "subdomain": [
        {
            "title": "Subdomain takeover",
            "agent": "subdomain_takeover",
            "probability": 0.6,
            "impact": 0.8,
        },
    ],
    "dns": [
        {
            "title": "DNS zone transfer / rebinding",
            "agent": "dns_deep",
            "probability": 0.5,
            "impact": 0.75,
        },
    ],
    "ssl": [
        {
            "title": "TLS/SSL protocol weakness",
            "agent": "crypto_tls",
            "probability": 0.7,
            "impact": 0.7,
        },
    ],
    "smb": [
        {
            "title": "SMB relay / share enumeration",
            "agent": "identity_ad",
            "probability": 0.7,
            "impact": 0.8,
        },
    ],
    "snmp": [
        {
            "title": "SNMP community string exploitation",
            "agent": "legacy_protocol",
            "probability": 0.75,
            "impact": 0.8,
        },
    ],
    "mongodb": [
        {
            "title": "MongoDB unauthenticated access",
            "agent": "database",
            "probability": 0.8,
            "impact": 0.9,
        },
    ],
    "redis": [
        {
            "title": "Redis unauthenticated command execution",
            "agent": "database",
            "probability": 0.8,
            "impact": 0.9,
        },
    ],
    # --- Secrets / Supply Chain ---
    "secret": [
        {
            "title": "Secrets in git history",
            "agent": "secrets_lifecycle",
            "probability": 0.85,
            "impact": 0.9,
        },
    ],
    "cicd": [
        {
            "title": "CI/CD pipeline compromise",
            "agent": "supply_chain",
            "probability": 0.65,
            "impact": 0.95,
        },
    ],
    # --- Physical / Advanced ---
    "wifi": [
        {
            "title": "WiFi rogue AP / credential harvest",
            "agent": "wireless",
            "probability": 0.5,
            "impact": 0.7,
        },
    ],
    "phishing": [
        {
            "title": "Spear-phishing via discovered info",
            "agent": "phishing_intel",
            "probability": 0.6,
            "impact": 0.8,
        },
    ],
    "llm": [
        {
            "title": "LLM prompt injection attack",
            "agent": "ai_llm",
            "probability": 0.7,
            "impact": 0.8,
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
