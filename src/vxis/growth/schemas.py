"""Growth Layer dataclasses|||Growth Layer 데이터 클래스."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

RiskLevel = Literal["low", "medium", "high", "critical"]
ChangeType = Literal[
    "vector_add",
    "guide_advice_append",
    "kb_pattern_add",
    "wordlist_expand",
    "waf_variant_add",
    "actor_profile_update",
    "phase_reorder",
    "scope_change",
    "new_phase",
]


@dataclass
class SignalSource:
    """Signal source metadata|||시그널 출처 메타데이터."""

    name: str
    url: str
    source_type: str  # "rss", "api", "crawler"
    trust_score: float  # 0.0 - 1.0


@dataclass
class RawSignal:
    """Raw collected signal before LLM analysis|||LLM 분석 이전 원시 시그널."""

    signal_id: str  # SHA256-derived short hash
    source: SignalSource
    timestamp: str  # ISO 8601
    title: str
    body: str
    url: str
    metadata: dict = field(default_factory=dict)


@dataclass
class NewsIntelligence:
    """Structured intelligence from LLM extraction|||LLM 추출 결과 구조화 인텔리전스."""

    signal_id: str
    source_name: str
    article_url: str
    article_title: str
    pub_date: str
    trust_score: float

    # Factual extraction (regex)
    cves: list[str] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)

    # LLM extraction
    threat_actors: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    ttps: list[dict] = field(default_factory=list)
    attack_chain: list[str] = field(default_factory=list)
    target_industries: list[str] = field(default_factory=list)
    target_technologies: list[str] = field(default_factory=list)

    # Proposed upgrades
    proposed_vectors: list[dict] = field(default_factory=list)
    proposed_phase_updates: list[dict] = field(default_factory=list)
    proposed_kb_patterns: list[dict] = field(default_factory=list)
    proposed_waf_variants: list[dict] = field(default_factory=list)
    proposed_actor_updates: list[dict] = field(default_factory=list)

    extracted_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class Proposal:
    """Individual upgrade proposal|||개별 업그레이드 제안."""

    proposal_id: str
    source_signal_id: str
    change_type: ChangeType
    target_file: str
    change_data: dict

    confidence: float  # 0.0 - 1.0
    risk: RiskLevel
    rationale_en: str
    rationale_ko: str
    source_url: str

    status: str = "pending"
    applied_at: str = ""
    rolled_back_at: str = ""
    effectiveness_score: float = 0.0


@dataclass
class AppliedChange:
    """Auto-applied change record (rollback-capable)|||자동 적용 변경 기록."""

    proposal_id: str
    applied_at: str
    reverse_diff: str
    files_modified: list[str]
    git_commit_sha: str = ""


@dataclass
class BudgetState:
    """Monthly LLM budget tracking|||월별 LLM 예산 추적."""

    month: str  # "YYYY-MM"
    llm_calls_used: int = 0
    llm_tokens_used: int = 0
    estimated_cost_usd: float = 0.0
    cap_usd: float = 15.0
    tier_usage: dict[str, int] = field(default_factory=dict)
