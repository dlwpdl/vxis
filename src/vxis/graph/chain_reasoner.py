"""VXIS Chain Reasoner — 공격 체인 추론 엔진.

개별 취약점이 아닌, 취약점들을 연결하여 공격 체인을 추론한다.

핵심 원칙:
    발견 1: 정보노출 (.env 파일) → info
    발견 2: SSRF 가능 → medium
    발견 3: 내부 Redis 인증 없음 → medium

    개별로 보면: medium 3개
    체인으로 보면: .env → 내부 IP → SSRF → Redis → 세션 탈취 = CRITICAL

Architecture:
    ┌─────────────────────────────────────────┐
    │  Chain Reasoner                          │
    ├─────────────────────────────────────────┤
    │  ChainTemplate    — 알려진 체인 패턴      │
    │  ChainCandidate   — 발견된 체인 후보      │
    │  ChainScorer      — 체인 심각도 평가      │
    │  ChainInference   — 새로운 체인 추론      │
    └─────────────────────────────────────────┘
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from vxis.evidence.schema import Evidence, Severity

logger = logging.getLogger(__name__)


# ── Data Models ──────────────────────────────────────────────────

@dataclass
class ChainLink:
    """공격 체인의 한 단계."""

    evidence_id: str  # 연결된 Evidence
    title: str
    severity: str
    role: str  # "entry", "pivot", "escalation", "impact"
    technique: str  # MITRE ATT&CK 기법 등


@dataclass
class AttackChain:
    """발견된 공격 체인."""

    id: str
    title: str
    links: list[ChainLink]
    overall_severity: str  # 체인 전체의 심각도
    impact_score: float  # 0.0~1.0
    confidence: float  # 0.0~1.0
    narrative: str  # 체인의 서술적 설명
    mitigations: list[str] = field(default_factory=list)

    @property
    def length(self) -> int:
        return len(self.links)


@dataclass
class ChainTemplate:
    """알려진 공격 체인 패턴 (매칭용)."""

    name: str
    pattern: list[str]  # 필요한 취약점 유형 시퀀스
    severity_upgrade: str  # 체인 달성 시 업그레이드 되는 심각도
    description: str
    impact: float


# ── Chain Templates (알려진 공격 체인 패턴) ───────────────────────

_CHAIN_TEMPLATES: list[ChainTemplate] = [
    # ── Web → 내부 접근 ──
    ChainTemplate(
        name="Info Disclosure → SSRF → Internal Access",
        pattern=["info_disclosure", "ssrf"],
        severity_upgrade="critical",
        description=".env/config 노출로 내부 IP 획득 → SSRF로 내부 서비스 접근",
        impact=0.95,
    ),
    ChainTemplate(
        name="SSRF → Cloud Metadata → Credential Theft",
        pattern=["ssrf", "cloud_metadata"],
        severity_upgrade="critical",
        description="SSRF로 AWS/GCP 메타데이터 접근 → IAM 자격증명 탈취",
        impact=1.0,
    ),
    ChainTemplate(
        name="SQLi → DB Access → Credential Dump",
        pattern=["sqli", "database"],
        severity_upgrade="critical",
        description="SQL 인젝션으로 DB 접근 → 사용자 자격증명 덤프",
        impact=0.95,
    ),
    ChainTemplate(
        name="XSS → Session Hijack → Admin Access",
        pattern=["xss", "session"],
        severity_upgrade="high",
        description="XSS로 관리자 세션 토큰 탈취 → 관리자 권한 획득",
        impact=0.85,
    ),
    ChainTemplate(
        name="Secret Leak → Service Access → Lateral Movement",
        pattern=["secret_exposure", "service_access"],
        severity_upgrade="critical",
        description="API 키/토큰 노출 → 외부 서비스 접근 → 횡적 이동",
        impact=0.9,
    ),
    # ── 인프라 체인 ──
    ChainTemplate(
        name="Open Port → Default Creds → RCE",
        pattern=["open_service", "default_credentials"],
        severity_upgrade="critical",
        description="노출된 서비스 → 기본 자격증명 → 원격 코드 실행",
        impact=1.0,
    ),
    ChainTemplate(
        name="Subdomain Takeover → Phishing → Credential Harvest",
        pattern=["subdomain_takeover", "domain_control"],
        severity_upgrade="high",
        description="서브도메인 탈취 → 피싱 페이지 → 자격증명 수집",
        impact=0.85,
    ),
    ChainTemplate(
        name="JWT Weakness → Auth Bypass → Privilege Escalation",
        pattern=["jwt_vulnerability", "auth_bypass"],
        severity_upgrade="critical",
        description="JWT 알고리즘 혼동 → 인증 우회 → 권한 상승",
        impact=0.95,
    ),
    # ── 클라우드 체인 ──
    ChainTemplate(
        name="S3 Misconfiguration → Data Exfiltration",
        pattern=["s3_public", "data_exposure"],
        severity_upgrade="critical",
        description="공개 S3 버킷 → 민감 데이터 유출",
        impact=0.9,
    ),
    ChainTemplate(
        name="Container Escape → Host Access → Cluster Takeover",
        pattern=["container_escape", "host_access"],
        severity_upgrade="critical",
        description="컨테이너 탈출 → 호스트 접근 → K8s 클러스터 장악",
        impact=1.0,
    ),
    # ── Redis/DB 체인 ──
    ChainTemplate(
        name="Redis No Auth → Session Theft → Admin Hijack",
        pattern=["redis_noauth", "session_data"],
        severity_upgrade="critical",
        description="Redis 인증 없음 → 세션 토큰 덤프 → 관리자 세션 하이재킹",
        impact=0.95,
    ),
    ChainTemplate(
        name="MongoDB No Auth → Data Dump → Credential Reuse",
        pattern=["mongodb_noauth", "credential_data"],
        severity_upgrade="critical",
        description="MongoDB 인증 없음 → 사용자 데이터 덤프 → 자격증명 재사용",
        impact=0.95,
    ),
    # ── Email 체인 ──
    ChainTemplate(
        name="No SPF/DMARC → Email Spoofing → Phishing",
        pattern=["email_misconfiguration", "spoofing"],
        severity_upgrade="high",
        description="이메일 인증 미설정 → 스푸핑 → 타겟 피싱 공격",
        impact=0.8,
    ),
    # ── 복합 체인 ──
    ChainTemplate(
        name="Info Disclosure → SSRF → Redis → Session Hijack",
        pattern=["info_disclosure", "ssrf", "redis_noauth"],
        severity_upgrade="critical",
        description="설정 파일 노출 → SSRF → 내부 Redis → 세션 탈취 (3단 체인)",
        impact=1.0,
    ),
    ChainTemplate(
        name="Deserialization → RCE → Lateral Movement",
        pattern=["deserialization", "rce"],
        severity_upgrade="critical",
        description="역직렬화 취약점 → 원격 코드 실행 → 내부 네트워크 횡적 이동",
        impact=1.0,
    ),
]

# ── 키워드 → 취약점 유형 매핑 ────────────────────────────────────

_KEYWORD_TO_VULN_TYPE: dict[str, list[str]] = {
    # Info Disclosure
    ".env": ["info_disclosure"],
    "config": ["info_disclosure"],
    "phpinfo": ["info_disclosure"],
    "swagger": ["info_disclosure"],
    "actuator": ["info_disclosure"],
    "debug": ["info_disclosure"],
    "directory listing": ["info_disclosure"],
    "source code": ["info_disclosure"],
    # SSRF
    "ssrf": ["ssrf"],
    "server-side request": ["ssrf"],
    "request forgery": ["ssrf"],
    # SQLi
    "sql injection": ["sqli"],
    "injectable": ["sqli"],
    "sqli": ["sqli"],
    # XSS
    "xss": ["xss"],
    "cross-site scripting": ["xss"],
    "script injection": ["xss"],
    # Session
    "session": ["session", "session_data"],
    "cookie": ["session"],
    "token": ["session"],
    # Secrets
    "api key": ["secret_exposure"],
    "api_key": ["secret_exposure"],
    "password": ["secret_exposure", "credential_data"],
    "credential": ["secret_exposure", "credential_data"],
    "secret": ["secret_exposure"],
    "token": ["secret_exposure"],
    # Services
    "redis": ["redis_noauth"],
    "mongodb": ["mongodb_noauth"],
    "open service": ["open_service"],
    "no authentication": ["default_credentials", "redis_noauth", "mongodb_noauth"],
    "default password": ["default_credentials"],
    "default credential": ["default_credentials"],
    # Cloud
    "metadata": ["cloud_metadata"],
    "169.254.169.254": ["cloud_metadata"],
    "s3": ["s3_public"],
    "bucket": ["s3_public", "data_exposure"],
    # Container
    "container escape": ["container_escape"],
    "docker socket": ["container_escape"],
    "privileged": ["container_escape"],
    # Auth
    "jwt": ["jwt_vulnerability"],
    "auth bypass": ["auth_bypass"],
    "authentication bypass": ["auth_bypass"],
    # Domain
    "subdomain takeover": ["subdomain_takeover"],
    "dangling": ["subdomain_takeover"],
    # Email
    "spf": ["email_misconfiguration"],
    "dmarc": ["email_misconfiguration"],
    "spoofing": ["spoofing", "email_misconfiguration"],
    # Advanced
    "deserialization": ["deserialization"],
    "rce": ["rce"],
    "remote code execution": ["rce"],
    "command injection": ["rce"],
    "data exposure": ["data_exposure"],
    "data leak": ["data_exposure"],
    "host access": ["host_access"],
}


# ── Chain Reasoner ───────────────────────────────────────────────

class ChainReasoner:
    """공격 체인 추론 엔진.

    Usage:
        reasoner = ChainReasoner()

        # 발견물 추가
        reasoner.add_finding(evidence1)
        reasoner.add_finding(evidence2)

        # 체인 추론
        chains = reasoner.infer_chains()

        # 결과 확인
        for chain in chains:
            print(f"{chain.title}: {chain.overall_severity}")
    """

    def __init__(self) -> None:
        self._findings: list[Evidence] = []
        self._vuln_types: dict[str, list[str]] = {}  # evidence_id → [vuln_types]
        self._discovered_chains: list[AttackChain] = []
        self._chain_counter = 0

    def add_finding(self, evidence: Evidence) -> None:
        """발견물을 추가하고 취약점 유형을 분류한다."""
        self._findings.append(evidence)

        # 키워드 매칭으로 취약점 유형 분류
        vuln_types = self._classify_finding(evidence)
        self._vuln_types[evidence.id] = vuln_types

        logger.debug(
            "체인 추론기에 발견물 추가: %s → 유형: %s",
            evidence.title, vuln_types,
        )

    def infer_chains(self) -> list[AttackChain]:
        """현재까지의 발견물로 공격 체인을 추론한다.

        Returns:
            발견된 공격 체인 목록 (impact_score 내림차순)
        """
        if len(self._findings) < 2:
            return []

        # 현재 보유한 취약점 유형 집합
        all_vuln_types: set[str] = set()
        for types in self._vuln_types.values():
            all_vuln_types.update(types)

        chains: list[AttackChain] = []

        # 각 체인 템플릿에 대해 매칭 확인
        for template in _CHAIN_TEMPLATES:
            if self._template_matches(template, all_vuln_types):
                chain = self._build_chain(template, all_vuln_types)
                if chain:
                    chains.append(chain)

        # 중복 제거 (같은 증거를 사용하는 체인이 여러 개면 점수 높은 것만)
        chains = self._deduplicate_chains(chains)

        # impact_score 기준 정렬
        chains.sort(key=lambda c: c.impact_score, reverse=True)

        self._discovered_chains = chains
        return chains

    def get_chain_hypotheses(self) -> list[dict[str, Any]]:
        """발견된 체인에서 추가 탐색 가설을 생성한다.

        체인이 "거의 완성"된 경우 (패턴의 일부만 매칭),
        나머지를 찾기 위한 가설을 생성한다.
        """
        all_vuln_types: set[str] = set()
        for types in self._vuln_types.values():
            all_vuln_types.update(types)

        hypotheses = []

        for template in _CHAIN_TEMPLATES:
            pattern_set = set(template.pattern)
            matched = pattern_set & all_vuln_types
            missing = pattern_set - all_vuln_types

            # 패턴의 절반 이상 매칭 + 아직 미완성
            if len(matched) >= len(template.pattern) / 2 and missing:
                for vuln_type in missing:
                    hypotheses.append({
                        "title": f"체인 완성 시도: {template.name}",
                        "rationale": (
                            f"발견: {', '.join(matched)} → "
                            f"미발견: {', '.join(missing)} → "
                            f"완성 시 {template.severity_upgrade}"
                        ),
                        "missing_vuln_type": vuln_type,
                        "chain_template": template.name,
                        "potential_severity": template.severity_upgrade,
                        "impact": template.impact,
                        "probability": 0.6,  # 절반 이상 발견했으므로 가능성 높음
                    })

        return hypotheses

    def format_chains_for_brain(self) -> str:
        """Brain LLM 프롬프트에 삽입할 체인 요약을 생성한다."""
        if not self._discovered_chains:
            return ""

        lines = ["## 발견된 공격 체인"]
        for chain in self._discovered_chains[:5]:
            severity_emoji = {
                "critical": "CRITICAL",
                "high": "HIGH",
                "medium": "MEDIUM",
            }.get(chain.overall_severity, chain.overall_severity)

            lines.append(
                f"- [{severity_emoji}] {chain.title} "
                f"(신뢰도 {chain.confidence:.0%}, {chain.length}단계)"
            )
            lines.append(f"  {chain.narrative}")

        # 미완성 체인 가설
        hypotheses = self.get_chain_hypotheses()
        if hypotheses:
            lines.append("\n## 체인 완성 가능성")
            for h in hypotheses[:3]:
                lines.append(
                    f"- {h['title']}: {h['rationale']}"
                )

        return "\n".join(lines)

    # ── Internal Methods ─────────────────────────────────────────

    def _classify_finding(self, evidence: Evidence) -> list[str]:
        """발견물의 제목/설명에서 취약점 유형을 분류한다."""
        text = f"{evidence.title} {evidence.description}".lower()
        vuln_types: set[str] = set()

        for keyword, types in _KEYWORD_TO_VULN_TYPE.items():
            if keyword in text:
                vuln_types.update(types)

        return list(vuln_types) if vuln_types else ["unknown"]

    def _template_matches(
        self, template: ChainTemplate, available_types: set[str],
    ) -> bool:
        """체인 템플릿의 모든 패턴이 현재 발견된 취약점에 매칭되는지 확인."""
        return all(
            vuln_type in available_types
            for vuln_type in template.pattern
        )

    def _build_chain(
        self,
        template: ChainTemplate,
        available_types: set[str],
    ) -> Optional[AttackChain]:
        """매칭된 템플릿으로 공격 체인을 구성한다."""
        links: list[ChainLink] = []

        for i, vuln_type in enumerate(template.pattern):
            # 해당 유형의 증거 찾기
            evidence = self._find_evidence_for_type(vuln_type)
            if not evidence:
                continue

            role = "entry" if i == 0 else (
                "impact" if i == len(template.pattern) - 1 else "pivot"
            )

            links.append(ChainLink(
                evidence_id=evidence.id,
                title=evidence.title,
                severity=evidence.severity.value if hasattr(evidence.severity, 'value') else str(evidence.severity),
                role=role,
                technique=vuln_type,
            ))

        if len(links) < 2:
            return None

        self._chain_counter += 1

        # 체인 신뢰도 = 각 링크의 개별 심각도 기반
        confidence = min(0.95, 0.5 + len(links) * 0.15)

        return AttackChain(
            id=f"chain-{self._chain_counter}",
            title=template.name,
            links=links,
            overall_severity=template.severity_upgrade,
            impact_score=template.impact,
            confidence=confidence,
            narrative=template.description,
            mitigations=self._generate_mitigations(template),
        )

    def _find_evidence_for_type(self, vuln_type: str) -> Optional[Evidence]:
        """특정 취약점 유형에 해당하는 증거를 찾는다."""
        for evidence_id, types in self._vuln_types.items():
            if vuln_type in types:
                for evidence in self._findings:
                    if evidence.id == evidence_id:
                        return evidence
        return None

    def _deduplicate_chains(
        self, chains: list[AttackChain],
    ) -> list[AttackChain]:
        """같은 증거를 사용하는 체인 중 점수 높은 것만 남긴다."""
        seen_evidence_sets: list[set[str]] = []
        unique_chains: list[AttackChain] = []

        for chain in sorted(chains, key=lambda c: c.impact_score, reverse=True):
            evidence_set = {link.evidence_id for link in chain.links}

            # 이미 사용된 증거 조합인지 확인
            is_duplicate = any(
                evidence_set == seen for seen in seen_evidence_sets
            )

            if not is_duplicate:
                seen_evidence_sets.append(evidence_set)
                unique_chains.append(chain)

        return unique_chains

    @staticmethod
    def _generate_mitigations(template: ChainTemplate) -> list[str]:
        """체인 패턴에 기반한 완화 조치를 생성한다."""
        mitigations_map: dict[str, list[str]] = {
            "info_disclosure": [
                "민감 파일(.env, config) 웹 서버에서 접근 차단",
                "디렉토리 리스팅 비활성화",
            ],
            "ssrf": [
                "SSRF 필터링 적용 (내부 IP 대역 차단)",
                "네트워크 세그멘테이션 강화",
            ],
            "sqli": [
                "파라미터화된 쿼리 사용",
                "입력 유효성 검증 강화",
            ],
            "xss": [
                "출력 인코딩 적용",
                "Content-Security-Policy 헤더 설정",
            ],
            "redis_noauth": [
                "Redis 인증 설정 (requirepass)",
                "Redis 포트 외부 접근 차단",
            ],
            "mongodb_noauth": [
                "MongoDB 인증 활성화",
                "네트워크 바인딩 제한 (localhost only)",
            ],
            "default_credentials": [
                "기본 자격증명 변경",
                "강력한 비밀번호 정책 적용",
            ],
            "container_escape": [
                "컨테이너 privileged 모드 비활성화",
                "seccomp/AppArmor 프로파일 적용",
            ],
        }

        mitigations: list[str] = []
        for vuln_type in template.pattern:
            mitigations.extend(mitigations_map.get(vuln_type, []))

        return mitigations[:5]  # 최대 5개
