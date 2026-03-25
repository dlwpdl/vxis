"""Cross-Protocol Synthesis Engine — 크로스-레이어 공격 체인 자동 합성.

핵심 원칙:
    개별 에이전트는 자기 레이어만 본다.
    이 엔진은 모든 에이전트의 발견을 받아서 "레이어를 넘나드는 체인"을 합성한다.
    인간이 절대 생각하지 못하는 공격 경로를 찾는다.

동작 방식:
    1. 모든 Finding을 OSI 레이어 + 공격 카테고리로 태깅
    2. 크로스-레이어 연결 패턴 DB에서 가능한 조합 탐색
    3. LLM에게 "이 발견들이 연결되면 어떤 공격이 가능한가?" 질의
    4. Attack Graph에 합성된 체인 추가
    5. PoC 텍스트 자동 생성

실제 예시:
    입력:
        - web_agent: .env 파일 노출 (AWS_ACCESS_KEY 포함) → INFO
        - cloud_agent: S3 버킷 public listing 가능 → MEDIUM
        - api_agent: 내부 API에 인증 없음 → MEDIUM
    합성:
        .env 노출 → AWS 키 탈취 → S3 데이터 다운로드 → 내부 API 호출
        개별: INFO + MEDIUM + MEDIUM
        체인: CRITICAL (데이터 유출 + 내부 접근)

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │  CrossProtocolSynthesizer                                    │
    │                                                             │
    │  ┌──────────┐  ┌──────────────┐  ┌───────────────────────┐ │
    │  │ Layer    │  │ Connection   │  │ LLM Chain            │ │
    │  │ Tagger   │──│ Pattern DB   │──│ Synthesizer          │ │
    │  │          │  │              │  │ (Claude/Kimi/Gemini)  │ │
    │  └──────────┘  └──────────────┘  └───────────┬───────────┘ │
    │                                               │             │
    │  ┌──────────────┐  ┌─────────────────────────▼───────────┐ │
    │  │ Feasibility  │  │ PoC Generator                       │ │
    │  │ Verifier     │──│ (공격 체인 → 실행 가능한 PoC 스크립트) │ │
    │  └──────────────┘  └─────────────────────────────────────┘ │
    └─────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from vxis.evidence.schema import Evidence, Severity

logger = logging.getLogger(__name__)


# ── OSI Layer Classification ────────────────────────────────────

class OSILayer(str, Enum):
    """OSI 7계층 + 추가 카테고리."""

    PHYSICAL = "L1_physical"      # USB, 물리 접근
    DATA_LINK = "L2_data_link"    # ARP, 802.1Q, Wi-Fi
    NETWORK = "L3_network"        # IP, BGP, DNS
    TRANSPORT = "L4_transport"    # TCP/UDP, TLS
    SESSION = "L5_session"        # 인증, 세션, AD
    PRESENTATION = "L6_presentation"  # 직렬화, 인코딩
    APPLICATION = "L7_application"    # HTTP, API, 웹앱

    # 비OSI 확장 카테고리
    CLOUD = "cloud"               # AWS/Azure/GCP 설정
    SUPPLY_CHAIN = "supply_chain" # 의존성, CI/CD
    HUMAN = "human"               # 소셜 엔지니어링, 피싱
    DATA = "data"                 # DB, 파일, 시크릿


class AttackCategory(str, Enum):
    """공격 카테고리 — Finding이 어떤 종류의 공격에 기여하는가."""

    INITIAL_ACCESS = "initial_access"         # 초기 진입점
    CREDENTIAL_HARVEST = "credential_harvest" # 자격증명 수집
    LATERAL_MOVEMENT = "lateral_movement"     # 횡적 이동
    PRIVILEGE_ESCALATION = "privilege_escalation"  # 권한 상승
    DATA_EXFILTRATION = "data_exfiltration"   # 데이터 탈취
    PERSISTENCE = "persistence"               # 지속성 확보
    IMPACT = "impact"                         # 최종 임팩트
    RECONNAISSANCE = "reconnaissance"         # 정찰 정보


# ── Layer Tagging Rules ─────────────────────────────────────────

# 에이전트 ID → OSI 레이어 매핑
_AGENT_LAYER_MAP: dict[str, OSILayer] = {
    "physical_usb": OSILayer.PHYSICAL,
    "side_channel": OSILayer.PHYSICAL,
    "dma_attack": OSILayer.PHYSICAL,
    "l2_network": OSILayer.DATA_LINK,
    "wireless": OSILayer.DATA_LINK,
    "bluetooth_deep": OSILayer.DATA_LINK,
    "network": OSILayer.NETWORK,
    "bgp_routing": OSILayer.NETWORK,
    "ipv6": OSILayer.NETWORK,
    "dns_deep": OSILayer.NETWORK,
    "crypto_tls": OSILayer.TRANSPORT,
    "quic_http3": OSILayer.TRANSPORT,
    "dtls": OSILayer.TRANSPORT,
    "identity_ad": OSILayer.SESSION,
    "remote_access": OSILayer.SESSION,
    "deserialization": OSILayer.PRESENTATION,
    "encoding_attack": OSILayer.PRESENTATION,
    "recon": OSILayer.APPLICATION,
    "web": OSILayer.APPLICATION,
    "api": OSILayer.APPLICATION,
    "browser_client": OSILayer.APPLICATION,
    "cms_biz_platform": OSILayer.APPLICATION,
    "business_logic": OSILayer.APPLICATION,
    "cloud": OSILayer.CLOUD,
    "iam_rbac": OSILayer.CLOUD,
    "container_k8s": OSILayer.CLOUD,
    "supply_chain": OSILayer.SUPPLY_CHAIN,
    "database": OSILayer.DATA,
    "email_security": OSILayer.APPLICATION,
    "subdomain_takeover": OSILayer.NETWORK,
    "secrets_lifecycle": OSILayer.DATA,
}

# 키워드 → 공격 카테고리 매핑
_KEYWORD_CATEGORY_MAP: dict[str, AttackCategory] = {
    # Initial Access
    "xss": AttackCategory.INITIAL_ACCESS,
    "sqli": AttackCategory.INITIAL_ACCESS,
    "sql injection": AttackCategory.INITIAL_ACCESS,
    "rce": AttackCategory.INITIAL_ACCESS,
    "ssrf": AttackCategory.LATERAL_MOVEMENT,
    "open redirect": AttackCategory.INITIAL_ACCESS,
    "default credential": AttackCategory.INITIAL_ACCESS,
    "brute force": AttackCategory.INITIAL_ACCESS,
    # Credential Harvest
    ".env": AttackCategory.CREDENTIAL_HARVEST,
    "api key": AttackCategory.CREDENTIAL_HARVEST,
    "secret": AttackCategory.CREDENTIAL_HARVEST,
    "credential": AttackCategory.CREDENTIAL_HARVEST,
    "token": AttackCategory.CREDENTIAL_HARVEST,
    "password": AttackCategory.CREDENTIAL_HARVEST,
    "aws_access": AttackCategory.CREDENTIAL_HARVEST,
    # Lateral Movement
    "internal": AttackCategory.LATERAL_MOVEMENT,
    "pivot": AttackCategory.LATERAL_MOVEMENT,
    "proxy": AttackCategory.LATERAL_MOVEMENT,
    "tunnel": AttackCategory.LATERAL_MOVEMENT,
    # Privilege Escalation
    "admin": AttackCategory.PRIVILEGE_ESCALATION,
    "root": AttackCategory.PRIVILEGE_ESCALATION,
    "sudo": AttackCategory.PRIVILEGE_ESCALATION,
    "iam": AttackCategory.PRIVILEGE_ESCALATION,
    "rbac": AttackCategory.PRIVILEGE_ESCALATION,
    # Data Exfiltration
    "s3": AttackCategory.DATA_EXFILTRATION,
    "bucket": AttackCategory.DATA_EXFILTRATION,
    "database": AttackCategory.DATA_EXFILTRATION,
    "dump": AttackCategory.DATA_EXFILTRATION,
    "backup": AttackCategory.DATA_EXFILTRATION,
    "pii": AttackCategory.DATA_EXFILTRATION,
    # Reconnaissance
    "subdomain": AttackCategory.RECONNAISSANCE,
    "open port": AttackCategory.RECONNAISSANCE,
    "version": AttackCategory.RECONNAISSANCE,
    "banner": AttackCategory.RECONNAISSANCE,
    "technology": AttackCategory.RECONNAISSANCE,
}


# ── Cross-Layer Connection Patterns ─────────────────────────────
# "이 두 레이어의 발견이 이런 패턴이면 체인이 된다"

@dataclass
class ConnectionPattern:
    """크로스-레이어 연결 패턴."""

    name: str
    source_layer: OSILayer
    target_layer: OSILayer
    source_categories: list[AttackCategory]
    target_categories: list[AttackCategory]
    chain_severity: Severity  # 합성 시 체인의 severity
    description: str
    kill_chain_stage: str  # MITRE Kill Chain 단계


# 알려진 크로스-레이어 체인 패턴 DB
KNOWN_PATTERNS: list[ConnectionPattern] = [
    # ── 정보노출 → 자격증명 → 클라우드 접근 ──
    ConnectionPattern(
        name="credential_to_cloud",
        source_layer=OSILayer.APPLICATION,
        target_layer=OSILayer.CLOUD,
        source_categories=[AttackCategory.CREDENTIAL_HARVEST],
        target_categories=[AttackCategory.DATA_EXFILTRATION],
        chain_severity=Severity.CRITICAL,
        description="애플리케이션에서 노출된 자격증명으로 클라우드 리소스에 접근",
        kill_chain_stage="Exploitation → Actions on Objectives",
    ),
    # ── SSRF → 내부 서비스 접근 ──
    ConnectionPattern(
        name="ssrf_to_internal",
        source_layer=OSILayer.APPLICATION,
        target_layer=OSILayer.NETWORK,
        source_categories=[AttackCategory.LATERAL_MOVEMENT],
        target_categories=[AttackCategory.DATA_EXFILTRATION, AttackCategory.PRIVILEGE_ESCALATION],
        chain_severity=Severity.CRITICAL,
        description="웹 앱의 SSRF로 내부 네트워크 서비스에 접근",
        kill_chain_stage="Exploitation → Lateral Movement",
    ),
    # ── 서브도메인 탈취 → 세션 하이재킹 ──
    ConnectionPattern(
        name="subdomain_to_session",
        source_layer=OSILayer.NETWORK,
        target_layer=OSILayer.SESSION,
        source_categories=[AttackCategory.INITIAL_ACCESS],
        target_categories=[AttackCategory.CREDENTIAL_HARVEST],
        chain_severity=Severity.HIGH,
        description="서브도메인 탈취 후 쿠키 도메인 범위를 악용한 세션 탈취",
        kill_chain_stage="Initial Access → Credential Access",
    ),
    # ── DNS 조작 → TLS 인증서 우회 ──
    ConnectionPattern(
        name="dns_to_tls_bypass",
        source_layer=OSILayer.NETWORK,
        target_layer=OSILayer.TRANSPORT,
        source_categories=[AttackCategory.INITIAL_ACCESS],
        target_categories=[AttackCategory.LATERAL_MOVEMENT],
        chain_severity=Severity.HIGH,
        description="DNS 설정 취약점으로 TLS 인증서 발급/우회",
        kill_chain_stage="Initial Access → Defense Evasion",
    ),
    # ── 공급망 → 코드 실행 → 인프라 접근 ──
    ConnectionPattern(
        name="supply_chain_to_rce",
        source_layer=OSILayer.SUPPLY_CHAIN,
        target_layer=OSILayer.APPLICATION,
        source_categories=[AttackCategory.INITIAL_ACCESS],
        target_categories=[AttackCategory.PRIVILEGE_ESCALATION],
        chain_severity=Severity.CRITICAL,
        description="공급망 취약점(의존성 혼동 등)을 통한 코드 실행",
        kill_chain_stage="Initial Access → Execution → Persistence",
    ),
    # ── 이메일 스푸핑 → 피싱 → 자격증명 탈취 ──
    ConnectionPattern(
        name="email_spoof_to_cred",
        source_layer=OSILayer.APPLICATION,
        target_layer=OSILayer.SESSION,
        source_categories=[AttackCategory.INITIAL_ACCESS],
        target_categories=[AttackCategory.CREDENTIAL_HARVEST],
        chain_severity=Severity.HIGH,
        description="SPF/DMARC 미설정 → 이메일 스푸핑 → 피싱 → 계정 탈취",
        kill_chain_stage="Initial Access → Credential Access",
    ),
    # ── 약한 TLS → MITM → 데이터 탈취 ──
    ConnectionPattern(
        name="weak_tls_to_mitm",
        source_layer=OSILayer.TRANSPORT,
        target_layer=OSILayer.DATA,
        source_categories=[AttackCategory.INITIAL_ACCESS],
        target_categories=[AttackCategory.DATA_EXFILTRATION],
        chain_severity=Severity.HIGH,
        description="약한 TLS 설정 → MITM 공격 → 민감 데이터 탈취",
        kill_chain_stage="Initial Access → Collection → Exfiltration",
    ),
    # ── 컨테이너 탈출 → 호스트 접근 → 인프라 장악 ──
    ConnectionPattern(
        name="container_escape_to_infra",
        source_layer=OSILayer.CLOUD,
        target_layer=OSILayer.NETWORK,
        source_categories=[AttackCategory.PRIVILEGE_ESCALATION],
        target_categories=[AttackCategory.LATERAL_MOVEMENT],
        chain_severity=Severity.CRITICAL,
        description="컨테이너 탈출 → 호스트 OS 접근 → 네트워크 피봇",
        kill_chain_stage="Privilege Escalation → Lateral Movement",
    ),
    # ── 역직렬화 → RCE → 시스템 장악 ──
    ConnectionPattern(
        name="deserialization_to_rce",
        source_layer=OSILayer.PRESENTATION,
        target_layer=OSILayer.APPLICATION,
        source_categories=[AttackCategory.INITIAL_ACCESS],
        target_categories=[AttackCategory.PRIVILEGE_ESCALATION],
        chain_severity=Severity.CRITICAL,
        description="역직렬화 취약점 → 원격 코드 실행 → 시스템 장악",
        kill_chain_stage="Exploitation → Execution → Persistence",
    ),
    # ── Wi-Fi → 내부 네트워크 → AD 장악 ──
    ConnectionPattern(
        name="wifi_to_ad",
        source_layer=OSILayer.DATA_LINK,
        target_layer=OSILayer.SESSION,
        source_categories=[AttackCategory.INITIAL_ACCESS],
        target_categories=[AttackCategory.PRIVILEGE_ESCALATION],
        chain_severity=Severity.CRITICAL,
        description="Wi-Fi 취약점 → 내부 네트워크 진입 → AD 장악",
        kill_chain_stage="Initial Access → Lateral Movement → Domain Dominance",
    ),
]


# ── Synthesized Attack Chain ────────────────────────────────────

@dataclass
class SynthesizedChain:
    """합성된 크로스-프로토콜 공격 체인."""

    id: str
    title: str
    description: str
    severity: Severity
    kill_chain_stages: list[str]
    findings: list[Evidence]  # 체인을 구성하는 개별 발견들
    layers_crossed: list[OSILayer]  # 체인이 넘나드는 레이어들
    pattern_name: str  # 매칭된 패턴 이름 (또는 "llm_synthesized")
    confidence: float  # 0.0~1.0
    poc_text: str = ""  # PoC 설명 텍스트
    individual_severity_sum: str = ""  # 개별 severity 합계 (비교용)
    escalation_reason: str = ""  # severity가 상승된 이유


# ── Core Synthesizer ────────────────────────────────────────────

class CrossProtocolSynthesizer:
    """크로스-프로토콜 공격 체인 합성 엔진.

    Phase 1: 패턴 DB 기반 매칭 (LLM 불필요, Tier 0)
    Phase 2: LLM 기반 창의적 합성 (Tier 4 Opus)
    Phase 3: 합성된 체인의 실현 가능성 검증
    Phase 4: PoC 텍스트 생성
    """

    def __init__(self) -> None:
        self._findings: list[Evidence] = []
        self._tagged: list[tuple[Evidence, OSILayer, list[AttackCategory]]] = []
        self._chains: list[SynthesizedChain] = []

    def add_findings(self, findings: list[Evidence]) -> None:
        """새로운 발견들을 추가한다."""
        for f in findings:
            if f.id not in {existing.id for existing in self._findings}:
                self._findings.append(f)
                layer = self._tag_layer(f)
                categories = self._tag_categories(f)
                self._tagged.append((f, layer, categories))

    async def synthesize(self) -> list[SynthesizedChain]:
        """모든 발견을 분석하여 크로스-레이어 체인을 합성한다.

        Returns:
            새로 발견된 SynthesizedChain 리스트.
        """
        new_chains: list[SynthesizedChain] = []

        # Phase 1: 패턴 DB 매칭 (빠름, LLM 불필요)
        pattern_chains = self._match_patterns()
        new_chains.extend(pattern_chains)

        # Phase 2: LLM 창의적 합성 (비쌈, 발견이 3개 이상일 때만)
        if len(self._findings) >= 3:
            llm_chains = await self._llm_synthesize()
            # 패턴 매칭과 중복 제거
            existing_titles = {c.title for c in new_chains}
            for chain in llm_chains:
                if chain.title not in existing_titles:
                    new_chains.append(chain)

        self._chains.extend(new_chains)

        if new_chains:
            logger.info(
                "크로스-프로토콜 합성: %d개 새 체인 발견 (총 %d개)",
                len(new_chains), len(self._chains),
            )
            for chain in new_chains:
                layers = " → ".join(l.value for l in chain.layers_crossed)
                logger.info(
                    "  [%s] %s (%s) — 신뢰도 %.0f%%",
                    chain.severity.value.upper(),
                    chain.title,
                    layers,
                    chain.confidence * 100,
                )

        return new_chains

    @property
    def all_chains(self) -> list[SynthesizedChain]:
        return self._chains

    # ── Phase 1: Pattern Matching ───────────────────────────────

    def _match_patterns(self) -> list[SynthesizedChain]:
        """알려진 패턴 DB에서 매칭되는 체인을 찾는다."""
        chains: list[SynthesizedChain] = []

        for pattern in KNOWN_PATTERNS:
            # Source 레이어 + 카테고리에 매칭되는 발견 찾기
            sources = [
                (f, layer, cats) for f, layer, cats in self._tagged
                if layer == pattern.source_layer
                and any(c in pattern.source_categories for c in cats)
            ]

            # Target 레이어 + 카테고리에 매칭되는 발견 찾기
            targets = [
                (f, layer, cats) for f, layer, cats in self._tagged
                if layer == pattern.target_layer
                and any(c in pattern.target_categories for c in cats)
            ]

            # 매칭된 조합으로 체인 생성
            if sources and targets:
                for src_f, src_l, _ in sources:
                    for tgt_f, tgt_l, _ in targets:
                        if src_f.id == tgt_f.id:
                            continue

                        # 개별 severity vs 체인 severity 비교
                        individual = f"{src_f.severity.value} + {tgt_f.severity.value}"
                        escalated = pattern.chain_severity

                        chain = SynthesizedChain(
                            id=f"chain_{pattern.name}_{src_f.id[:8]}_{tgt_f.id[:8]}",
                            title=f"{pattern.description}",
                            description=(
                                f"크로스-레이어 공격 체인 감지:\n"
                                f"  단계 1: [{src_f.severity.value}] {src_f.title} "
                                f"({src_l.value})\n"
                                f"  단계 2: [{tgt_f.severity.value}] {tgt_f.title} "
                                f"({tgt_l.value})\n\n"
                                f"개별 평가: {individual}\n"
                                f"체인 평가: {escalated.value.upper()}\n\n"
                                f"Kill Chain: {pattern.kill_chain_stage}"
                            ),
                            severity=escalated,
                            kill_chain_stages=pattern.kill_chain_stage.split(" → "),
                            findings=[src_f, tgt_f],
                            layers_crossed=[src_l, tgt_l],
                            pattern_name=pattern.name,
                            confidence=0.85,
                            individual_severity_sum=individual,
                            escalation_reason=(
                                f"개별로는 {individual}이지만, "
                                f"체인으로 연결하면 {escalated.value.upper()}. "
                                f"패턴: {pattern.name}"
                            ),
                        )
                        chains.append(chain)

        return chains

    # ── Phase 2: LLM Creative Synthesis ─────────────────────────

    async def _llm_synthesize(self) -> list[SynthesizedChain]:
        """LLM에게 창의적 체인 합성을 요청한다."""
        import json

        # 발견 요약 구성
        findings_text = []
        for f, layer, cats in self._tagged:
            cat_str = ", ".join(c.value for c in cats)
            findings_text.append(
                f"- [{f.severity.value}] {f.title} "
                f"(레이어: {layer.value}, 카테고리: {cat_str}, "
                f"에이전트: {f.agent_id})"
            )

        if not findings_text:
            return []

        prompt = f"""\
다음은 보안 스캔에서 발견된 개별 취약점 목록이다.
이 발견들을 **레이어를 넘나드는 공격 체인**으로 합성하라.

개별 발견:
{chr(10).join(findings_text)}

규칙:
1. 최소 2개 이상의 서로 다른 레이어의 발견을 연결해야 한다.
2. 개별로는 낮은 severity지만 체인으로 연결하면 높아지는 경우를 찾아라.
3. 현실적으로 실행 가능한 체인만 제시하라.
4. 각 체인에 대해 구체적인 공격 시나리오를 설명하라.

JSON으로 응답:
{{
  "chains": [
    {{
      "title": "체인 제목 (한국어)",
      "description": "상세 공격 시나리오 (한국어)",
      "severity": "critical|high|medium",
      "kill_chain_stages": ["Initial Access", "Lateral Movement", ...],
      "finding_ids": ["id1", "id2"],
      "layers_crossed": ["L7_application", "cloud"],
      "confidence": 0.7,
      "escalation_reason": "왜 개별보다 심각한지 설명"
    }}
  ]
}}

체인이 없으면 빈 배열을 반환하라.
"""

        try:
            from vxis.llm.client import LLMClient
            client = LLMClient()
            response = await client.think(
                system="당신은 엘리트 레드팀 전문가입니다. 개별 취약점을 연결하여 치명적인 공격 체인을 합성합니다.",
                user=prompt,
                max_tokens=3000,
            )

            # Parse response
            text = response.text
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]

            data = json.loads(text.strip())
            finding_map = {f.id: f for f in self._findings}

            chains = []
            for item in data.get("chains", []):
                # Resolve finding references
                chain_findings = [
                    finding_map[fid] for fid in item.get("finding_ids", [])
                    if fid in finding_map
                ]
                if len(chain_findings) < 2:
                    continue

                # Parse layers
                layers = []
                for l_str in item.get("layers_crossed", []):
                    try:
                        layers.append(OSILayer(l_str))
                    except ValueError:
                        pass

                chains.append(SynthesizedChain(
                    id=f"chain_llm_{len(chains)}",
                    title=item.get("title", "LLM 합성 체인"),
                    description=item.get("description", ""),
                    severity=Severity(item.get("severity", "high")),
                    kill_chain_stages=item.get("kill_chain_stages", []),
                    findings=chain_findings,
                    layers_crossed=layers,
                    pattern_name="llm_synthesized",
                    confidence=item.get("confidence", 0.6),
                    escalation_reason=item.get("escalation_reason", ""),
                ))

            return chains

        except Exception as exc:
            logger.warning("LLM 체인 합성 실패: %s", exc)
            return []

    # ── Tagging ─────────────────────────────────────────────────

    def _tag_layer(self, evidence: Evidence) -> OSILayer:
        """Finding의 에이전트 ID로 OSI 레이어를 결정한다."""
        return _AGENT_LAYER_MAP.get(evidence.agent_id, OSILayer.APPLICATION)

    def _tag_categories(self, evidence: Evidence) -> list[AttackCategory]:
        """Finding의 제목/설명에서 공격 카테고리를 추출한다."""
        categories = []
        text = f"{evidence.title} {evidence.description}".lower()

        for keyword, category in _KEYWORD_CATEGORY_MAP.items():
            if keyword in text and category not in categories:
                categories.append(category)

        if not categories:
            categories.append(AttackCategory.RECONNAISSANCE)

        return categories

    # ── Reporting ───────────────────────────────────────────────

    def format_report(self) -> str:
        """합성된 체인 리포트를 마크다운으로 생성한다."""
        if not self._chains:
            return "## Cross-Protocol Synthesis\n\n_체인 없음._\n"

        lines = [
            "## Cross-Protocol Synthesis Report",
            f"_총 {len(self._chains)}개 크로스-레이어 공격 체인 발견_\n",
        ]

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

        for sev in severity_order:
            sev_chains = [c for c in self._chains if c.severity == sev]
            if not sev_chains:
                continue

            lines.append(f"### {sev.value.upper()} 체인 ({len(sev_chains)}개)\n")

            for chain in sev_chains:
                layers = " → ".join(l.value for l in chain.layers_crossed)
                lines.append(f"#### ⛓ {chain.title}")
                lines.append(f"**레이어:** {layers}")
                lines.append(f"**신뢰도:** {chain.confidence:.0%}")
                lines.append(f"**Kill Chain:** {' → '.join(chain.kill_chain_stages)}")
                if chain.escalation_reason:
                    lines.append(f"**에스컬레이션:** {chain.escalation_reason}")
                lines.append(f"\n{chain.description}\n")

                if chain.findings:
                    lines.append("**구성 요소:**")
                    for f in chain.findings:
                        lines.append(
                            f"- [{f.severity.value}] {f.title} ({f.agent_id})"
                        )
                lines.append("")

        return "\n".join(lines)
