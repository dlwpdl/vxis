"""다중 방어 경로 플래너 — 고객 상황에 맞는 여러 방어 옵션 제공.

각 옵션에 대해:
- 위험도 (적용 시 부작용 가능성)
- 효율성 (방어 효과 %)
- 구현 시간 (즉시/1시간/1일/1주)
- 비용 (무료/저가/고가)
- 복잡도 (낮음/중간/높음)

Usage:
    planner = DefensePlanner()
    options = await planner.plan_defense(verified_exploit)
    print(planner.format_defense_matrix(options))
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from .red_vs_blue import VerifiedExploit

logger = logging.getLogger(__name__)


# ── Data Models ─────────────────────────────────────────────────

@dataclass
class DefenseOption:
    """단일 방어 옵션 — 고객이 선택 가능한 하나의 방어 경로."""

    name: str                        # 예: "WAF 긴급 규칙", "코드 패치"
    category: str                    # quick_fix | proper_patch | waf_rule | architecture | isolation | honeypot
    risk_level: str                  # low | medium | high — 적용 시 서비스 영향
    effectiveness: float             # 0.0~1.0 — 방어 효과
    implementation_time: str         # "즉시" | "1시간" | "1일" | "1주"
    cost: str                        # "무료" | "저가" | "고가"
    complexity: str                  # "낮음" | "중간" | "높음"
    steps: list[str] = field(default_factory=list)       # 구체적 적용 단계
    trade_off: str = ""              # 장단점 설명
    side_effects: list[str] = field(default_factory=list)  # 가능한 부작용
    blocks_variants: int = 0         # 차단 가능한 변이 수 (100가지 중)

    @property
    def effectiveness_pct(self) -> str:
        """효율성을 퍼센트 문자열로 반환."""
        return f"{int(self.effectiveness * 100)}%"

    @property
    def risk_emoji(self) -> str:
        mapping = {"low": "🟢", "medium": "🟡", "high": "🔴"}
        return mapping.get(self.risk_level, "⚪")


# ── Default Option Factories (Tier 0 — 규칙 기반) ────────────────

def _make_waf_emergency_option(exploit: VerifiedExploit) -> DefenseOption:
    """옵션 A: WAF 긴급 차단 규칙."""
    attack = exploit.attack_type.lower()
    path = exploit.affected_component or "/"

    attack_steps: dict[str, list[str]] = {
        "sqli": [
            f"ModSecurity에 '{path}' 경로 SQLi 차단 규칙 추가",
            "REQUEST_ARGS에서 UNION, SELECT, OR 1=1 패턴 필터링",
            "WAF 로그 실시간 모니터링 활성화",
            "24시간 후 false positive 통계 검토",
        ],
        "xss": [
            f"ModSecurity에 '{path}' 경로 XSS 차단 규칙 추가",
            "<script>, javascript:, onerror= 패턴 필터링",
            "HTML 엔티티 디코드 후 재검사",
            "CSP(Content-Security-Policy) 헤더 강화",
        ],
        "ssrf": [
            "WAF에서 요청 파라미터의 내부 IP 패턴 차단",
            "169.254.x.x, 127.0.0.1, 10.x.x.x 범위 필터링",
            "외부 URL 요청 whitelist 적용",
            "DNS rebinding 방지 규칙 추가",
        ],
        "rce": [
            f"'{path}' 엔드포인트에 명령어 메타문자 필터링",
            "; | $ ` 등 shell 메타문자 차단",
            "WAF 규칙 적용 후 애플리케이션 기능 테스트",
            "false positive 발생 시 파라미터 범위 축소",
        ],
        "lfi": [
            f"'{path}' 경로에서 경로 순회 패턴 차단",
            "../, ..\\, %2e%2e 인코딩 변이 모두 필터링",
            "파일 경로 파라미터 whitelist 적용",
        ],
    }

    side_effects_map: dict[str, list[str]] = {
        "sqli": ["정상 SQL 키워드 포함 파라미터 차단 가능", "검색 기능 오작동 가능성"],
        "xss": ["마크업 허용 필드에서 false positive 발생 가능", "리치 텍스트 에디터 영향"],
        "ssrf": ["정상 외부 URL 요청 서비스 영향 가능", "OAuth redirect 등 주의 필요"],
        "rce": ["일부 정상 파라미터 차단 가능", "쉘 스크립트 업로드 기능 영향"],
        "lfi": ["파일 다운로드 기능 일부 영향 가능"],
    }

    return DefenseOption(
        name="WAF 긴급 차단 규칙",
        category="waf_rule",
        risk_level="low",
        effectiveness=0.70,
        implementation_time="즉시",
        cost="무료",
        complexity="낮음",
        steps=attack_steps.get(attack, [
            f"'{path}' 경로에 공격 패턴 필터링 규칙 추가",
            "WAF 로그 모니터링 활성화",
        ]),
        trade_off=(
            "즉시 적용 가능하나 우회 가능성 존재. "
            "변이 공격(인코딩, 분할)에 취약. "
            "근본 해결책이 아닌 임시 방어."
        ),
        side_effects=side_effects_map.get(attack, ["일부 정상 요청 차단 가능성"]),
        blocks_variants=70,
    )


def _make_code_patch_option(exploit: VerifiedExploit) -> DefenseOption:
    """옵션 B: 정식 코드 패치."""
    attack = exploit.attack_type.lower()

    patch_steps: dict[str, list[str]] = {
        "sqli": [
            "모든 DB 쿼리를 Prepared Statement / ORM으로 교체",
            "입력 파라미터 타입 검증 추가 (정수, 문자열 길이)",
            "최소권한 DB 계정 사용 확인",
            "단위 테스트 작성 후 스테이징 배포",
            "프로덕션 배포 및 모니터링",
        ],
        "xss": [
            "모든 출력 값에 HTML 엔티티 인코딩 적용",
            "템플릿 엔진의 auto-escape 활성화 확인",
            "CSP 헤더 추가 (script-src 'self' 등)",
            "DOMPurify 등 클라이언트 측 sanitization 적용",
            "단위 테스트 및 배포",
        ],
        "ssrf": [
            "URL 파라미터 입력값 검증 로직 추가",
            "허용된 도메인/IP 범위 whitelist 구현",
            "내부 IP 범위 요청 차단 로직 (RFC1918)",
            "HTTP 리디렉션 팔로우 제한",
            "단위 테스트 및 배포",
        ],
        "rce": [
            "shell 명령어 직접 호출 제거, 라이브러리 API로 대체",
            "불가피한 경우 escapeshellarg() 등 이스케이프 적용",
            "입력값 whitelist 검증 (허용 문자 정의)",
            "최소 권한으로 프로세스 실행",
            "단위 테스트 및 배포",
        ],
        "lfi": [
            "파일 경로 입력 파라미터 제거 또는 ID 기반으로 변경",
            "파일 경로 접근 시 realpath() 후 허용 디렉토리 검증",
            "허용된 파일 목록 whitelist 구현",
            "단위 테스트 및 배포",
        ],
    }

    return DefenseOption(
        name="정식 코드 패치",
        category="proper_patch",
        risk_level="low",
        effectiveness=1.0,
        implementation_time="1일",
        cost="무료",
        complexity="중간",
        steps=patch_steps.get(attack, [
            f"{attack} 취약점 원인 코드 분석",
            "입력 검증 및 출력 인코딩 로직 수정",
            "단위 테스트 작성",
            "스테이징 검증 후 프로덕션 배포",
        ]),
        trade_off=(
            "근본적 해결책으로 모든 변이 차단. "
            "개발 및 테스트 시간 필요. "
            "배포 과정에서 서비스 중단 가능성 있으나 계획적 수행 시 최소화 가능."
        ),
        side_effects=["배포 과정 서비스 재시작 (수 초~분)", "기존 기능 회귀 테스트 필요"],
        blocks_variants=100,
    )


def _make_network_isolation_option(exploit: VerifiedExploit) -> DefenseOption:
    """옵션 C: 네트워크 격리."""
    path = exploit.affected_component or "/"

    return DefenseOption(
        name="네트워크 격리",
        category="isolation",
        risk_level="medium",
        effectiveness=0.90,
        implementation_time="1시간",
        cost="무료",
        complexity="중간",
        steps=[
            f"방화벽/보안그룹에서 '{path}' 엔드포인트 외부 접근 차단",
            "신뢰된 IP 범위만 허용하는 ACL 적용",
            "내부 서비스만 접근 가능하도록 VPC/VLAN 분리",
            "API 게이트웨이에서 인증된 사용자만 접근 허용",
            "Nginx/HAProxy에서 특정 경로 접근 제한 규칙 적용",
        ],
        trade_off=(
            "정상 외부 사용자 접근도 차단되어 서비스 영향 발생. "
            "내부 공격자나 인증된 사용자의 악용은 차단 불가. "
            "긴급 상황에서 서비스보다 보안 우선 시 유효."
        ),
        side_effects=[
            "외부 사용자 해당 기능 사용 불가",
            "B2B API 연동 서비스 영향 가능",
            "모바일 앱 등 외부 클라이언트 영향",
        ],
        blocks_variants=90,
    )


def _make_architecture_change_option(exploit: VerifiedExploit) -> DefenseOption:
    """옵션 D: 아키텍처 변경."""
    attack = exploit.attack_type.lower()

    arch_steps: dict[str, list[str]] = {
        "sqli": [
            "ORM 도입 및 Raw SQL 전면 제거",
            "DB 접근 계층(Repository Pattern) 분리",
            "Read/Write DB 계정 분리 (최소권한)",
            "DB 방화벽(DBShield 등) 도입 검토",
            "마이그레이션 계획 수립 및 단계적 적용",
        ],
        "ssrf": [
            "외부 URL 요청 기능을 별도 격리 서비스로 분리",
            "격리 서비스에 엄격한 egress 방화벽 적용",
            "URL 처리 큐(Queue) 기반 비동기 처리",
            "Zero Trust 네트워크 아키텍처 도입",
        ],
        "rce": [
            "사용자 입력 처리를 컨테이너/샌드박스 내부로 격리",
            "gVisor, seccomp 등 런타임 보안 적용",
            "최소 권한 컨테이너로 기능 분리",
            "입력 처리 서비스와 핵심 서비스 완전 분리",
        ],
    }

    return DefenseOption(
        name="아키텍처 변경",
        category="architecture",
        risk_level="high",
        effectiveness=1.0,
        implementation_time="1주",
        cost="고가",
        complexity="높음",
        steps=arch_steps.get(attack, [
            "현재 아키텍처 보안 취약점 전체 리뷰",
            "Zero Trust 원칙 기반 재설계",
            "단계적 마이그레이션 계획 수립",
            "기능별 격리 및 최소권한 원칙 적용",
            "전체 보안 테스트 후 전환",
        ]),
        trade_off=(
            "가장 강력한 장기적 해결책. "
            "높은 구현 비용과 시간 필요. "
            "마이그레이션 과정의 복잡성과 위험. "
            "완료 후 유사 공격 전체 클래스 차단 가능."
        ),
        side_effects=[
            "대규모 코드 변경으로 인한 회귀 위험",
            "마이그레이션 기간 중 서비스 불안정 가능",
            "팀 학습 곡선 및 추가 인프라 비용",
        ],
        blocks_variants=100,
    )


def _make_honeypot_option(exploit: VerifiedExploit) -> DefenseOption:
    """옵션 E: 허니팟 전환 — 공격자 추적."""
    path = exploit.affected_component or "/"

    return DefenseOption(
        name="허니팟 전환 (공격자 추적)",
        category="honeypot",
        risk_level="low",
        effectiveness=0.80,
        implementation_time="1시간",
        cost="무료",
        complexity="중간",
        steps=[
            f"'{path}' 엔드포인트를 허니팟 서버로 리다이렉트",
            "허니팟이 성공한 것처럼 가짜 응답 반환하도록 설정",
            "모든 요청/페이로드/IP 로깅 활성화",
            "실제 서비스는 다른 경로/포트로 이동",
            "수집된 IP를 WAF 차단 목록에 자동 추가",
            "공격 패턴 분석 후 VXIS 학습 데이터 피드백",
        ],
        trade_off=(
            "공격자를 탐지하고 추적 정보를 수집. "
            "실제 서비스를 보호하면서 공격 기법 학습. "
            "공격자가 허니팟임을 알아채면 효과 없음. "
            "실제 데이터 노출 없이 공격자 전술 파악 가능."
        ),
        side_effects=[
            "허니팟 유지관리 오버헤드",
            "정교한 공격자는 우회 가능",
            "법적 이슈 검토 필요 (관할권별 차이)",
        ],
        blocks_variants=80,
    )


# ── Defense Planner ──────────────────────────────────────────────

class DefensePlanner:
    """공격 유형과 컨텍스트에 따라 다중 방어 경로를 생성한다.

    Usage:
        planner = DefensePlanner()
        options = await planner.plan_defense(exploit)
        print(planner.format_defense_matrix(options))
    """

    async def plan_defense(self, exploit: VerifiedExploit) -> list[DefenseOption]:
        """검증된 익스플로잇에 대한 4~5가지 방어 옵션을 생성한다.

        Phase 1: 규칙 기반 기본 옵션 생성 (Tier 0 — 항상 실행)
        Phase 2: LLM으로 각 옵션 컨텍스트 맞춤 개선 (Tier 3 — 가능한 경우)
        """
        logger.info(
            "방어 경로 플래닝 시작: %s (%s)",
            exploit.title, exploit.attack_type,
        )

        # Phase 1: 규칙 기반 기본 옵션 5가지 생성
        options = [
            _make_waf_emergency_option(exploit),
            _make_code_patch_option(exploit),
            _make_network_isolation_option(exploit),
            _make_architecture_change_option(exploit),
            _make_honeypot_option(exploit),
        ]

        # Phase 2: LLM으로 각 옵션의 steps/trade_off를 컨텍스트 맞춤 개선
        enhanced = await self._enhance_with_llm(exploit, options)
        if enhanced:
            options = enhanced

        logger.info("방어 경로 %d개 생성 완료", len(options))
        return options

    async def _enhance_with_llm(
        self,
        exploit: VerifiedExploit,
        options: list[DefenseOption],
    ) -> list[DefenseOption] | None:
        """LLM을 사용하여 옵션을 컨텍스트에 맞게 개선한다."""
        prompt = f"""\
검증된 취약점에 대한 방어 옵션 5가지를 컨텍스트에 맞게 개선하라.

취약점 정보:
- 제목: {exploit.title}
- 유형: {exploit.attack_type}
- 심각도: {exploit.severity}
- 영향 컴포넌트: {exploit.affected_component}
- 설명: {exploit.description[:300]}
- 페이로드: {exploit.payload[:200] if exploit.payload else '없음'}

현재 방어 옵션 5가지:
{json.dumps([{
    "name": o.name,
    "category": o.category,
    "steps": o.steps,
    "trade_off": o.trade_off,
} for o in options], ensure_ascii=False, indent=2)}

위 옵션들의 steps와 trade_off를 이 특정 취약점 컨텍스트에 맞게 구체화하라.
다음 JSON 배열로 반환하라 (순서 동일, 5개):
[
  {{
    "name": "...",
    "steps": ["구체적 단계 1", ...],
    "trade_off": "장단점 설명",
    "side_effects": ["부작용 1", ...]
  }},
  ...
]
"""
        try:
            from vxis.llm.client import LLMClient
            client = LLMClient()
            response = await client.think(
                system="당신은 시니어 보안 아키텍트입니다. 취약점별 맞춤형 방어 전략을 제시합니다.",
                user=prompt,
                max_tokens=3000,
            )

            text = response.text
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]

            enhanced_data: list[dict[str, Any]] = json.loads(text.strip())

            if not isinstance(enhanced_data, list) or len(enhanced_data) != len(options):
                logger.warning("LLM 응답 형식 불일치 — 기본 옵션 유지")
                return None

            for i, (option, data) in enumerate(zip(options, enhanced_data)):
                if isinstance(data.get("steps"), list) and data["steps"]:
                    option.steps = data["steps"]
                if isinstance(data.get("trade_off"), str) and data["trade_off"]:
                    option.trade_off = data["trade_off"]
                if isinstance(data.get("side_effects"), list) and data["side_effects"]:
                    option.side_effects = data["side_effects"]

            return options

        except Exception as exc:
            logger.warning("LLM 옵션 개선 실패, 기본 옵션 사용: %s", exc)
            return None

    def format_defense_matrix(self, options: list[DefenseOption]) -> str:
        """방어 옵션 비교 매트릭스를 마크다운으로 출력한다."""
        if not options:
            return "## 방어 옵션 없음\n"

        lines = [
            "## 다중 방어 경로 비교 매트릭스",
            "",
            "| # | 옵션 | 위험도 | 효과 | 구현 시간 | 비용 | 복잡도 | 변이 차단 |",
            "|---|------|--------|------|-----------|------|--------|-----------|",
        ]

        for i, opt in enumerate(options, 1):
            lines.append(
                f"| {i} | **{opt.name}** "
                f"| {opt.risk_emoji} {opt.risk_level} "
                f"| {opt.effectiveness_pct} "
                f"| {opt.implementation_time} "
                f"| {opt.cost} "
                f"| {opt.complexity} "
                f"| {opt.blocks_variants}/100 |"
            )

        lines.append("")
        lines.append("---")
        lines.append("")

        for i, opt in enumerate(options, 1):
            lines.append(f"### 옵션 {i}: {opt.name}")
            lines.append("")
            lines.append(f"**카테고리:** `{opt.category}` | "
                         f"**위험도:** {opt.risk_emoji} {opt.risk_level} | "
                         f"**효과:** {opt.effectiveness_pct}")
            lines.append("")

            if opt.steps:
                lines.append("**적용 단계:**")
                for j, step in enumerate(opt.steps, 1):
                    lines.append(f"{j}. {step}")
                lines.append("")

            if opt.trade_off:
                lines.append(f"**장단점:** {opt.trade_off}")
                lines.append("")

            if opt.side_effects:
                lines.append("**부작용 주의:**")
                for effect in opt.side_effects:
                    lines.append(f"- {effect}")
                lines.append("")

        lines.append("---")
        lines.append("_VXIS Defense Planner — 상황에 맞는 방어 경로를 선택하세요._")

        return "\n".join(lines)
