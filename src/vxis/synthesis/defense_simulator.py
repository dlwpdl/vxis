"""방어 시뮬레이터 — 실제 인프라 변경 없이 방어 효과를 검증.

1. 원본 공격 PoC를 N가지 변이로 확장
2. 각 방어 옵션에 대해 변이별 차단 여부 시뮬레이션
3. 결과: "Option A는 95/100 변이 차단, Option B는 100/100 차단"

실제 서버를 건드리지 않고 정규식/규칙 레벨에서 시뮬레이션한다.

Usage:
    simulator = DefenseSimulator()
    variants = simulator.generate_attack_variants(exploit, count=50)
    results = await simulator.run_simulation(exploit, defense_options)
    print(simulator.format_simulation_report(results))
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from .red_vs_blue import VerifiedExploit
from .defense_planner import DefenseOption

logger = logging.getLogger(__name__)


# ── Data Models ─────────────────────────────────────────────────

@dataclass
class SimulationResult:
    """단일 방어 옵션의 시뮬레이션 결과."""

    defense_option_name: str
    total_variants: int
    blocked: int
    bypassed: int
    bypass_rate: float                              # 0.0~1.0
    bypassed_payloads: list[str] = field(default_factory=list)  # 통과된 페이로드 목록

    @property
    def block_rate(self) -> float:
        return 1.0 - self.bypass_rate

    @property
    def block_pct(self) -> str:
        return f"{int(self.block_rate * 100)}%"

    @property
    def status_emoji(self) -> str:
        if self.bypass_rate == 0.0:
            return "🟢"
        elif self.bypass_rate < 0.1:
            return "🟡"
        elif self.bypass_rate < 0.3:
            return "🟠"
        else:
            return "🔴"


# ── Attack Variant Generators (Tier 0 — 규칙 기반) ───────────────

class _VariantGenerators:
    """공격 유형별 변이 생성기 — 순수 규칙 기반."""

    @staticmethod
    def _url_encode(s: str) -> str:
        return urllib.parse.quote(s, safe="")

    @staticmethod
    def _double_url_encode(s: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")

    @staticmethod
    def _to_hex(s: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in s)

    @staticmethod
    def _html_encode(s: str) -> str:
        return "".join(f"&#{ord(c)};" for c in s)

    # ── SQL Injection 변이 ─────────────────────────────────────

    @classmethod
    def sqli_variants(cls, base_payload: str) -> list[str]:
        """SQLi 변이 — 인코딩, 문법 변이, 블라인드 기법."""
        variants: list[str] = []

        # 1. 원본 기반 인코딩 변이
        if base_payload:
            variants.append(base_payload)
            variants.append(cls._url_encode(base_payload))
            variants.append(cls._double_url_encode(base_payload))

        # 2. UNION 기반 변이
        union_bases = [
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT 1,2,3--",
            '" UNION SELECT 1,2,3--',
            "'/**/UNION/**/SELECT/**/1,2,3--",
            "' UNION%20SELECT%201,2,3--",
            "'%20UNION%20SELECT%201,2,3--",
            "'+UNION+SELECT+1,2,3--",
            "' UNION SELECT 1,2,3#",
            "' UNION SELECT 1,2,3;--",
        ]
        variants.extend(union_bases)

        # 3. OR 기반 변이 (인증 우회)
        or_variants = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            '" OR "1"="1',
            "' OR 'x'='x",
            "' OR 1=1/*",
            "') OR ('1'='1",
            "') OR (1=1)--",
            "'||'1'='1",
            "' OR 0x31=0x31--",
        ]
        variants.extend(or_variants)

        # 4. 블라인드 SQLi 변이
        blind_variants = [
            "' AND SLEEP(5)--",
            "' AND 1=IF(1=1,SLEEP(5),0)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND BENCHMARK(5000000,MD5('test'))--",
        ]
        variants.extend(blind_variants)

        # 5. 인코딩 우회 변이
        encoding_variants = [
            "%27 OR %271%27=%271",
            "%2527 OR 1=1--",
            "&#39; OR 1=1--",
            "0x27204f5220313d312d2d",  # hex
        ]
        variants.extend(encoding_variants)

        return variants[:50]  # count 제한

    # ── XSS 변이 ──────────────────────────────────────────────

    @classmethod
    def xss_variants(cls, base_payload: str) -> list[str]:
        """XSS 변이 — 컨텍스트별, 인코딩별."""
        variants: list[str] = []

        if base_payload:
            variants.append(base_payload)
            variants.append(cls._url_encode(base_payload))

        # 1. 태그 기반 변이
        tag_variants = [
            "<script>alert(1)</script>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script >alert(1)</script>",
            "<script\t>alert(1)</script>",
            "<script\n>alert(1)</script>",
            "<<script>alert(1)<</script>",
            "<script/src='data:,alert(1)'></script>",
        ]
        variants.extend(tag_variants)

        # 2. 이벤트 핸들러 변이
        event_variants = [
            "<img src=x onerror=alert(1)>",
            "<img src=x onerror='alert(1)'>",
            '<img src=x onerror="alert(1)">',
            "<img src=x OnErRoR=alert(1)>",
            "<body onload=alert(1)>",
            "<svg onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<select autofocus onfocus=alert(1)>",
            "<iframe onload=alert(1)>",
        ]
        variants.extend(event_variants)

        # 3. javascript: 프로토콜 변이
        js_proto_variants = [
            "javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            "java\tscript:alert(1)",
            "java\nscript:alert(1)",
            "&#106;avascript:alert(1)",
            "j&#97;vascript:alert(1)",
            "%6aavascript:alert(1)",
            "jav&#x61;script:alert(1)",
        ]
        variants.extend(js_proto_variants)

        # 4. 인코딩 변이
        encoding_variants = [
            "%3Cscript%3Ealert(1)%3C/script%3E",
            cls._double_url_encode("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;",
        ]
        variants.extend(encoding_variants)

        # 5. 속성 컨텍스트 탈출
        attr_variants = [
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)",
        ]
        variants.extend(attr_variants)

        return variants[:50]

    # ── SSRF 변이 ─────────────────────────────────────────────

    @classmethod
    def ssrf_variants(cls, base_payload: str) -> list[str]:
        """SSRF 변이 — IP 표현 방식, DNS, 프로토콜."""
        variants: list[str] = []

        if base_payload:
            variants.append(base_payload)

        # 1. localhost 변이
        localhost_variants = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://[::1]/",                    # IPv6
            "http://[0:0:0:0:0:0:0:1]/",
            "http://0177.0.0.1/",               # octal
            "http://2130706433/",               # decimal
            "http://0x7f000001/",               # hex
            "http://127.1/",                    # 단축
            "http://127.0.1/",
        ]
        variants.extend(localhost_variants)

        # 2. 메타데이터 서비스
        metadata_variants = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://metadata.google.internal/",
            "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
        ]
        variants.extend(metadata_variants)

        # 3. 내부 IP 범위
        internal_variants = [
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
            "http://192.168.0.1/",
        ]
        variants.extend(internal_variants)

        # 4. 프로토콜 변이
        protocol_variants = [
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "gopher://127.0.0.1:6379/_PING",
            "dict://127.0.0.1:11211/stats",
            "sftp://127.0.0.1/etc/passwd",
            "ldap://127.0.0.1/",
            "ftp://127.0.0.1/",
        ]
        variants.extend(protocol_variants)

        # 5. DNS rebinding / 우회
        dns_variants = [
            "http://localtest.me/",
            "http://127.0.0.1.nip.io/",
            "http://oob.example/",
        ]
        variants.extend(dns_variants)

        # 6. 인코딩 변이
        encoding_variants = [
            "http://127.0.0.1%2F",
            cls._url_encode("http://127.0.0.1/"),
            "http://127.0.0.1%23@evil.com/",
        ]
        variants.extend(encoding_variants)

        return variants[:50]

    # ── RCE 변이 ──────────────────────────────────────────────

    @classmethod
    def rce_variants(cls, base_payload: str) -> list[str]:
        """RCE 변이 — 쉘 메타문자, 인코딩, 기법."""
        variants: list[str] = []

        if base_payload:
            variants.append(base_payload)
            variants.append(cls._url_encode(base_payload))

        # 1. 세미콜론 구분자 변이
        semicolon_variants = [
            "; id",
            ";id",
            "; whoami",
            "; cat /etc/passwd",
            "; ls -la",
        ]
        variants.extend(semicolon_variants)

        # 2. 파이프 변이
        pipe_variants = [
            "| id",
            "|id",
            "|| id",
            "& id",
            "&& id",
        ]
        variants.extend(pipe_variants)

        # 3. 서브쉘 변이
        subshell_variants = [
            "$(id)",
            "`id`",
            "${IFS}id",
            "$((1))id",
            "$(cat /etc/passwd)",
        ]
        variants.extend(subshell_variants)

        # 4. 인코딩 변이
        encoding_variants = [
            "%3Bid",                    # ;id URL encoded
            "%7Cid",                    # |id URL encoded
            "%24(id)",                  # $(id) URL encoded
            "%60id%60",                 # `id` URL encoded
            cls._double_url_encode("; id"),
        ]
        variants.extend(encoding_variants)

        # 5. 공백 우회
        space_bypass_variants = [
            ";{IFS}id",
            ";$IFS$9id",
            ";<TAB>id",
            ";{id}",
        ]
        variants.extend(space_bypass_variants)

        # 6. Bash 고급 기법
        advanced_variants = [
            ";/bin/sh -c id",
            ";/bin/bash -c 'id'",
            ";python3 -c 'import os;os.system(\"id\")'",
            ";perl -e 'system(\"id\")'",
        ]
        variants.extend(advanced_variants)

        return variants[:50]

    # ── LFI 변이 ──────────────────────────────────────────────

    @classmethod
    def lfi_variants(cls, base_payload: str) -> list[str]:
        """LFI 변이 — 경로 순회, 인코딩."""
        variants: list[str] = []

        if base_payload:
            variants.append(base_payload)
            variants.append(cls._url_encode(base_payload))

        # 1. 기본 경로 순회
        traversal_variants = [
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "..\\etc\\passwd",
            "..\\..\\etc\\passwd",
        ]
        variants.extend(traversal_variants)

        # 2. URL 인코딩 변이
        url_encoded_variants = [
            "%2e%2e%2fetc%2fpasswd",
            "%2e%2e/%2e%2e/etc/passwd",
            "..%2fetc%2fpasswd",
            "..%252fetc%252fpasswd",    # double encoded
            "%252e%252e%252fetc/passwd",
        ]
        variants.extend(url_encoded_variants)

        # 3. NULL 바이트 / 필터 우회
        filter_bypass_variants = [
            "../etc/passwd%00",
            "../etc/passwd%00.jpg",
            "....//etc/passwd",         # 중복 점
            "..../etc/passwd",
            "....\\\\etc/passwd",
        ]
        variants.extend(filter_bypass_variants)

        # 4. 절대 경로
        absolute_variants = [
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "C:\\Windows\\system.ini",
            "C:\\boot.ini",
        ]
        variants.extend(absolute_variants)

        return variants[:50]

    # ── Generic 변이 ──────────────────────────────────────────

    @classmethod
    def generic_variants(cls, base_payload: str) -> list[str]:
        """알 수 없는 공격 유형에 대한 기본 변이."""
        if not base_payload:
            return []
        return [
            base_payload,
            cls._url_encode(base_payload),
            cls._double_url_encode(base_payload),
            base_payload.upper(),
            base_payload.lower(),
        ]


# ── WAF Rule Simulator ───────────────────────────────────────────

class _WafSimulator:
    """ModSecurity 규칙 정규식을 파싱하여 페이로드를 테스트한다."""

    # @rx 패턴 추출 정규식
    _RX_PATTERN = re.compile(r'@rx\s+([^\s"\\]+(?:\\.[^\s"\\]*)*)', re.IGNORECASE)
    # SecRule 내 "@rx" 외에 "content:" 등 Suricata 패턴도 간단 지원
    _CONTENT_PATTERN = re.compile(r'content:"([^"\\]+(?:\\.[^"\\]*)*)"', re.IGNORECASE)

    @classmethod
    def extract_patterns(cls, rule: str) -> list[re.Pattern[str]]:
        """WAF 규칙에서 정규식 패턴을 추출한다."""
        compiled: list[re.Pattern[str]] = []

        for match in cls._RX_PATTERN.finditer(rule):
            raw = match.group(1)
            try:
                compiled.append(re.compile(raw, re.IGNORECASE))
            except re.error as exc:
                logger.debug("규칙 파싱 실패 '%s': %s", raw[:60], exc)

        # Suricata content 문자열도 literal로 테스트
        for match in cls._CONTENT_PATTERN.finditer(rule):
            literal = match.group(1).replace('\\"', '"')
            try:
                compiled.append(re.compile(re.escape(literal), re.IGNORECASE))
            except re.error:
                pass

        return compiled

    @classmethod
    def test_payload(cls, patterns: list[re.Pattern[str]], payload: str) -> bool:
        """페이로드가 하나라도 패턴에 매칭되면 True (차단됨)."""
        if not patterns:
            # 패턴을 추출하지 못한 경우 — 차단 불가로 처리 (보수적)
            return False
        return any(p.search(payload) for p in patterns)


# ── Defense Simulator ────────────────────────────────────────────

class DefenseSimulator:
    """방어 옵션별 차단 효과를 공격 변이로 시뮬레이션한다.

    Usage:
        simulator = DefenseSimulator()
        variants = simulator.generate_attack_variants(exploit, count=50)
        results = await simulator.run_simulation(exploit, defense_options)
        print(simulator.format_simulation_report(results))
    """

    def generate_attack_variants(
        self,
        exploit: VerifiedExploit,
        count: int = 50,
    ) -> list[str]:
        """공격 유형별 변이 페이로드를 생성한다.

        Tier 0: 규칙 기반 변이 (항상)
        Tier 3: LLM 기반 창의적 변이 (가능한 경우, run_simulation 내에서)
        """
        attack = exploit.attack_type.lower()
        base_payload = exploit.payload or ""

        generators: dict[str, Any] = {
            "sqli": _VariantGenerators.sqli_variants,
            "sql_injection": _VariantGenerators.sqli_variants,
            "sql injection": _VariantGenerators.sqli_variants,
            "xss": _VariantGenerators.xss_variants,
            "cross-site scripting": _VariantGenerators.xss_variants,
            "ssrf": _VariantGenerators.ssrf_variants,
            "server-side request forgery": _VariantGenerators.ssrf_variants,
            "rce": _VariantGenerators.rce_variants,
            "remote code execution": _VariantGenerators.rce_variants,
            "command injection": _VariantGenerators.rce_variants,
            "lfi": _VariantGenerators.lfi_variants,
            "local file inclusion": _VariantGenerators.lfi_variants,
            "path traversal": _VariantGenerators.lfi_variants,
        }

        generator_fn = generators.get(attack, _VariantGenerators.generic_variants)
        variants = generator_fn(base_payload)

        # 중복 제거 및 count 제한
        seen: set[str] = set()
        unique_variants: list[str] = []
        for v in variants:
            if v and v not in seen:
                seen.add(v)
                unique_variants.append(v)
                if len(unique_variants) >= count:
                    break

        logger.info(
            "공격 변이 %d개 생성 (attack_type=%s)",
            len(unique_variants), attack,
        )
        return unique_variants

    async def _generate_llm_variants(
        self,
        exploit: VerifiedExploit,
        existing_variants: list[str],
        extra_count: int = 10,
    ) -> list[str]:
        """LLM으로 추가 창의적 변이 생성 (Tier 3)."""
        prompt = f"""\
다음 취약점에 대한 WAF 우회 페이로드 변이를 {extra_count}개 더 생성하라.

취약점 유형: {exploit.attack_type}
기존 페이로드: {exploit.payload[:200] if exploit.payload else '없음'}
이미 생성된 변이 예시:
{chr(10).join(existing_variants[:5])}

WAF 규칙을 우회할 수 있는 새로운 변이를 JSON 배열로 반환하라:
["페이로드1", "페이로드2", ...]
"""
        try:
            from vxis.llm.client import LLMClient
            client = LLMClient()
            response = await client.think(
                system="당신은 웹 보안 연구원입니다. WAF 우회 기법을 잘 알고 있습니다.",
                user=prompt,
                max_tokens=1000,
            )

            text = response.text
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]

            data = json.loads(text.strip())
            if isinstance(data, list):
                return [str(v) for v in data if v][:extra_count]

        except Exception as exc:
            logger.debug("LLM 변이 생성 실패: %s", exc)

        return []

    def simulate_waf(
        self,
        rule: str,
        variants: list[str],
        option_name: str = "WAF 규칙",
    ) -> SimulationResult:
        """ModSecurity/Suricata 규칙에 대해 변이별 차단 여부를 테스트한다."""
        patterns = _WafSimulator.extract_patterns(rule)

        blocked_count = 0
        bypassed_payloads: list[str] = []

        for variant in variants:
            if _WafSimulator.test_payload(patterns, variant):
                blocked_count += 1
            else:
                bypassed_payloads.append(variant)

        total = len(variants)
        bypassed_count = total - blocked_count
        bypass_rate = bypassed_count / total if total > 0 else 0.0

        return SimulationResult(
            defense_option_name=option_name,
            total_variants=total,
            blocked=blocked_count,
            bypassed=bypassed_count,
            bypass_rate=bypass_rate,
            bypassed_payloads=bypassed_payloads,
        )

    def _simulate_code_patch(
        self,
        exploit: VerifiedExploit,
        variants: list[str],
    ) -> SimulationResult:
        """정식 코드 패치 — 모든 변이 차단 (근본 해결)."""
        return SimulationResult(
            defense_option_name="정식 코드 패치",
            total_variants=len(variants),
            blocked=len(variants),
            bypassed=0,
            bypass_rate=0.0,
            bypassed_payloads=[],
        )

    def _simulate_network_isolation(
        self,
        exploit: VerifiedExploit,
        variants: list[str],
    ) -> SimulationResult:
        """네트워크 격리 — 외부 공격자의 90% 차단 (내부 공격자 제외)."""
        # 내부 IP 공격이나 인증 우회 시도는 격리로 차단 불가 모델링
        bypassed: list[str] = []
        for v in variants:
            # 내부망 공격 시뮬레이션: 페이로드 자체는 통과될 수 있음
            if any(internal in v for internal in ["127.0.0.1", "localhost", "::1", "10."]):
                bypassed.append(v)

        blocked_count = len(variants) - len(bypassed)
        bypass_rate = len(bypassed) / len(variants) if variants else 0.0

        return SimulationResult(
            defense_option_name="네트워크 격리",
            total_variants=len(variants),
            blocked=blocked_count,
            bypassed=len(bypassed),
            bypass_rate=bypass_rate,
            bypassed_payloads=bypassed,
        )

    def _simulate_honeypot(
        self,
        exploit: VerifiedExploit,
        variants: list[str],
    ) -> SimulationResult:
        """허니팟 — 공격 요청을 받아서 로깅하지만 실제 피해 없음.

        효과: 80% (정교한 공격자가 허니팟 탐지 시 우회 가능).
        """
        # 정교한 변이(인코딩 복잡) 중 일부는 허니팟도 우회 모델링
        bypassed: list[str] = []
        for v in variants:
            # double-encoded 변이는 허니팟 탐지 회피 가능
            if "%25" in v or "\\x" in v:
                bypassed.append(v)

        blocked_count = len(variants) - len(bypassed)
        bypass_rate = len(bypassed) / len(variants) if variants else 0.0

        return SimulationResult(
            defense_option_name="허니팟 전환",
            total_variants=len(variants),
            blocked=blocked_count,
            bypassed=len(bypassed),
            bypass_rate=bypass_rate,
            bypassed_payloads=bypassed,
        )

    async def run_simulation(
        self,
        exploit: VerifiedExploit,
        defense_options: list[DefenseOption],
    ) -> list[SimulationResult]:
        """모든 방어 옵션에 대해 시뮬레이션을 실행하고 효과 순으로 정렬한다."""
        logger.info("방어 시뮬레이션 시작: %d개 옵션", len(defense_options))

        # 1. 변이 생성 (Tier 0)
        variants = self.generate_attack_variants(exploit, count=50)

        # 2. LLM 추가 변이 (Tier 3 — 실패해도 계속)
        llm_variants = await self._generate_llm_variants(exploit, variants, extra_count=10)
        if llm_variants:
            seen = set(variants)
            for v in llm_variants:
                if v not in seen:
                    variants.append(v)
                    seen.add(v)
            logger.info("LLM 추가 변이 %d개 합산 → 총 %d개", len(llm_variants), len(variants))

        results: list[SimulationResult] = []

        for option in defense_options:
            category = option.category

            if category == "waf_rule":
                # WAF 규칙: ModSecurity 규칙 정규식으로 실제 테스트
                # DefenseOption에는 rule_content가 없으므로 red_vs_blue에서 생성
                rule = self._get_waf_rule_for_exploit(exploit)
                result = self.simulate_waf(rule, variants, option.name)

            elif category == "proper_patch":
                result = self._simulate_code_patch(exploit, variants)

            elif category == "isolation":
                result = self._simulate_network_isolation(exploit, variants)

            elif category == "honeypot":
                result = self._simulate_honeypot(exploit, variants)

            elif category == "architecture":
                # 아키텍처 변경도 근본 해결
                result = SimulationResult(
                    defense_option_name=option.name,
                    total_variants=len(variants),
                    blocked=len(variants),
                    bypassed=0,
                    bypass_rate=0.0,
                    bypassed_payloads=[],
                )

            else:
                # 알 수 없는 카테고리 — 기본 WAF로 테스트
                rule = self._get_waf_rule_for_exploit(exploit)
                result = self.simulate_waf(rule, variants, option.name)

            results.append(result)
            logger.debug(
                "시뮬레이션 결과 [%s]: %d/%d 차단 (우회율 %.1f%%)",
                option.name, result.blocked, result.total_variants,
                result.bypass_rate * 100,
            )

        # 차단율 내림차순 정렬
        results.sort(key=lambda r: r.block_rate, reverse=True)

        logger.info("시뮬레이션 완료: %d개 옵션 평가", len(results))
        return results

    def _get_waf_rule_for_exploit(self, exploit: VerifiedExploit) -> str:
        """익스플로잇 유형에 맞는 기본 WAF 규칙을 반환한다."""
        attack = exploit.attack_type.lower()

        waf_rules: dict[str, str] = {
            "sqli": (
                'SecRule ARGS|REQUEST_BODY "@rx '
                '(?i)(union\\s+select|or\\s+1\\s*=\\s*1|\\x27|--|%27|0x27)" '
                '"deny"'
            ),
            "sql_injection": (
                'SecRule ARGS "@rx (?i)(union\\s+select|or\\s+1\\s*=\\s*1|\\x27|--)" "deny"'
            ),
            "xss": (
                'SecRule ARGS "@rx (?i)(<script|javascript:|on\\w+\\s*=|onerror\\s*=)" '
                '"t:urlDecodeUni,t:htmlEntityDecode,deny"'
            ),
            "ssrf": (
                'SecRule ARGS "@rx '
                '(?i)(127\\.0\\.0\\.1|localhost|169\\.254\\.|10\\.|0x7f|2130706433|0177)" '
                '"deny"'
            ),
            "rce": (
                'SecRule ARGS "@rx (?i)(;|\\||\\$\\(|`|\\{\\{|/bin/|/etc/passwd)" "deny"'
            ),
            "command injection": (
                'SecRule ARGS "@rx (?i)(;|\\||\\$\\(|`|/bin/|passthru|system)" "deny"'
            ),
            "lfi": (
                'SecRule ARGS|REQUEST_URI "@rx (\\.\\./|%2e%2e|%252e|\\.\\.\\\\)" "deny"'
            ),
            "local file inclusion": (
                'SecRule ARGS "@rx (\\.\\./|%2e%2e|/etc/passwd|/proc/self)" "deny"'
            ),
        }

        return waf_rules.get(attack, 'SecRule ARGS "@rx (.+)" "deny"')

    def format_simulation_report(self, results: list[SimulationResult]) -> str:
        """시뮬레이션 결과를 마크다운 보고서로 출력한다."""
        if not results:
            return "## 시뮬레이션 결과 없음\n"

        total = results[0].total_variants if results else 0

        lines = [
            "## 방어 시뮬레이션 결과 보고서",
            "",
            f"**총 테스트 변이:** {total}개",
            f"**평가 옵션 수:** {len(results)}개",
            "",
            "### 차단율 순위",
            "",
            "| 순위 | 방어 옵션 | 차단 | 우회 | 차단율 | 상태 |",
            "|------|-----------|------|------|--------|------|",
        ]

        for i, r in enumerate(results, 1):
            lines.append(
                f"| {i} | {r.defense_option_name} "
                f"| {r.blocked} "
                f"| {r.bypassed} "
                f"| {r.block_pct} "
                f"| {r.status_emoji} |"
            )

        lines.append("")
        lines.append("---")
        lines.append("")

        for r in results:
            lines.append(f"### {r.status_emoji} {r.defense_option_name}")
            lines.append(f"- **차단:** {r.blocked}/{r.total_variants} ({r.block_pct})")
            lines.append(f"- **우회:** {r.bypassed}개")

            if r.bypassed_payloads:
                lines.append("")
                lines.append("**우회된 페이로드 (상위 5개):**")
                for payload in r.bypassed_payloads[:5]:
                    # 마크다운 코드 블록 안전 처리
                    safe_payload = payload.replace("`", "'")
                    lines.append(f"```\n{safe_payload}\n```")

            lines.append("")

        # 추천 옵션
        if results:
            best = results[0]
            lines.append("---")
            lines.append(f"**권장 옵션:** {best.status_emoji} **{best.defense_option_name}**")
            lines.append(f"- {best.block_pct} 차단율로 가장 효과적")
            if best.bypassed > 0:
                lines.append(
                    f"- 단, {best.bypassed}개 변이가 우회 가능하므로 "
                    f"추가 레이어 방어를 권장합니다."
                )
            else:
                lines.append("- 모든 테스트 변이를 완전 차단합니다.")

        lines.append("")
        lines.append("---")
        lines.append("_VXIS Defense Simulator — 실제 인프라 변경 없이 시뮬레이션된 결과입니다._")

        return "\n".join(lines)
