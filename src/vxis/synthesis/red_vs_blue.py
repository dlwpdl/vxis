"""Red vs Blue Co-Intelligence — PoC 검증된 공격에 대한 방어 대응 자동 생성.

호출 조건: PoC가 완전히 검증된 경우에만 (디폴트 실행 아님)
호출 방법:
    1. CLI: vxis defend --finding <id>
    2. Agent: Director가 exploit_confirmed=True일 때 수동 호출
    3. API: BlueTeamResponder.respond(verified_exploit)

생성하는 것:
    1. WAF 규칙 (ModSecurity / AWS WAF / Cloudflare)
    2. IDS/IPS 시그니처 (Suricata / Snort)
    3. SIEM 탐지 쿼리 (Splunk SPL / Elastic KQL)
    4. 패치/설정 변경 권고
    5. 모니터링 대시보드 쿼리
    6. 임시 완화 조치 (hotfix)

Architecture:
    ┌─────────────────────────────────────────┐
    │  BlueTeamResponder                       │
    │                                         │
    │  입력: VerifiedExploit (PoC 검증 완료)    │
    │                                         │
    │  ┌───────────┐ ┌──────────┐ ┌────────┐ │
    │  │ WAF Rules │ │ IDS Sig  │ │ SIEM   │ │
    │  │ Generator │ │ Generator│ │ Query  │ │
    │  └─────┬─────┘ └────┬─────┘ └───┬────┘ │
    │        └─────────┬───┘           │      │
    │                  ▼               │      │
    │        ┌─────────────────┐       │      │
    │        │ Patch Advisor   │◄──────┘      │
    │        │ (LLM 기반)      │              │
    │        └────────┬────────┘              │
    │                 ▼                       │
    │        ┌─────────────────┐              │
    │        │ Defense Report  │              │
    │        │ (통합 보고서)    │              │
    │        └─────────────────┘              │
    └─────────────────────────────────────────┘
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path("~/.vxis/defense").expanduser()


# ── Data Models ─────────────────────────────────────────────────

@dataclass
class VerifiedExploit:
    """PoC가 검증된 공격 — Blue 대응의 입력."""

    finding_id: str
    title: str
    severity: str  # critical, high, medium
    attack_type: str  # sqli, xss, ssrf, rce, lfi, etc.
    target: str
    affected_component: str  # URL path, port, service
    request: str = ""  # 공격에 사용된 HTTP 요청
    response: str = ""  # 서버 응답 (취약점 확인)
    payload: str = ""  # 사용된 페이로드
    cve_id: str = ""
    description: str = ""
    chain_context: str = ""  # 체인 공격의 일부인 경우 컨텍스트


@dataclass
class DefenseRule:
    """생성된 방어 규칙 하나."""

    rule_type: str  # waf, ids, siem, patch, monitoring, hotfix
    platform: str  # modsecurity, aws_waf, cloudflare, suricata, snort, splunk, elastic
    rule_content: str
    description: str
    confidence: float = 0.9  # 규칙의 정확도 (false positive 가능성)
    false_positive_risk: str = "low"  # low, medium, high


@dataclass
class DefenseReport:
    """통합 방어 보고서."""

    exploit: VerifiedExploit
    rules: list[DefenseRule] = field(default_factory=list)
    patch_recommendation: str = ""
    hotfix_steps: list[str] = field(default_factory=list)
    monitoring_queries: list[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_markdown(self) -> str:
        """마크다운 보고서 생성."""
        lines = [
            f"# 🛡️ Blue Team 방어 대응 보고서",
            f"**생성 시각:** {self.generated_at}",
            f"**대상:** {self.exploit.target}",
            f"**취약점:** {self.exploit.title}",
            f"**심각도:** {self.exploit.severity.upper()}",
            f"**공격 유형:** {self.exploit.attack_type}",
            "",
        ]

        if self.exploit.cve_id:
            lines.append(f"**CVE:** {self.exploit.cve_id}\n")

        # WAF Rules
        waf_rules = [r for r in self.rules if r.rule_type == "waf"]
        if waf_rules:
            lines.append("## 🔥 WAF 규칙\n")
            for rule in waf_rules:
                lines.append(f"### {rule.platform}\n")
                lines.append(f"_{rule.description}_\n")
                lines.append(f"```\n{rule.rule_content}\n```\n")
                lines.append(f"FP 위험: {rule.false_positive_risk}\n")

        # IDS/IPS Signatures
        ids_rules = [r for r in self.rules if r.rule_type == "ids"]
        if ids_rules:
            lines.append("## 🚨 IDS/IPS 시그니처\n")
            for rule in ids_rules:
                lines.append(f"### {rule.platform}\n")
                lines.append(f"```\n{rule.rule_content}\n```\n")

        # SIEM Queries
        siem_rules = [r for r in self.rules if r.rule_type == "siem"]
        if siem_rules:
            lines.append("## 📊 SIEM 탐지 쿼리\n")
            for rule in siem_rules:
                lines.append(f"### {rule.platform}\n")
                lines.append(f"```\n{rule.rule_content}\n```\n")

        # Patch
        if self.patch_recommendation:
            lines.append("## 🔧 패치 권고\n")
            lines.append(self.patch_recommendation + "\n")

        # Hotfix
        if self.hotfix_steps:
            lines.append("## ⚡ 임시 완화 조치\n")
            for i, step in enumerate(self.hotfix_steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        # Monitoring
        if self.monitoring_queries:
            lines.append("## 👁️ 모니터링 쿼리\n")
            for q in self.monitoring_queries:
                lines.append(f"```\n{q}\n```\n")

        lines.append("---")
        lines.append("_이 보고서는 VXIS Red vs Blue Co-Intelligence에 의해 자동 생성되었습니다._")

        return "\n".join(lines)


# ── Blue Team Responder ─────────────────────────────────────────

class BlueTeamResponder:
    """PoC 검증된 공격에 대한 방어 대응을 자동 생성한다.

    디폴트 실행 아님 — 명시적으로 호출해야 함.

    Usage:
        responder = BlueTeamResponder()
        report = await responder.respond(verified_exploit)
        print(report.to_markdown())
    """

    async def respond(self, exploit: VerifiedExploit) -> DefenseReport:
        """검증된 공격에 대한 전체 방어 대응을 생성한다."""
        logger.info(
            "Blue Team 대응 시작: %s (%s)",
            exploit.title, exploit.attack_type,
        )

        report = DefenseReport(exploit=exploit)

        # Phase 1: 규칙 기반 방어 생성 (Tier 0 — LLM 불필요)
        report.rules.extend(self._generate_waf_rules(exploit))
        report.rules.extend(self._generate_ids_signatures(exploit))
        report.rules.extend(self._generate_siem_queries(exploit))

        # Phase 2: LLM 기반 패치 권고 + 핫픽스 (Tier 3)
        patch_and_hotfix = await self._generate_patch_recommendation(exploit)
        report.patch_recommendation = patch_and_hotfix.get("patch", "")
        report.hotfix_steps = patch_and_hotfix.get("hotfix_steps", [])
        report.monitoring_queries = patch_and_hotfix.get("monitoring", [])

        # Save report
        self._save_report(report)

        logger.info(
            "Blue Team 대응 완료: %d개 규칙, 패치 권고 %d자",
            len(report.rules),
            len(report.patch_recommendation),
        )

        return report

    # ── WAF Rules (Tier 0 — 규칙 기반) ─────────────────────────

    def _generate_waf_rules(self, exploit: VerifiedExploit) -> list[DefenseRule]:
        """공격 유형별 WAF 규칙 생성."""
        rules = []
        attack = exploit.attack_type.lower()
        payload = _escape_for_regex(exploit.payload) if exploit.payload else ""
        path = exploit.affected_component or "/"

        # ModSecurity
        if attack in ("sqli", "sql_injection", "sql injection"):
            rules.append(DefenseRule(
                rule_type="waf",
                platform="ModSecurity",
                rule_content=(
                    f'SecRule REQUEST_URI "{_escape_modsec(path)}" \\\n'
                    f'  "id:100001,phase:2,deny,status:403,\\\n'
                    f'  msg:\'VXIS: SQLi blocked on {path}\',\\\n'
                    f'  chain"\n'
                    f'SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx '
                    f'(?i)(union\\s+select|or\\s+1\\s*=\\s*1|\\x27|--)" \\\n'
                    f'  "t:none,t:urlDecodeUni"'
                ),
                description=f"SQL Injection 차단 — {path}",
                false_positive_risk="low",
            ))

        elif attack in ("xss", "cross-site scripting"):
            rules.append(DefenseRule(
                rule_type="waf",
                platform="ModSecurity",
                rule_content=(
                    f'SecRule REQUEST_URI "{_escape_modsec(path)}" \\\n'
                    f'  "id:100002,phase:2,deny,status:403,\\\n'
                    f'  msg:\'VXIS: XSS blocked on {path}\',\\\n'
                    f'  chain"\n'
                    f'SecRule ARGS|REQUEST_BODY "@rx (?i)(<script|javascript:|on\\w+\\s*=)" \\\n'
                    f'  "t:none,t:urlDecodeUni,t:htmlEntityDecode"'
                ),
                description=f"XSS 차단 — {path}",
                false_positive_risk="medium",
            ))

        elif attack in ("ssrf", "server-side request forgery"):
            rules.append(DefenseRule(
                rule_type="waf",
                platform="ModSecurity",
                rule_content=(
                    f'SecRule ARGS|REQUEST_BODY "@rx '
                    f'(?i)(127\\.0\\.0\\.1|localhost|169\\.254\\.|10\\.|172\\.(1[6-9]|2|3[01])\\.|192\\.168\\.)" \\\n'
                    f'  "id:100003,phase:2,deny,status:403,\\\n'
                    f'  msg:\'VXIS: SSRF blocked — internal IP detected\'"'
                ),
                description="SSRF 차단 — 내부 IP 접근 방지",
                false_positive_risk="low",
            ))

        elif attack in ("rce", "remote code execution", "command injection"):
            rules.append(DefenseRule(
                rule_type="waf",
                platform="ModSecurity",
                rule_content=(
                    f'SecRule ARGS|REQUEST_BODY "@rx '
                    f'(?i)(;|\\||\\$\\(|`|\\{{\\{{|exec|system|passthru|popen)" \\\n'
                    f'  "id:100004,phase:2,deny,status:403,\\\n'
                    f'  msg:\'VXIS: Command Injection blocked\'"'
                ),
                description="RCE/Command Injection 차단",
                false_positive_risk="medium",
            ))

        elif attack in ("lfi", "local file inclusion", "path traversal"):
            rules.append(DefenseRule(
                rule_type="waf",
                platform="ModSecurity",
                rule_content=(
                    f'SecRule ARGS|REQUEST_URI "@rx (\\.\\./|\\.\\.\\\\|%2e%2e)" \\\n'
                    f'  "id:100005,phase:2,deny,status:403,\\\n'
                    f'  msg:\'VXIS: Path Traversal blocked\'"'
                ),
                description="LFI/Path Traversal 차단",
                false_positive_risk="low",
            ))

        # AWS WAF (JSON format)
        if payload:
            rules.append(DefenseRule(
                rule_type="waf",
                platform="AWS WAF",
                rule_content=json.dumps({
                    "Name": f"VXIS-Block-{attack.upper()}-{exploit.finding_id[:8]}",
                    "Priority": 1,
                    "Action": {"Block": {}},
                    "Statement": {
                        "RegexPatternSetReferenceStatement": {
                            "ARN": "arn:aws:wafv2:REGION:ACCOUNT:regional/regexpatternset/VXIS-Patterns/ID",
                            "FieldToMatch": {"Body": {}},
                            "TextTransformations": [
                                {"Priority": 0, "Type": "URL_DECODE"},
                                {"Priority": 1, "Type": "HTML_ENTITY_DECODE"},
                            ],
                        }
                    },
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": f"VXIS-{attack}",
                    },
                }, indent=2),
                description=f"AWS WAF 규칙 — {attack} 차단",
                false_positive_risk="low",
            ))

        return rules

    # ── IDS Signatures (Tier 0) ─────────────────────────────────

    def _generate_ids_signatures(self, exploit: VerifiedExploit) -> list[DefenseRule]:
        """Suricata/Snort IDS 시그니처 생성."""
        rules = []
        attack = exploit.attack_type.lower()
        target_host = exploit.target.replace("https://", "").replace("http://", "").split("/")[0]

        sid_base = 9000000 + hash(exploit.finding_id) % 100000

        # Suricata rule
        if exploit.payload:
            escaped_payload = exploit.payload[:100].replace('"', '\\"')
            rules.append(DefenseRule(
                rule_type="ids",
                platform="Suricata",
                rule_content=(
                    f'alert http any any -> $HOME_NET any (\\\n'
                    f'  msg:"VXIS: {attack.upper()} attempt on {target_host}";\\\n'
                    f'  flow:established,to_server;\\\n'
                    f'  content:"{escaped_payload}";\\\n'
                    f'  sid:{sid_base}; rev:1;\\\n'
                    f'  classtype:web-application-attack;\\\n'
                    f'  metadata:affected_host {target_host}, attack_type {attack};\\\n'
                    f')'
                ),
                description=f"Suricata 탐지 규칙 — {attack} on {target_host}",
            ))

        return rules

    # ── SIEM Queries (Tier 0) ───────────────────────────────────

    def _generate_siem_queries(self, exploit: VerifiedExploit) -> list[DefenseRule]:
        """SIEM 탐지 쿼리 생성."""
        rules = []
        attack = exploit.attack_type.lower()
        target_host = exploit.target.replace("https://", "").replace("http://", "").split("/")[0]
        path = exploit.affected_component or "*"

        # Splunk SPL
        splunk_patterns = {
            "sqli": 'sourcetype=access_* uri_path="*{path}*" (uri_query="*union*select*" OR uri_query="*or+1=1*" OR uri_query="*%27*")',
            "xss": 'sourcetype=access_* uri_path="*{path}*" (uri_query="*<script*" OR uri_query="*javascript:*" OR uri_query="*onerror=*")',
            "ssrf": 'sourcetype=access_* (uri_query="*127.0.0.1*" OR uri_query="*localhost*" OR uri_query="*169.254*")',
            "rce": 'sourcetype=access_* (uri_query="*;*" OR uri_query="*|*" OR uri_query="*$(* OR uri_query="*`*")',
            "lfi": 'sourcetype=access_* (uri_query="*../*" OR uri_query="*%2e%2e*")',
        }

        pattern = splunk_patterns.get(attack, "")
        if pattern:
            rules.append(DefenseRule(
                rule_type="siem",
                platform="Splunk SPL",
                rule_content=(
                    f'index=web host="{target_host}" {pattern.format(path=path)}\n'
                    f'| stats count by src_ip, uri_path, uri_query\n'
                    f'| where count > 5\n'
                    f'| sort -count'
                ),
                description=f"Splunk 탐지 쿼리 — {attack} 시도 모니터링",
            ))

        # Elastic KQL
        elastic_patterns = {
            "sqli": f'url.path:"{path}" AND (url.query:*union* OR url.query:*select* OR url.query:*%27*)',
            "xss": f'url.path:"{path}" AND (url.query:*script* OR url.query:*javascript* OR url.query:*onerror*)',
            "ssrf": 'url.query:(*127.0.0.1* OR *localhost* OR *169.254*)',
            "rce": 'url.query:(*%3B* OR *%7C* OR *%24%28* OR *%60*)',
            "lfi": 'url.query:(*..%2F* OR *%2e%2e*)',
        }

        elastic_q = elastic_patterns.get(attack, "")
        if elastic_q:
            rules.append(DefenseRule(
                rule_type="siem",
                platform="Elastic KQL",
                rule_content=(
                    f'host.name:"{target_host}" AND {elastic_q}'
                ),
                description=f"Elastic 탐지 쿼리 — {attack} 모니터링",
            ))

        return rules

    # ── Patch Recommendation (Tier 3 — LLM) ─────────────────────

    async def _generate_patch_recommendation(
        self, exploit: VerifiedExploit,
    ) -> dict[str, Any]:
        """LLM을 사용하여 구체적인 패치 권고를 생성한다."""
        prompt = f"""\
검증된 취약점에 대한 방어 대응을 생성하라.

취약점 정보:
- 제목: {exploit.title}
- 유형: {exploit.attack_type}
- 심각도: {exploit.severity}
- 대상: {exploit.target}
- 영향 컴포넌트: {exploit.affected_component}
- CVE: {exploit.cve_id or '없음'}
- 설명: {exploit.description[:500]}

공격 요청:
{exploit.request[:500] if exploit.request else '없음'}

페이로드:
{exploit.payload[:300] if exploit.payload else '없음'}

다음을 JSON으로 생성하라:
{{
  "patch": "구체적인 코드/설정 수정 권고 (한국어, 상세하게)",
  "hotfix_steps": ["임시 완화 조치 1", "임시 완화 조치 2", ...],
  "monitoring": ["모니터링 쿼리/명령 1", "모니터링 쿼리 2"]
}}
"""

        try:
            from vxis.llm.client import LLMClient
            client = LLMClient()
            response = await client.think(
                system="당신은 시니어 보안 엔지니어입니다. 검증된 취약점에 대한 구체적인 방어 대응을 생성합니다.",
                user=prompt,
                max_tokens=2000,
            )

            text = response.text
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]

            return json.loads(text.strip())

        except Exception as exc:
            logger.warning("LLM 패치 권고 생성 실패: %s", exc)
            return {
                "patch": f"{exploit.attack_type} 취약점에 대한 표준 보안 가이드라인을 따르세요.",
                "hotfix_steps": [
                    f"WAF에서 {exploit.affected_component} 경로에 대한 필터링 규칙을 추가하세요",
                    "영향받는 서비스의 접근 로그를 즉시 검토하세요",
                    "필요 시 영향받는 엔드포인트를 임시 비활성화하세요",
                ],
                "monitoring": [],
            }

    # ── Save ────────────────────────────────────────────────────

    def _save_report(self, report: DefenseReport) -> Path:
        """보고서를 파일로 저장."""
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        safe_id = report.exploit.finding_id.replace("/", "_")[:30]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"defense_{safe_id}_{timestamp}.md"
        path = OUTPUT_DIR / filename

        path.write_text(report.to_markdown(), encoding="utf-8")
        logger.info("방어 보고서 저장: %s", path)

        # JSON도 저장
        json_path = path.with_suffix(".json")
        json_data = {
            "exploit": {
                "finding_id": report.exploit.finding_id,
                "title": report.exploit.title,
                "severity": report.exploit.severity,
                "attack_type": report.exploit.attack_type,
                "target": report.exploit.target,
                "cve_id": report.exploit.cve_id,
            },
            "rules_count": len(report.rules),
            "rules": [
                {
                    "type": r.rule_type,
                    "platform": r.platform,
                    "content": r.rule_content,
                    "fp_risk": r.false_positive_risk,
                }
                for r in report.rules
            ],
            "generated_at": report.generated_at,
        }
        json_path.write_text(
            json.dumps(json_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        return path


# ── Helpers ─────────────────────────────────────────────────────

def _escape_for_regex(text: str) -> str:
    """정규식 메타문자 이스케이프."""
    return re.sub(r'([.+*?^${}()|[\]\\])', r'\\\1', text)


def _escape_modsec(text: str) -> str:
    """ModSecurity 규칙용 이스케이프."""
    return text.replace('"', '\\"').replace("'", "\\'")
