"""VXIS Context Compressor — 도구 출력을 LLM 프롬프트용으로 압축.

Raw 도구 출력 (수천 토큰) → 구조화된 요약 (수십 토큰)
90%+ 토큰 절약, 핵심 정보 보존.

Architecture:
    Raw Output → Parser → Extractor → Compressor → Structured Summary

    nmap raw (500줄) → {"open": {"80": "nginx 1.18.0"}, "interesting": [...]}
    nuclei raw (200줄) → {"critical": 1, "high": 3, "findings": [...]}
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CompressedOutput:
    """도구 출력의 압축된 표현."""

    tool: str
    summary: str  # 한 줄 요약
    structured: dict[str, Any]  # 구조화된 데이터
    interesting: list[str]  # Brain이 주목해야 할 것
    token_estimate: int = 0  # 추정 토큰 수

    @property
    def as_prompt(self) -> str:
        """LLM 프롬프트에 삽입할 수 있는 문자열로 변환."""
        lines = [f"[{self.tool}] {self.summary}"]
        if self.interesting:
            lines.append("  주목: " + "; ".join(self.interesting))
        return "\n".join(lines)


class ContextCompressor:
    """도구 출력을 LLM 컨텍스트용으로 압축하는 엔진.

    Usage:
        compressor = ContextCompressor()
        compressed = compressor.compress("nmap", raw_output)
        prompt_text = compressed.as_prompt  # 토큰 90% 절약
    """

    def compress(
        self,
        tool: str,
        raw_output: str,
        max_tokens: int = 200,
    ) -> CompressedOutput:
        """도구별 전문 파서로 출력을 압축한다.

        Args:
            tool: 도구 이름
            raw_output: 원본 출력 문자열
            max_tokens: 최대 토큰 수 (초과 시 추가 자름)

        Returns:
            CompressedOutput 인스턴스
        """
        parser = self._get_parser(tool)
        result = parser(raw_output)
        result.tool = tool
        result.token_estimate = self._estimate_tokens(result.as_prompt)

        # 토큰 한도 초과 시 추가 자름
        if result.token_estimate > max_tokens:
            result = self._truncate(result, max_tokens)

        return result

    def compress_batch(
        self,
        outputs: list[tuple[str, str]],
        total_max_tokens: int = 800,
    ) -> str:
        """여러 도구 출력을 일괄 압축하여 하나의 프롬프트로 생성.

        Args:
            outputs: (tool_name, raw_output) 튜플 리스트
            total_max_tokens: 전체 최대 토큰 수

        Returns:
            합쳐진 프롬프트 문자열
        """
        per_tool = max(100, total_max_tokens // max(len(outputs), 1))
        compressed = [
            self.compress(tool, raw, max_tokens=per_tool)
            for tool, raw in outputs
        ]
        return "\n".join(c.as_prompt for c in compressed)

    # ── Tool-specific parsers ────────────────────────────────────

    def _get_parser(self, tool: str):
        """도구별 전문 파서를 반환한다."""
        parsers = {
            "nmap": self._parse_nmap,
            "nuclei": self._parse_nuclei,
            "httpx": self._parse_httpx,
            "ffuf": self._parse_ffuf,
            "testssl": self._parse_testssl,
            "subfinder": self._parse_subdomain_tool,
            "crtsh": self._parse_subdomain_tool,
            "sqlmap": self._parse_sqlmap,
            "wafw00f": self._parse_wafw00f,
            "checkdmarc": self._parse_checkdmarc,
            "trufflehog": self._parse_secrets_tool,
            "gitleaks": self._parse_secrets_tool,
            "sslyze": self._parse_sslyze,
        }
        return parsers.get(tool, self._parse_generic)

    def _parse_nmap(self, raw: str) -> CompressedOutput:
        """nmap 출력을 구조화된 포트/서비스 맵으로 압축."""
        open_ports: dict[str, dict[str, str]] = {}
        interesting: list[str] = []
        host_up = False

        for line in raw.splitlines():
            line = line.strip()

            if "Host is up" in line:
                host_up = True

            # 포트 라인 파싱: "80/tcp open http nginx 1.18.0"
            port_match = re.match(
                r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)",
                line,
            )
            if port_match:
                port, proto, state, service, version = port_match.groups()
                version = version.strip()[:40]
                open_ports[port] = {
                    "proto": proto,
                    "state": state,
                    "service": service,
                    "version": version,
                }

                # 흥미로운 포트 식별
                if service == "unknown" or state == "filtered":
                    interesting.append(f"port {port}: {state} {service}")
                if "ssl/unknown" in line.lower():
                    interesting.append(f"port {port}: SSL unknown service")

            # OS 탐지
            if line.startswith("OS details:"):
                interesting.append(line[:80])

            # 스크립트 결과 중 중요한 것
            if any(
                kw in line.lower()
                for kw in ["vulnerable", "anonymous", "no auth", "default"]
            ):
                interesting.append(line[:80])

        summary = f"{len(open_ports)} ports open" if open_ports else "no open ports"
        if not host_up:
            summary = "host down or filtered"

        return CompressedOutput(
            tool="nmap",
            summary=summary,
            structured={"ports": open_ports},
            interesting=interesting[:5],
        )

    def _parse_nuclei(self, raw: str) -> CompressedOutput:
        """nuclei 출력을 심각도별 요약으로 압축."""
        severity_counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        findings: list[dict[str, str]] = []
        interesting: list[str] = []

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue

            # nuclei 출력 형식: [template-id] [protocol] [severity] url
            for sev in severity_counts:
                if f"[{sev}]" in line.lower():
                    severity_counts[sev] += 1

                    # template ID 추출
                    template_match = re.search(r"\[([^\]]+)\]", line)
                    template_id = template_match.group(1) if template_match else "unknown"

                    finding = {"severity": sev, "template": template_id}
                    findings.append(finding)

                    if sev in ("critical", "high"):
                        interesting.append(f"{sev.upper()}: {template_id}")
                    break

        total = sum(severity_counts.values())
        summary = (
            f"{total} findings ("
            f"C:{severity_counts['critical']} "
            f"H:{severity_counts['high']} "
            f"M:{severity_counts['medium']} "
            f"L:{severity_counts['low']})"
        )

        return CompressedOutput(
            tool="nuclei",
            summary=summary,
            structured={
                "severity_counts": severity_counts,
                "findings": findings[:10],
            },
            interesting=interesting[:5],
        )

    def _parse_httpx(self, raw: str) -> CompressedOutput:
        """httpx 출력을 라이브 호스트 + 기술 스택으로 압축."""
        live_hosts: list[dict[str, str]] = []
        tech_stack: set[str] = set()
        interesting: list[str] = []

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                host_info = {
                    "url": data.get("url", ""),
                    "status": str(data.get("status_code", "")),
                    "title": data.get("title", "")[:50],
                }
                live_hosts.append(host_info)

                # 기술 스택 추출
                for tech in data.get("tech", []):
                    tech_stack.add(tech)

                # 흥미로운 헤더
                if data.get("status_code") in (401, 403, 500, 502):
                    interesting.append(
                        f"{data.get('url', '')}: HTTP {data.get('status_code')}"
                    )
            except (json.JSONDecodeError, TypeError):
                # JSON이 아닌 라인은 URL만 추출
                if line.startswith("http"):
                    live_hosts.append({"url": line, "status": "", "title": ""})

        summary = f"{len(live_hosts)} live hosts, tech: {', '.join(sorted(tech_stack)[:5])}"

        return CompressedOutput(
            tool="httpx",
            summary=summary,
            structured={
                "hosts": live_hosts[:20],
                "tech_stack": sorted(tech_stack),
            },
            interesting=interesting[:5],
        )

    def _parse_ffuf(self, raw: str) -> CompressedOutput:
        """ffuf 출력을 발견된 경로로 압축."""
        paths: list[dict[str, Any]] = []
        interesting: list[str] = []

        try:
            data = json.loads(raw)
            for result in data.get("results", []):
                path_info = {
                    "url": result.get("url", ""),
                    "status": result.get("status", 0),
                    "length": result.get("length", 0),
                }
                paths.append(path_info)

                if result.get("status") in (200, 301, 302):
                    url_path = result.get("url", "").split("/")[-1]
                    interesting.append(f"/{url_path} ({result.get('status')})")
        except (json.JSONDecodeError, TypeError):
            for line in raw.splitlines():
                if any(
                    code in line
                    for code in ["200", "301", "302", "403"]
                ):
                    paths.append({"raw": line.strip()[:80]})

        summary = f"{len(paths)} paths discovered"

        return CompressedOutput(
            tool="ffuf",
            summary=summary,
            structured={"paths": paths[:15]},
            interesting=interesting[:5],
        )

    def _parse_testssl(self, raw: str) -> CompressedOutput:
        """testssl 출력을 TLS 취약점 요약으로 압축."""
        vulns: list[str] = []
        interesting: list[str] = []
        protocol_issues: list[str] = []

        vuln_keywords = [
            "vulnerable", "not ok", "warn", "medium", "high",
            "critical", "heartbleed", "robot", "beast", "poodle",
            "freak", "logjam", "drown", "sweet32", "lucky13",
        ]

        for line in raw.splitlines():
            line_lower = line.strip().lower()
            if any(kw in line_lower for kw in vuln_keywords):
                cleaned = line.strip()[:80]
                vulns.append(cleaned)
                if any(
                    kw in line_lower
                    for kw in ["vulnerable", "critical", "high"]
                ):
                    interesting.append(cleaned)

            if any(
                proto in line_lower
                for proto in ["sslv2", "sslv3", "tls1.0", "tls 1.0"]
            ):
                protocol_issues.append(line.strip()[:60])

        summary = f"{len(vulns)} TLS issues"
        if protocol_issues:
            summary += f", weak protocols: {len(protocol_issues)}"

        return CompressedOutput(
            tool="testssl",
            summary=summary,
            structured={
                "vulnerabilities": vulns[:10],
                "protocol_issues": protocol_issues[:5],
            },
            interesting=interesting[:5],
        )

    def _parse_subdomain_tool(self, raw: str) -> CompressedOutput:
        """subfinder/crtsh 출력을 서브도메인 리스트로 압축."""
        subdomains = set()
        for line in raw.splitlines():
            line = line.strip()
            if line and "." in line and not line.startswith("#"):
                # 기본적인 도메인 형식 검증
                if re.match(r"^[\w\.\-]+\.\w{2,}$", line):
                    subdomains.add(line.lower())

        interesting = []
        for sub in subdomains:
            if any(
                kw in sub
                for kw in [
                    "admin", "dev", "staging", "test", "api",
                    "internal", "vpn", "jenkins", "gitlab",
                ]
            ):
                interesting.append(sub)

        summary = f"{len(subdomains)} subdomains"

        return CompressedOutput(
            tool="subfinder",
            summary=summary,
            structured={"subdomains": sorted(subdomains)[:50]},
            interesting=interesting[:10],
        )

    def _parse_sqlmap(self, raw: str) -> CompressedOutput:
        """sqlmap 출력을 SQLi 결과로 압축."""
        injectable = "injectable" in raw.lower()
        interesting = []

        if injectable:
            interesting.append("SQL INJECTION CONFIRMED")

            # 주입 유형 추출
            for injection_type in [
                "boolean-based", "time-based", "union-based",
                "error-based", "stacked queries",
            ]:
                if injection_type in raw.lower():
                    interesting.append(f"Type: {injection_type}")

        # DB 정보 추출
        db_match = re.search(r"back-end DBMS:\s*(.+)", raw)
        if db_match:
            interesting.append(f"DBMS: {db_match.group(1).strip()}")

        summary = "INJECTABLE!" if injectable else "no injection found"

        return CompressedOutput(
            tool="sqlmap",
            summary=summary,
            structured={"injectable": injectable},
            interesting=interesting[:5],
        )

    def _parse_wafw00f(self, raw: str) -> CompressedOutput:
        """wafw00f 출력을 WAF 탐지 결과로 압축."""
        waf_detected = None
        interesting = []

        for line in raw.splitlines():
            if "is behind" in line.lower():
                waf_match = re.search(r"is behind\s+(.+)", line, re.IGNORECASE)
                if waf_match:
                    waf_detected = waf_match.group(1).strip()
                    interesting.append(f"WAF: {waf_detected}")
            elif "no waf" in line.lower():
                interesting.append("No WAF detected — direct attack possible")

        summary = f"WAF: {waf_detected}" if waf_detected else "No WAF"

        return CompressedOutput(
            tool="wafw00f",
            summary=summary,
            structured={"waf": waf_detected},
            interesting=interesting[:3],
        )

    def _parse_checkdmarc(self, raw: str) -> CompressedOutput:
        """checkdmarc 출력을 이메일 보안 요약으로 압축."""
        issues = []
        interesting = []

        checks = {
            "spf": "not found" if "no spf" in raw.lower() else "ok",
            "dmarc": "not found" if "no dmarc" in raw.lower() else "ok",
            "dkim": "not found" if "no dkim" in raw.lower() else "ok",
        }

        for check, status in checks.items():
            if status == "not found":
                issues.append(f"{check.upper()} missing")
                interesting.append(f"{check.upper()} not configured — spoofing possible")

        summary = f"Email security: {len(issues)} issues" if issues else "Email security: OK"

        return CompressedOutput(
            tool="checkdmarc",
            summary=summary,
            structured=checks,
            interesting=interesting[:3],
        )

    def _parse_secrets_tool(self, raw: str) -> CompressedOutput:
        """trufflehog/gitleaks 출력을 시크릿 탐지 결과로 압축."""
        secrets: list[dict[str, str]] = []
        interesting = []

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                secret_info = {
                    "type": data.get("DetectorName", data.get("RuleID", "unknown")),
                    "file": data.get("SourceMetadata", {}).get("Data", {}).get(
                        "Filesystem", {},
                    ).get("file", "")[:40],
                }
                secrets.append(secret_info)
                interesting.append(
                    f"Secret: {secret_info['type']} in {secret_info['file']}"
                )
            except (json.JSONDecodeError, TypeError):
                if any(
                    kw in line.lower()
                    for kw in ["secret", "key", "token", "password", "api"]
                ):
                    secrets.append({"raw": line[:60]})
                    interesting.append(line[:60])

        summary = f"{len(secrets)} secrets found" if secrets else "no secrets"

        return CompressedOutput(
            tool="trufflehog",
            summary=summary,
            structured={"secrets": secrets[:10]},
            interesting=interesting[:5],
        )

    def _parse_sslyze(self, raw: str) -> CompressedOutput:
        """sslyze 출력을 SSL 분석 결과로 압축."""
        vulns = []
        interesting = []

        vuln_checks = [
            ("heartbleed", "Heartbleed"),
            ("robot", "ROBOT"),
            ("openssl_ccs", "CCS Injection"),
            ("session_renegotiation", "Insecure Renegotiation"),
        ]

        for check_name, display_name in vuln_checks:
            if check_name in raw.lower() and "vulnerable" in raw.lower():
                vulns.append(display_name)
                interesting.append(f"VULN: {display_name}")

        summary = f"SSL: {len(vulns)} vulnerabilities" if vulns else "SSL: OK"

        return CompressedOutput(
            tool="sslyze",
            summary=summary,
            structured={"vulnerabilities": vulns},
            interesting=interesting[:5],
        )

    def _parse_generic(self, raw: str) -> CompressedOutput:
        """알 수 없는 도구의 출력을 최소한으로 압축."""
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        interesting = []

        # 키워드 기반 중요 라인 추출
        important_keywords = [
            "vulnerability", "vulnerable", "critical", "high",
            "warning", "error", "found", "detected", "exploit",
            "injection", "bypass", "unauthorized", "leaked",
        ]

        for line in lines:
            if any(kw in line.lower() for kw in important_keywords):
                interesting.append(line[:80])

        summary = f"{len(lines)} lines output, {len(interesting)} notable"

        return CompressedOutput(
            tool="generic",
            summary=summary,
            structured={"total_lines": len(lines)},
            interesting=interesting[:5],
        )

    # ── Utilities ────────────────────────────────────────────────

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """토큰 수를 대략적으로 추정 (1 토큰 ≈ 4 characters)."""
        return len(text) // 4

    @staticmethod
    def _truncate(output: CompressedOutput, max_tokens: int) -> CompressedOutput:
        """토큰 한도에 맞게 출력을 자른다."""
        max_chars = max_tokens * 4

        # interesting 부터 자름
        while (
            ContextCompressor._estimate_tokens(output.as_prompt) > max_tokens
            and output.interesting
        ):
            output.interesting.pop()

        # summary 자름
        if len(output.summary) > max_chars // 2:
            output.summary = output.summary[: max_chars // 2] + "..."

        output.token_estimate = ContextCompressor._estimate_tokens(output.as_prompt)
        return output
