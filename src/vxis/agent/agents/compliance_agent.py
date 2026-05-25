"""META-09 ComplianceAgent — GDPR/HIPAA/PCI-DSS/SOC2 mapping and fine calculation."""

from __future__ import annotations

import asyncio
import json
import shutil

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


# Maximum fine structures by framework
_FINE_STRUCTURES = {
    "GDPR": {
        "max_fine": "4% of annual global turnover or EUR 20M",
        "lower_tier": "2% of annual global turnover or EUR 10M",
    },
    "HIPAA": {
        "tier1": "USD 100-50,000 per violation (unknowing)",
        "tier2": "USD 1,000-50,000 per violation (reasonable cause)",
        "tier3": "USD 10,000-50,000 per violation (willful neglect, corrected)",
        "tier4": "USD 50,000+ per violation (willful neglect, not corrected)",
        "annual_max": "USD 1.5M per identical provision",
    },
    "PCI-DSS": {
        "non_compliance": "USD 5,000-100,000 per month",
        "breach": "USD 50-90 per cardholder record compromised",
    },
    "SOC2": {
        "fine": "No direct fines, but contract penalties and lost business",
        "impact": "Customer trust erosion, contract termination",
    },
}

# Compliance control mappings
_CONTROL_MAPPINGS = {
    "encryption_at_rest": {
        "GDPR": "Art. 32 — Encryption of personal data",
        "HIPAA": "§164.312(a)(2)(iv) — Encryption and decryption",
        "PCI-DSS": "Req 3.4 — Render PAN unreadable",
        "SOC2": "CC6.1 — Logical and physical access controls",
    },
    "encryption_in_transit": {
        "GDPR": "Art. 32 — Security of processing",
        "HIPAA": "§164.312(e)(1) — Transmission security",
        "PCI-DSS": "Req 4.1 — Encrypt transmissions over public networks",
        "SOC2": "CC6.7 — Restrict transmission of data",
    },
    "access_control": {
        "GDPR": "Art. 25 — Data protection by design",
        "HIPAA": "§164.312(a)(1) — Access control",
        "PCI-DSS": "Req 7 — Restrict access by business need-to-know",
        "SOC2": "CC6.3 — Role-based access",
    },
    "logging_monitoring": {
        "GDPR": "Art. 33/34 — Breach notification (requires detection)",
        "HIPAA": "§164.312(b) — Audit controls",
        "PCI-DSS": "Req 10 — Track and monitor access",
        "SOC2": "CC7.2 — Monitor system components",
    },
    "data_retention": {
        "GDPR": "Art. 5(1)(e) — Storage limitation",
        "HIPAA": "§164.530(j) — Documentation retention (6 years)",
        "PCI-DSS": "Req 3.1 — Limit cardholder data storage",
        "SOC2": "CC6.5 — Dispose of data securely",
    },
    "vulnerability_management": {
        "GDPR": "Art. 32 — Appropriate technical measures",
        "HIPAA": "§164.308(a)(5)(ii)(B) — Protection from malicious software",
        "PCI-DSS": "Req 6.1 — Establish vulnerability management process",
        "SOC2": "CC7.1 — Detect and monitor security events",
    },
}


@register
class ComplianceAgent(BaseAgent):
    agent_id = "compliance"
    description = (
        "Compliance mapping: GDPR, HIPAA, PCI-DSS, SOC2 control assessment, "
        "violation identification, and potential fine calculation"
    )

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: TLS/encryption compliance check
        tls_findings = await self._check_tls_compliance(target)
        findings.extend(tls_findings)

        # Phase 2: Security headers compliance
        header_findings = await self._check_security_headers(target)
        findings.extend(header_findings)

        # Phase 3: Cookie compliance (GDPR consent, secure flags)
        cookie_findings = await self._check_cookie_compliance(target)
        findings.extend(cookie_findings)

        # Phase 4: Privacy policy / data handling assessment
        privacy_findings = await self._check_privacy_compliance(target)
        findings.extend(privacy_findings)

        # Phase 5: Map findings to compliance frameworks
        violations = self._map_to_frameworks(findings)
        if violations:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Compliance violations mapped for {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.OTHER,
                    description=self._format_violation_report(violations),
                    response=json.dumps(violations, indent=2),
                    tags=["compliance", "gdpr", "hipaa", "pci-dss", "soc2"],
                )
            )

        # Phase 6: Fine calculation
        fine_report = self._calculate_potential_fines(violations)
        findings.append(
            Evidence(
                agent_id=self.agent_id,
                title=f"Potential fine exposure for {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.OTHER,
                description=fine_report,
                response=json.dumps(_FINE_STRUCTURES, indent=2),
                tags=["compliance", "fines", "risk-assessment"],
            )
        )

        # Generate hypotheses
        hypotheses.append(
            Hypothesis(
                title=f"GDPR right-to-erasure violation on {target}",
                rationale="Data handling practices may not support deletion requests",
                probability=0.5,
                impact=0.8,
                suggested_agent="compliance",
            )
        )
        hypotheses.append(
            Hypothesis(
                title=f"PCI-DSS cardholder data exposure on {target}",
                rationale="Web application may process/store card data insecurely",
                probability=0.4,
                impact=0.9,
                suggested_agent="web",
            )
        )

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "frameworks_checked": ["GDPR", "HIPAA", "PCI-DSS", "SOC2"],
                "violations_found": len(violations) if violations else 0,
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _check_tls_compliance(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("nmap"):
            return results

        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "-Pn",
            "--script",
            "ssl-enum-ciphers",
            "-p",
            "443",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode()

        violations: list[str] = []
        if "TLSv1.0" in output:
            violations.append("TLS 1.0 enabled (PCI-DSS non-compliant since 2018)")
        if "TLSv1.1" in output:
            violations.append("TLS 1.1 enabled (deprecated, non-compliant)")
        if "RC4" in output or "DES" in output or "NULL" in output:
            violations.append("Weak cipher suites detected")
        if "SWEET32" in output or "POODLE" in output:
            violations.append("Known TLS vulnerability present")

        if violations:
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"TLS compliance violations on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        "TLS configuration violations:\n"
                        + "\n".join(f"- {v}" for v in violations)
                        + "\n\nAffected frameworks: PCI-DSS Req 4.1, "
                        "HIPAA §164.312(e)(1), GDPR Art. 32"
                    ),
                    response=output[:2000],
                    tags=["compliance", "tls", "encryption-in-transit"],
                )
            )
        return results

    async def _check_security_headers(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        proc = await asyncio.create_subprocess_exec(
            "curl",
            "-s",
            "-I",
            "--max-time",
            "10",
            f"https://{target}/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        headers = stdout.decode().lower()

        missing: list[str] = []
        required_headers = {
            "strict-transport-security": "HSTS (PCI-DSS, SOC2)",
            "x-content-type-options": "Content-Type sniffing prevention",
            "x-frame-options": "Clickjacking prevention",
            "content-security-policy": "CSP (OWASP, SOC2)",
            "x-xss-protection": "XSS filter",
        }
        for header, desc in required_headers.items():
            if header not in headers:
                missing.append(f"{header}: {desc}")

        if missing:
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Missing security headers on {target}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        "Missing security headers:\n" + "\n".join(f"- {m}" for m in missing)
                    ),
                    response=stdout.decode()[:1000],
                    tags=["compliance", "security-headers", "misconfiguration"],
                )
            )
        return results

    async def _check_cookie_compliance(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        proc = await asyncio.create_subprocess_exec(
            "curl",
            "-s",
            "-I",
            "--max-time",
            "10",
            f"https://{target}/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        headers = stdout.decode()

        cookie_issues: list[str] = []
        for line in headers.splitlines():
            if line.lower().startswith("set-cookie:"):
                cookie = line.lower()
                if "secure" not in cookie:
                    cookie_issues.append("Cookie missing Secure flag")
                if "httponly" not in cookie:
                    cookie_issues.append("Cookie missing HttpOnly flag")
                if "samesite" not in cookie:
                    cookie_issues.append("Cookie missing SameSite attribute")

        if cookie_issues:
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Cookie security issues on {target}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        "Cookie compliance issues:\n"
                        + "\n".join(f"- {i}" for i in set(cookie_issues))
                        + "\n\nGDPR: Insecure cookies may expose user session data. "
                        "PCI-DSS Req 6.5.10: Broken authentication."
                    ),
                    tags=["compliance", "cookie", "session-security"],
                )
            )
        return results

    async def _check_privacy_compliance(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # Check for privacy policy page
        privacy_paths = ["/privacy", "/privacy-policy", "/legal/privacy"]
        found_privacy = False
        for path in privacy_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "5",
                f"https://{target}{path}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            if stdout.decode().strip() == "200":
                found_privacy = True
                break

        if not found_privacy:
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"No privacy policy found on {target}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        "No accessible privacy policy page found. "
                        "GDPR Art. 13/14 requires clear privacy notices. "
                        "CCPA also requires disclosure of data practices."
                    ),
                    tags=["compliance", "gdpr", "privacy-policy"],
                )
            )
        return results

    def _map_to_frameworks(
        self,
        findings: list[Evidence],
    ) -> dict[str, list[str]]:
        violations: dict[str, list[str]] = {
            "GDPR": [],
            "HIPAA": [],
            "PCI-DSS": [],
            "SOC2": [],
        }
        for finding in findings:
            tags = set(finding.tags)
            if "tls" in tags or "encryption-in-transit" in tags:
                for fw, ctrl in _CONTROL_MAPPINGS["encryption_in_transit"].items():
                    violations[fw].append(f"{ctrl}: {finding.title}")
            if "security-headers" in tags or "cookie" in tags:
                for fw, ctrl in _CONTROL_MAPPINGS["access_control"].items():
                    violations[fw].append(f"{ctrl}: {finding.title}")
            if "privacy-policy" in tags:
                violations["GDPR"].append(f"Art. 13/14 — Transparency obligation: {finding.title}")

        return {k: v for k, v in violations.items() if v}

    def _format_violation_report(
        self,
        violations: dict[str, list[str]],
    ) -> str:
        lines = ["Compliance Violation Summary:\n"]
        for framework, items in violations.items():
            lines.append(f"\n[{framework}]")
            for item in items:
                lines.append(f"  - {item}")
        return "\n".join(lines)

    def _calculate_potential_fines(
        self,
        violations: dict[str, list[str]] | None,
    ) -> str:
        if not violations:
            return "No compliance violations detected — no fine exposure."

        lines = ["Potential Fine Exposure:\n"]
        for framework in violations:
            if framework in _FINE_STRUCTURES:
                lines.append(f"\n[{framework}]")
                for tier, amount in _FINE_STRUCTURES[framework].items():
                    lines.append(f"  {tier}: {amount}")
        lines.append(
            "\nNote: Actual fines depend on violation severity, number of "
            "affected individuals, organizational response, and regulator discretion."
        )
        return "\n".join(lines)
