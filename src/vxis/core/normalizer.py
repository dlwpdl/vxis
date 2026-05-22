"""Post-processing normalizer for VXIS security automation platform.

Converts raw tool output from all supported plugins into canonical Finding
objects and provides deduplication utilities.  Supported tools: nuclei, nmap,
testssl, checkdmarc, trufflehog, wafw00f, prowler, gitleaks, trivy, dnstwist,
crtsh, sslyze, bloodhound, certipy, netexec, linpeas, semgrep, bandit,
checkov, kube-bench, poutine, subfinder, httpx, shodan, trivy-k8s, swaks,
actionlint, s3scanner, confused, winpeas.
"""

from __future__ import annotations

import re
from typing import Any

from vxis.core.normalizer_web import FindingFactoryWebMixin
from vxis.models.finding import Evidence, Finding, Severity
from vxis.core.normalizer_support import (
    FindingDeduplicator,
    _make_id,
)

__all__ = ["FindingDeduplicator", "FindingFactory", "NORMALIZERS"]

# ---------------------------------------------------------------------------
# FindingFactory
# ---------------------------------------------------------------------------


class FindingFactory(FindingFactoryWebMixin):
    """Convert raw tool-specific output into canonical Finding objects."""


    @staticmethod
    def from_bloodhound(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert BloodHound AD graph statistics into Finding objects.

        Severity mapping:
        - Kerberoastable users  → high
        - Unconstrained delegation → critical
        - AS-REP roastable users → medium

        Args:
            parsed_data: Dict with keys: users, admins, kerberoastable,
                         asreproastable, unconstrained_delegation.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for risky AD configurations.
        """
        findings: list[Finding] = []

        kerberoastable = int(parsed_data.get("kerberoastable", 0))
        if kerberoastable > 0:
            findings.append(Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=f"Kerberoastable Users Detected ({kerberoastable})",
                description=(
                    f"{kerberoastable} user account(s) have Service Principal Names (SPNs) "
                    "set and are vulnerable to Kerberoasting attacks. Attackers can request "
                    "service tickets offline and crack them to recover plaintext credentials."
                ),
                severity=Severity.high,
                target="Active Directory",
                affected_component="Kerberos / SPNs",
                finding_type="misconfiguration",
                source_plugin="bloodhound",
                evidence=[Evidence(
                    evidence_type="ad_graph",
                    title="BloodHound AD Statistics",
                    content=f"Kerberoastable accounts: {kerberoastable}",
                    content_type="text/plain",
                )],
                raw_data=parsed_data,
            ))

        unconstrained = int(parsed_data.get("unconstrained_delegation", 0))
        if unconstrained > 0:
            findings.append(Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=f"Unconstrained Delegation Enabled ({unconstrained})",
                description=(
                    f"{unconstrained} object(s) have unconstrained delegation enabled. "
                    "An attacker who compromises these accounts can impersonate any domain "
                    "user, including Domain Admins, against any service in the domain."
                ),
                severity=Severity.critical,
                target="Active Directory",
                affected_component="Kerberos Delegation",
                finding_type="misconfiguration",
                source_plugin="bloodhound",
                evidence=[Evidence(
                    evidence_type="ad_graph",
                    title="BloodHound AD Statistics",
                    content=f"Unconstrained delegation objects: {unconstrained}",
                    content_type="text/plain",
                )],
                raw_data=parsed_data,
            ))

        asrep = int(parsed_data.get("asreproastable", 0))
        if asrep > 0:
            findings.append(Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=f"AS-REP Roastable Users Detected ({asrep})",
                description=(
                    f"{asrep} user account(s) do not require Kerberos pre-authentication "
                    "(DONT_REQ_PREAUTH flag set). Attackers can request AS-REP tickets "
                    "without credentials and crack them offline."
                ),
                severity=Severity.medium,
                target="Active Directory",
                affected_component="Kerberos Pre-authentication",
                finding_type="misconfiguration",
                source_plugin="bloodhound",
                evidence=[Evidence(
                    evidence_type="ad_graph",
                    title="BloodHound AD Statistics",
                    content=f"AS-REP roastable accounts: {asrep}",
                    content_type="text/plain",
                )],
                raw_data=parsed_data,
            ))

        return findings

    # ------------------------------------------------------------------
    # certipy
    # ------------------------------------------------------------------

    @staticmethod
    def from_certipy(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert Certipy ADCS findings into Finding objects.

        Severity mapping:
        - ESC1, ESC2 → critical
        - ESC3-ESC8  → high

        Args:
            parsed_data: Dict with key "vulnerable_templates" (list of template dicts).
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for each vulnerable certificate template.
        """
        _CRITICAL_CLASSES: frozenset[str] = frozenset({"ESC1", "ESC2"})

        findings: list[Finding] = []
        templates: list[dict[str, Any]] = parsed_data.get("vulnerable_templates", [])

        for template in templates:
            esc_class = str(template.get("vulnerability", "")).upper()
            template_name = template.get("template_name", "Unknown")
            severity = Severity.critical if esc_class in _CRITICAL_CLASSES else Severity.high

            findings.append(Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=f"ADCS Vulnerable Template: {template_name} ({esc_class})",
                description=(
                    f"Certificate template '{template_name}' is vulnerable to {esc_class}. "
                    f"Enabled: {template.get('enabled', False)}, "
                    f"Client Authentication: {template.get('client_authentication', False)}, "
                    f"Enrollee Supplies Subject: {template.get('enrollee_supplies_subject', False)}. "
                    "This may allow domain privilege escalation via certificate abuse."
                ),
                severity=severity,
                target="Active Directory Certificate Services",
                affected_component=template_name,
                finding_type="misconfiguration",
                source_plugin="certipy",
                source_tool_ref=esc_class,
                evidence=[Evidence(
                    evidence_type="adcs_scan",
                    title=f"Certipy Finding: {esc_class}",
                    content=(
                        f"Template: {template_name}\n"
                        f"Vulnerability: {esc_class}\n"
                        f"Enabled: {template.get('enabled', False)}\n"
                        f"Client Authentication: {template.get('client_authentication', False)}"
                    ),
                    content_type="text/plain",
                )],
                raw_data=template,
            ))

        return findings

    # ------------------------------------------------------------------
    # netexec
    # ------------------------------------------------------------------

    @staticmethod
    def from_netexec(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert NetExec SMB enumeration results into Finding objects.

        Severity mapping:
        - Readable SMB shares → medium
        - Weak password policy → high

        Args:
            parsed_data: Dict with keys "readable_shares" (list) and
                         "password_policy" (dict with min_length, complexity).
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for exposed shares and policy weaknesses.
        """
        findings: list[Finding] = []

        for share in parsed_data.get("readable_shares", []):
            share_name = share.get("share", "Unknown")
            permissions = share.get("permissions", "")
            findings.append(Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=f"Readable SMB Share: {share_name}",
                description=(
                    f"SMB share '{share_name}' is accessible with permissions: {permissions}. "
                    "Unauthorised network share access may expose sensitive data or configuration files."
                ),
                severity=Severity.medium,
                target="SMB",
                affected_component=share_name,
                finding_type="exposure",
                source_plugin="netexec",
                evidence=[Evidence(
                    evidence_type="smb_enum",
                    title=f"SMB Share: {share_name}",
                    content=f"Share: {share_name}\nPermissions: {permissions}",
                    content_type="text/plain",
                )],
                raw_data=share,
            ))

        policy = parsed_data.get("password_policy", {})
        if policy:
            min_length = policy.get("min_length")
            complexity = policy.get("complexity")
            is_weak = (min_length is not None and min_length < 8) or (complexity is False)
            if is_weak:
                findings.append(Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title="Weak Domain Password Policy",
                    description=(
                        f"The domain password policy is weak: {policy.get('raw', '')}. "
                        "A minimum length below 8 characters or disabled complexity requirements "
                        "significantly increases the risk of successful brute-force or spray attacks."
                    ),
                    severity=Severity.high,
                    target="Active Directory",
                    affected_component="Password Policy",
                    finding_type="misconfiguration",
                    source_plugin="netexec",
                    evidence=[Evidence(
                        evidence_type="smb_enum",
                        title="Domain Password Policy",
                        content=f"Policy: {policy.get('raw', '')}\nMinLength: {min_length}\nComplexity: {complexity}",
                        content_type="text/plain",
                    )],
                    raw_data=policy,
                ))

        return findings

    # ------------------------------------------------------------------
    # linpeas
    # ------------------------------------------------------------------

    @staticmethod
    def from_linpeas(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert LinPEAS privilege escalation results into Finding objects.

        Severity mapping (from linpeas confidence percentages):
        - 95% → critical
        - 70% → high
        - 50% → medium

        Args:
            parsed_data: Dict with key "findings" (list of dicts with severity,
                         title, confidence_pct) as produced by LinpeasPlugin.
                         Also accepts direct PluginOutput.findings-style list
                         via a "privesc_findings" key.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for Linux privilege escalation vectors.
        """
        _PCT_TO_SEVERITY: dict[int, Severity] = {
            95: Severity.critical,
            70: Severity.high,
            50: Severity.medium,
        }
        _NAME_TO_SEVERITY: dict[str, Severity] = {
            "critical": Severity.critical,
            "high": Severity.high,
            "medium": Severity.medium,
            "low": Severity.low,
        }

        findings: list[Finding] = []

        # Support both list-under-key and raw-list forms
        raw_list: list[dict[str, Any]] = (
            parsed_data.get("privesc_findings")
            or parsed_data.get("findings")
            or []
        )

        for item in raw_list:
            title = item.get("title", "Linux Privilege Escalation Vector")
            description = item.get("description", title)
            pct: int | None = item.get("confidence_pct")
            severity_str: str = item.get("severity", "medium")

            if pct is not None and pct in _PCT_TO_SEVERITY:
                severity = _PCT_TO_SEVERITY[pct]
            else:
                severity = _NAME_TO_SEVERITY.get(severity_str.lower(), Severity.medium)

            findings.append(Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                target="localhost",
                affected_component="Linux OS",
                finding_type="vulnerability",
                source_plugin="linpeas",
                evidence=[Evidence(
                    evidence_type="privesc_scan",
                    title="LinPEAS Finding",
                    content=item.get("raw_line", title),
                    content_type="text/plain",
                )],
                raw_data=item,
            ))

        return findings

    # ------------------------------------------------------------------
    # semgrep
    # ------------------------------------------------------------------

    @staticmethod
    def from_semgrep(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert semgrep SAST findings to Finding objects.

        Severity mapping:
        - ERROR → high
        - WARNING → medium

        Args:
            parsed_data: Dict with key "sast_findings" (list) produced by SemgrepPlugin.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for each semgrep result.
        """
        _semgrep_severity_map: dict[str, Severity] = {
            "ERROR": Severity.high,
            "WARNING": Severity.medium,
            "INFO": Severity.informational,
        }

        raw_findings: list[dict[str, Any]] = (
            parsed_data.get("sast_findings", parsed_data)
            if isinstance(parsed_data, dict)
            else parsed_data
        )
        if not isinstance(raw_findings, list):
            raw_findings = [raw_findings]

        findings: list[Finding] = []

        for item in raw_findings:
            severity_str = str(item.get("severity", "WARNING")).upper()
            severity = _semgrep_severity_map.get(severity_str, Severity.medium)

            check_id = item.get("check_id", "")
            message = item.get("message", "")
            affected_component = item.get("affected_component", "")

            title = f"SAST: {check_id}" if check_id else "SAST Finding"
            description = message or f"Semgrep rule triggered: {check_id}"

            evidence_list = [Evidence(
                evidence_type="sast_result",
                title=f"Semgrep: {check_id}",
                content=(
                    f"Rule: {check_id}\n"
                    f"Severity: {severity_str}\n"
                    f"Message: {message}\n"
                    f"Location: {affected_component}"
                ),
                content_type="text/plain",
            )]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                target=item.get("path", ""),
                affected_component=affected_component,
                finding_type="vulnerability",
                source_plugin="semgrep",
                source_tool_ref=check_id,
                evidence=evidence_list,
                raw_data=item,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # bandit
    # ------------------------------------------------------------------

    @staticmethod
    def from_bandit(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert bandit Python SAST findings to Finding objects.

        Severity mapping:
        - HIGH → high
        - MEDIUM → medium
        - LOW → low

        Args:
            parsed_data: Dict with key "python_sast" (list) produced by BanditPlugin.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for each bandit result.
        """
        _bandit_severity_map: dict[str, Severity] = {
            "HIGH": Severity.high,
            "MEDIUM": Severity.medium,
            "LOW": Severity.low,
        }

        raw_findings: list[dict[str, Any]] = (
            parsed_data.get("python_sast", parsed_data)
            if isinstance(parsed_data, dict)
            else parsed_data
        )
        if not isinstance(raw_findings, list):
            raw_findings = [raw_findings]

        findings: list[Finding] = []

        for item in raw_findings:
            severity_str = str(item.get("issue_severity", "MEDIUM")).upper()
            severity = _bandit_severity_map.get(severity_str, Severity.medium)

            test_id = item.get("test_id", "")
            issue_text = item.get("issue_text", "")
            filename = item.get("filename", "")
            line_number = item.get("line_number", 0)
            cwe_id = item.get("cwe_id")

            cwe_ids_out: list[str] = []
            if cwe_id is not None:
                cwe_ids_out.append(f"CWE-{cwe_id}")

            affected_component = f"{filename}:{line_number}" if filename else ""
            title = f"Python SAST: {test_id}" if test_id else "Python SAST Finding"
            description = issue_text or f"Bandit issue detected: {test_id}"

            evidence_list = [Evidence(
                evidence_type="sast_result",
                title=f"Bandit: {test_id}",
                content=(
                    f"TestID: {test_id}\n"
                    f"Severity: {severity_str}\n"
                    f"Issue: {issue_text}\n"
                    f"File: {filename}\n"
                    f"Line: {line_number}"
                ),
                content_type="text/plain",
            )]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                target=filename,
                affected_component=affected_component,
                finding_type="vulnerability",
                source_plugin="bandit",
                source_tool_ref=test_id,
                evidence=evidence_list,
                raw_data=item,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # checkov
    # ------------------------------------------------------------------

    @staticmethod
    def from_checkov(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert checkov IaC misconfiguration findings to Finding objects.

        Severity is derived from the check's severity field (HIGH/MEDIUM/LOW).
        Defaults to medium when unspecified.

        Args:
            parsed_data: Dict with key "iac_findings" (list) produced by CheckovPlugin.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for failed IaC checks.
        """
        _checkov_severity_map: dict[str, Severity] = {
            "CRITICAL": Severity.critical,
            "HIGH": Severity.high,
            "MEDIUM": Severity.medium,
            "LOW": Severity.low,
        }

        raw_findings: list[dict[str, Any]] = (
            parsed_data.get("iac_findings", parsed_data)
            if isinstance(parsed_data, dict)
            else parsed_data
        )
        if not isinstance(raw_findings, list):
            raw_findings = [raw_findings]

        findings: list[Finding] = []

        for item in raw_findings:
            severity_str = str(item.get("severity", "MEDIUM")).upper()
            severity = _checkov_severity_map.get(severity_str, Severity.medium)

            check_id = item.get("check_id", "")
            name = item.get("name", "")
            guideline = item.get("guideline", "")
            file_path = item.get("file_path", "")
            line_range = item.get("file_line_range", [])

            line_info = f":{line_range[0]}-{line_range[-1]}" if line_range else ""
            affected_component = f"{file_path}{line_info}" if file_path else ""

            title = f"IaC Misconfiguration: {check_id}" if check_id else "IaC Misconfiguration"
            description = name or f"Checkov check failed: {check_id}"

            evidence_list = [Evidence(
                evidence_type="iac_scan",
                title=f"Checkov: {check_id}",
                content=(
                    f"CheckID: {check_id}\n"
                    f"Name: {name}\n"
                    f"Severity: {severity_str}\n"
                    f"File: {file_path}\n"
                    f"Lines: {line_range}\n"
                    f"Guideline: {guideline}"
                ),
                content_type="text/plain",
            )]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                target=file_path,
                affected_component=affected_component,
                finding_type="misconfiguration",
                source_plugin="checkov",
                source_tool_ref=check_id,
                remediation=guideline,
                evidence=evidence_list,
                raw_data=item,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # kube-bench
    # ------------------------------------------------------------------

    @staticmethod
    def from_kube_bench(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert kube-bench CIS benchmark failures to Finding objects.

        All CIS benchmark failures are treated as medium severity by default;
        scored checks are considered more impactful.

        Args:
            parsed_data: Dict with key "k8s_cis" (list) produced by KubeBenchPlugin.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for each benchmark failure.
        """
        raw_findings: list[dict[str, Any]] = (
            parsed_data.get("k8s_cis", parsed_data)
            if isinstance(parsed_data, dict)
            else parsed_data
        )
        if not isinstance(raw_findings, list):
            raw_findings = [raw_findings]

        findings: list[Finding] = []

        for item in raw_findings:
            test_number = item.get("test_number", "")
            test_desc = item.get("test_desc", "")
            remediation = item.get("remediation", "")
            scored = item.get("scored", True)

            title = f"CIS K8s Benchmark Failure: {test_number}" if test_number else "CIS K8s Benchmark Failure"
            description = test_desc or f"CIS benchmark check {test_number} failed."

            severity = Severity.medium if scored else Severity.low

            evidence_list = [Evidence(
                evidence_type="cis_benchmark",
                title=f"kube-bench: {test_number}",
                content=(
                    f"TestNumber: {test_number}\n"
                    f"Description: {test_desc}\n"
                    f"Status: FAIL\n"
                    f"Scored: {scored}\n"
                    f"Remediation: {remediation}"
                ),
                content_type="text/plain",
            )]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                target="kubernetes",
                affected_component=test_number,
                finding_type="misconfiguration",
                source_plugin="kube-bench",
                source_tool_ref=test_number,
                remediation=remediation,
                evidence=evidence_list,
                raw_data=item,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # poutine
    # ------------------------------------------------------------------

    @staticmethod
    def from_poutine(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert poutine CI/CD security findings to Finding objects.

        Severity mapping:
        - critical → critical
        - high → high
        - medium → medium
        - low / info → low

        Args:
            parsed_data: Dict with key "cicd_findings" (list) produced by PoutinePlugin.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for each CI/CD pipeline security issue.
        """
        _poutine_severity_map: dict[str, Severity] = {
            "critical": Severity.critical,
            "high": Severity.high,
            "medium": Severity.medium,
            "low": Severity.low,
            "info": Severity.low,
        }

        raw_findings: list[dict[str, Any]] = (
            parsed_data.get("cicd_findings", parsed_data)
            if isinstance(parsed_data, dict)
            else parsed_data
        )
        if not isinstance(raw_findings, list):
            raw_findings = [raw_findings]

        findings: list[Finding] = []

        for item in raw_findings:
            severity_str = str(item.get("severity", "medium")).lower()
            severity = _poutine_severity_map.get(severity_str, Severity.medium)

            rule_id = item.get("id", "")
            rule_title = item.get("title", "")
            details = item.get("details", "")

            title = f"CI/CD Security: {rule_title}" if rule_title else f"CI/CD Security: {rule_id}"
            description = details or rule_title or f"Poutine rule triggered: {rule_id}"

            evidence_list = [Evidence(
                evidence_type="cicd_scan",
                title=f"Poutine: {rule_id}",
                content=(
                    f"RuleID: {rule_id}\n"
                    f"Title: {rule_title}\n"
                    f"Severity: {severity_str}\n"
                    f"Details: {details}"
                ),
                content_type="text/plain",
            )]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                target="cicd",
                affected_component=rule_id,
                finding_type="misconfiguration",
                source_plugin="poutine",
                source_tool_ref=rule_id,
                evidence=evidence_list,
                raw_data=item,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # subfinder
    # ------------------------------------------------------------------

    @staticmethod
    def from_subfinder(parsed_data: dict[str, Any], scan_id: str, domain: str = "") -> list[Finding]:
        """Convert subfinder subdomain enumeration results to informational findings.

        Each discovered subdomain is an informational asset-discovery finding.

        Args:
            parsed_data: Dict with key "subdomains" (list of hostname strings)
                         as produced by SubfinderPlugin.
            scan_id: Identifier of the parent scan.
            domain: The parent domain that was queried.

        Returns:
            List of informational Finding objects for each discovered subdomain.
        """
        subdomains: list[str] = parsed_data.get("subdomains", [])
        if not isinstance(subdomains, list):
            subdomains = []

        findings: list[Finding] = []

        for subdomain in subdomains:
            if not subdomain:
                continue

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=f"Subdomain Discovered: {subdomain}",
                description=(
                    f"The subdomain '{subdomain}' was discovered via passive/active enumeration "
                    f"for domain '{domain or subdomain}'. This is an asset inventory finding."
                ),
                severity=Severity.informational,
                target=domain or subdomain,
                affected_component=subdomain,
                finding_type="discovery",
                source_plugin="subfinder",
                evidence=[Evidence(
                    evidence_type="recon",
                    title="Subdomain Enumeration",
                    content=f"Subdomain: {subdomain}",
                    content_type="text/plain",
                )],
                raw_data={"host": subdomain},
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # httpx
    # ------------------------------------------------------------------

    @staticmethod
    def from_httpx(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert httpx live host probe results to informational findings.

        Each reachable host/URL is an informational asset-discovery finding.

        Args:
            parsed_data: Dict with key "live_hosts" (list of host entry dicts
                         with url, status_code, title, tech, cdn, etc.)
                         as produced by HttpxPlugin.
            scan_id: Identifier of the parent scan.

        Returns:
            List of informational Finding objects for each live host.
        """
        live_hosts: list[dict[str, Any]] = parsed_data.get("live_hosts", [])
        if not isinstance(live_hosts, list):
            live_hosts = []

        findings: list[Finding] = []

        for host_entry in live_hosts:
            url = host_entry.get("url", "")
            if not url:
                continue

            status_code = host_entry.get("status_code", "")
            title = host_entry.get("title", "")
            tech: list[str] = host_entry.get("tech", []) or []
            cdn = host_entry.get("cdn", False)

            finding_title = f"Live Host: {url}"
            description_parts = [f"HTTP service detected at {url}."]
            if status_code:
                description_parts.append(f"Status: {status_code}.")
            if title:
                description_parts.append(f"Page title: {title}.")
            if tech:
                description_parts.append(f"Technologies: {', '.join(tech)}.")
            if cdn:
                description_parts.append("Behind CDN.")

            evidence_content = f"URL: {url}\nStatus: {status_code}\nTitle: {title}"
            if tech:
                evidence_content += f"\nTechnologies: {', '.join(tech)}"
            if cdn:
                evidence_content += "\nCDN: Yes"

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=finding_title,
                description=" ".join(description_parts),
                severity=Severity.informational,
                target=url,
                affected_component=title or url,
                finding_type="discovery",
                source_plugin="httpx",
                evidence=[Evidence(
                    evidence_type="recon",
                    title="HTTP Probe Result",
                    content=evidence_content,
                    content_type="text/plain",
                )],
                raw_data=host_entry,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # shodan
    # ------------------------------------------------------------------

    @staticmethod
    def from_shodan(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert Shodan exposed service results to informational findings.

        Each internet-exposed service is an informational finding.

        Args:
            parsed_data: Dict with key "shodan_results" (list of service dicts
                         with ip, port, org, os, product) as produced by
                         ShodanPlugin.
            scan_id: Identifier of the parent scan.

        Returns:
            List of informational Finding objects for each exposed service.
        """
        services: list[dict[str, Any]] = parsed_data.get("shodan_results", [])
        if not isinstance(services, list):
            services = []

        findings: list[Finding] = []

        for service in services:
            ip = service.get("ip", "")
            port = service.get("port", 0)
            org = service.get("org", "")
            os_name = service.get("os", "")
            product = service.get("product", "")

            if not ip:
                continue

            port_int: int | None = None
            if port:
                try:
                    port_int = int(port)
                except (ValueError, TypeError):
                    port_int = None

            title = f"Exposed Service: {ip}:{port}"
            if product:
                title += f" ({product})"

            description_parts = [f"Internet-exposed service detected on {ip}:{port}."]
            if product:
                description_parts.append(f"Product: {product}.")
            if os_name:
                description_parts.append(f"OS: {os_name}.")
            if org:
                description_parts.append(f"Organization: {org}.")

            evidence_content = (
                f"IP: {ip}\n"
                f"Port: {port}\n"
                f"Product: {product}\n"
                f"OS: {os_name}\n"
                f"Organization: {org}"
            )

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=" ".join(description_parts),
                severity=Severity.informational,
                target=ip,
                affected_component=product or f"{ip}:{port}",
                port=port_int,
                protocol="tcp",
                finding_type="discovery",
                source_plugin="shodan",
                evidence=[Evidence(
                    evidence_type="osint",
                    title="Shodan Service",
                    content=evidence_content,
                    content_type="text/plain",
                )],
                raw_data=service,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # trivy-k8s
    # ------------------------------------------------------------------

    @staticmethod
    def from_trivy_k8s(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert Trivy K8s cluster vulnerability findings to Finding objects.

        Severity is derived directly from each vulnerability's Severity field.

        Args:
            parsed_data: Dict with key "k8s_vulns" (list of dicts with
                         cluster_name, vulnerability_id, severity, title,
                         misconf_summary) as produced by TrivyK8sPlugin.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for Kubernetes cluster vulnerabilities.
        """
        _trivy_k8s_severity_map: dict[str, Severity] = {
            "CRITICAL": Severity.critical,
            "HIGH": Severity.high,
            "MEDIUM": Severity.medium,
            "LOW": Severity.low,
            "UNKNOWN": Severity.informational,
        }

        raw_findings: list[dict[str, Any]] = parsed_data.get("k8s_vulns", [])
        if not isinstance(raw_findings, list):
            raw_findings = []

        findings: list[Finding] = []

        for item in raw_findings:
            vuln_id = item.get("vulnerability_id", "")
            severity_str = item.get("severity", "UNKNOWN")
            title_str = item.get("title", "")
            cluster_name = item.get("cluster_name", "")
            misconf_summary = item.get("misconf_summary", {})

            severity = _trivy_k8s_severity_map.get(severity_str.upper(), Severity.informational)

            cve_ids: list[str] = []
            if re.match(r"CVE-\d{4}-\d+", vuln_id, re.IGNORECASE):
                cve_ids.append(vuln_id.upper())

            title = title_str or f"K8s Vulnerability: {vuln_id}"
            description = title_str or f"Kubernetes cluster vulnerability detected: {vuln_id}"
            if cluster_name:
                description += f"\nCluster: {cluster_name}"

            evidence_content = (
                f"VulnerabilityID: {vuln_id}\n"
                f"Severity: {severity_str}\n"
                f"Cluster: {cluster_name}"
            )
            if misconf_summary:
                evidence_content += f"\nMisconfiguration Summary: {misconf_summary}"

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                target=cluster_name or "kubernetes",
                affected_component=vuln_id,
                finding_type="vulnerability",
                cve_ids=cve_ids,
                source_plugin="trivy-k8s",
                source_tool_ref=vuln_id,
                evidence=[Evidence(
                    evidence_type="k8s_scan",
                    title=f"Trivy K8s: {vuln_id}",
                    content=evidence_content,
                    content_type="text/plain",
                )],
                raw_data=item,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # swaks
    # ------------------------------------------------------------------

    @staticmethod
    def from_swaks(parsed_data: dict[str, Any], scan_id: str, target: str = "") -> list[Finding]:
        """Convert Swaks SMTP open relay test results to Finding objects.

        Generates a high-severity finding when an open relay is detected.
        Generates an informational finding when no relay is detected.

        Args:
            parsed_data: Dict with key "email_relay_results" (dict with
                         open_relay, connection_failed, relay_denied)
                         as produced by SwaksPlugin.
            scan_id: Identifier of the parent scan.
            target: The target domain or mail server being tested.

        Returns:
            List of Finding objects for SMTP relay test results.
        """
        relay_results: dict[str, Any] = parsed_data.get("email_relay_results", {})
        if not isinstance(relay_results, dict):
            return []

        findings: list[Finding] = []
        open_relay = relay_results.get("open_relay", False)

        if open_relay:
            findings.append(Finding(
                id=_make_id(),
                scan_id=scan_id,
                title="SMTP Open Relay Detected",
                description=(
                    f"The mail server for '{target}' accepted a RCPT TO for a domain it does "
                    "not own (250 response), indicating a potential open relay. Open relays "
                    "can be abused to send spam or phishing emails on behalf of the target."
                ),
                severity=Severity.high,
                target=target,
                affected_component="SMTP",
                port=25,
                protocol="tcp",
                finding_type="misconfiguration",
                source_plugin="swaks",
                evidence=[Evidence(
                    evidence_type="email_test",
                    title="SMTP Open Relay Test",
                    content=f"Open Relay: True\nTarget: {target}",
                    content_type="text/plain",
                )],
                raw_data=relay_results,
            ))
        else:
            connection_failed = relay_results.get("connection_failed", False)
            reason = relay_results.get("reason", "")
            if not connection_failed:
                findings.append(Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title="SMTP Relay Test: Not Vulnerable",
                    description=(
                        f"The mail server for '{target}' does not appear to be an open relay. "
                        f"Relay was denied or not accepted."
                    ),
                    severity=Severity.informational,
                    target=target,
                    affected_component="SMTP",
                    port=25,
                    protocol="tcp",
                    finding_type="exposure",
                    source_plugin="swaks",
                    evidence=[Evidence(
                        evidence_type="email_test",
                        title="SMTP Relay Test",
                        content=(
                            f"Open Relay: False\n"
                            f"Target: {target}\n"
                            f"Reason: {reason}"
                        ),
                        content_type="text/plain",
                    )],
                    raw_data=relay_results,
                ))

        return findings

    # ------------------------------------------------------------------
    # actionlint
    # ------------------------------------------------------------------

    @staticmethod
    def from_actionlint(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert actionlint GitHub Actions lint findings to Finding objects.

        Severity mapping:
        - Security-relevant kinds (expression, shellcheck, credentials,
          permissions, secret, injection) -> medium
        - All other kinds -> low

        Args:
            parsed_data: Dict with key "gha_lint" (list of dicts with filepath,
                         line, column, message, kind, severity) as produced by
                         ActionlintPlugin.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for each GitHub Actions lint issue.
        """
        _actionlint_severity_map: dict[str, Severity] = {
            "critical": Severity.critical,
            "high": Severity.high,
            "medium": Severity.medium,
            "low": Severity.low,
        }

        raw_findings: list[dict[str, Any]] = parsed_data.get("gha_lint", [])
        if not isinstance(raw_findings, list):
            raw_findings = []

        findings: list[Finding] = []

        for item in raw_findings:
            severity_str = str(item.get("severity", "low")).lower()
            severity = _actionlint_severity_map.get(severity_str, Severity.low)

            filepath = item.get("filepath", "")
            line = item.get("line", 0)
            column = item.get("column", 0)
            message = item.get("message", "")
            kind = item.get("kind", "")

            affected_component = f"{filepath}:{line}" if filepath else ""
            title = f"GitHub Actions Lint: {kind}" if kind else "GitHub Actions Lint Issue"
            description = message or f"actionlint issue in {filepath}:{line}"

            evidence_list = [Evidence(
                evidence_type="cicd_lint",
                title=f"actionlint: {kind}",
                content=(
                    f"File: {filepath}\n"
                    f"Line: {line}\n"
                    f"Column: {column}\n"
                    f"Kind: {kind}\n"
                    f"Message: {message}"
                ),
                content_type="text/plain",
            )]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                target=filepath,
                affected_component=affected_component,
                finding_type="misconfiguration",
                source_plugin="actionlint",
                source_tool_ref=kind,
                evidence=evidence_list,
                raw_data=item,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # s3scanner
    # ------------------------------------------------------------------

    @staticmethod
    def from_s3scanner(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert S3Scanner public bucket findings to Finding objects.

        Severity mapping:
        - Public write access -> critical
        - Public read access -> high

        Args:
            parsed_data: Dict with key "public_buckets" (list of dicts with
                         bucket, exists, public_read, public_write) as produced
                         by S3ScannerPlugin.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for each publicly accessible S3 bucket.
        """
        public_buckets: list[dict[str, Any]] = parsed_data.get("public_buckets", [])
        if not isinstance(public_buckets, list):
            public_buckets = []

        findings: list[Finding] = []

        for bucket in public_buckets:
            bucket_name = bucket.get("bucket", "")
            public_read = bucket.get("public_read", False)
            public_write = bucket.get("public_write", False)

            if not bucket_name:
                continue

            if public_write:
                severity = Severity.critical
                title = f"S3 Bucket Publicly Writable: {bucket_name}"
                description = (
                    f"The S3 bucket '{bucket_name}' is publicly writable. "
                    "Anyone on the internet can upload, modify, or delete objects in this bucket. "
                    "This can lead to data tampering, malware hosting, or full data loss."
                )
            else:
                severity = Severity.high
                title = f"S3 Bucket Publicly Readable: {bucket_name}"
                description = (
                    f"The S3 bucket '{bucket_name}' is publicly readable. "
                    "Anyone on the internet can list and download objects from this bucket, "
                    "potentially exposing sensitive data."
                )

            permissions_str = []
            if public_read:
                permissions_str.append("READ")
            if public_write:
                permissions_str.append("WRITE")

            evidence_list = [Evidence(
                evidence_type="cloud_scan",
                title=f"S3 Bucket: {bucket_name}",
                content=(
                    f"Bucket: {bucket_name}\n"
                    f"Public Read: {public_read}\n"
                    f"Public Write: {public_write}\n"
                    f"Permissions: {', '.join(permissions_str)}"
                ),
                content_type="text/plain",
            )]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                target=bucket_name,
                affected_component="S3 Bucket",
                finding_type="misconfiguration",
                source_plugin="s3scanner",
                source_tool_ref=bucket_name,
                evidence=evidence_list,
                raw_data=bucket,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # confused
    # ------------------------------------------------------------------

    @staticmethod
    def from_confused(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert confused dependency confusion findings to Finding objects.

        All dependency confusion findings are treated as high severity.

        Args:
            parsed_data: Dict with key "dependency_confusion" (dict with
                         vulnerable_packages list and total_found count)
                         as produced by ConfusedPlugin. Also supports a
                         "findings" key with richer dicts.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for each dependency confusion vulnerability.
        """
        findings: list[Finding] = []

        # Support richer findings list from PluginOutput.findings
        raw_findings: list[dict[str, Any]] = parsed_data.get("findings", [])
        if raw_findings:
            for item in raw_findings:
                package_name = item.get("package_name", "")
                title = item.get("title", f"Dependency Confusion: {package_name}")
                description = item.get("description", "")
                registry_info = item.get("registry_info", "")

                evidence_list = [Evidence(
                    evidence_type="supply_chain",
                    title=f"Dependency Confusion: {package_name}",
                    content=(
                        f"Package: {package_name}\n"
                        f"Registry: {registry_info}\n"
                        f"Raw: {item.get('raw_line', '')}"
                    ),
                    content_type="text/plain",
                )]

                finding = Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title=title,
                    description=description,
                    severity=Severity.high,
                    target=package_name,
                    affected_component=package_name,
                    finding_type="vulnerability",
                    source_plugin="confused",
                    source_tool_ref=package_name,
                    evidence=evidence_list,
                    raw_data=item,
                )
                findings.append(finding)
            return findings

        # Fallback: use dependency_confusion.vulnerable_packages list
        confusion_data = parsed_data.get("dependency_confusion", {})
        if not isinstance(confusion_data, dict):
            return findings

        packages: list[str] = confusion_data.get("vulnerable_packages", [])
        for package_name in packages:
            if not package_name:
                continue

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=f"Dependency Confusion: {package_name}",
                description=(
                    f"The internal package '{package_name}' was found on a public registry. "
                    "An attacker could upload a malicious package with this name and a higher "
                    "version number, causing build systems to pull the malicious version."
                ),
                severity=Severity.high,
                target=package_name,
                affected_component=package_name,
                finding_type="vulnerability",
                source_plugin="confused",
                source_tool_ref=package_name,
                evidence=[Evidence(
                    evidence_type="supply_chain",
                    title=f"Dependency Confusion: {package_name}",
                    content=f"Package: {package_name}",
                    content_type="text/plain",
                )],
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # winpeas
    # ------------------------------------------------------------------

    @staticmethod
    def from_winpeas(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert WinPEAS privilege escalation results into Finding objects.

        Severity mapping (from winpeas confidence percentages):
        - 95% -> critical
        - 70% -> high
        - 50% -> medium

        Args:
            parsed_data: Dict with a "findings" key (list of dicts from
                         WinpeasPlugin PluginOutput.findings) containing
                         severity, title, confidence_pct, raw_line.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for Windows privilege escalation vectors.
        """
        _PCT_TO_SEVERITY: dict[int, Severity] = {
            95: Severity.critical,
            70: Severity.high,
            50: Severity.medium,
        }
        _NAME_TO_SEVERITY: dict[str, Severity] = {
            "critical": Severity.critical,
            "high": Severity.high,
            "medium": Severity.medium,
            "low": Severity.low,
        }

        findings: list[Finding] = []

        raw_list: list[dict[str, Any]] = parsed_data.get("findings", [])
        if not isinstance(raw_list, list):
            raw_list = []

        for item in raw_list:
            title = item.get("title", "Windows Privilege Escalation Vector")
            description = item.get("description", title)
            pct: int | None = item.get("confidence_pct")
            severity_str: str = item.get("severity", "medium")

            if pct is not None and pct in _PCT_TO_SEVERITY:
                severity = _PCT_TO_SEVERITY[pct]
            else:
                severity = _NAME_TO_SEVERITY.get(severity_str.lower(), Severity.medium)

            findings.append(Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                target="localhost",
                affected_component="Windows OS",
                finding_type="vulnerability",
                source_plugin="winpeas",
                evidence=[Evidence(
                    evidence_type="privesc_scan",
                    title="WinPEAS Finding",
                    content=item.get("raw_line", title),
                    content_type="text/plain",
                )],
                raw_data=item,
            ))

        return findings

    # ------------------------------------------------------------------
    # wafw00f
    # ------------------------------------------------------------------

    @staticmethod
    def from_wafw00f(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert wafw00f WAF detection results to informational findings.

        Args:
            parsed_data: Dict with key "results" (list of dicts with url/detected/waf)
                         or similar structure.
            scan_id: Identifier of the parent scan.

        Returns:
            List of informational Finding objects describing detected WAFs.
        """
        results: list[dict[str, Any]] = parsed_data.get("results", parsed_data) if isinstance(parsed_data, dict) else parsed_data
        if not isinstance(results, list):
            results = [results]

        findings: list[Finding] = []

        for result in results:
            url = result.get("url", result.get("target", ""))
            detected = result.get("detected", False)
            waf_name = result.get("firewall", result.get("waf", result.get("manufacturer", "")))
            manufacturer = result.get("manufacturer", "")

            if not detected:
                # No WAF detected is also informational
                finding = Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title="No WAF Detected",
                    description=(
                        f"No Web Application Firewall (WAF) was detected for {url}. "
                        "The application may be exposed directly without WAF protection."
                    ),
                    severity=Severity.informational,
                    target=url,
                    affected_component="WAF",
                    finding_type="exposure",
                    source_plugin="wafw00f",
                    raw_data=result,
                )
                findings.append(finding)
                continue

            waf_label = waf_name
            if manufacturer and manufacturer != waf_name:
                waf_label = f"{waf_name} ({manufacturer})"

            evidence_list = [Evidence(
                evidence_type="waf_detection",
                title="WAF Detection Result",
                content=f"URL: {url}\nWAF: {waf_label}\nDetected: {detected}",
                content_type="text/plain",
            )]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=f"WAF Detected: {waf_label}",
                description=(
                    f"A Web Application Firewall ({waf_label}) was detected in front of {url}. "
                    "This is informational — WAF presence indicates defensive posture but does not "
                    "guarantee complete protection."
                ),
                severity=Severity.informational,
                target=url,
                affected_component="WAF",
                finding_type="exposure",
                source_plugin="wafw00f",
                evidence=evidence_list,
                raw_data=result,
            )
            findings.append(finding)

        return findings


# ---------------------------------------------------------------------------
# NORMALIZERS registry — maps plugin name to FindingFactory method
# ---------------------------------------------------------------------------

NORMALIZERS: dict[str, Any] = {
    "nuclei": FindingFactory.from_nuclei,
    "nmap": FindingFactory.from_nmap,
    "testssl": FindingFactory.from_testssl,
    "checkdmarc": FindingFactory.from_checkdmarc,
    "trufflehog": FindingFactory.from_trufflehog,
    "wafw00f": FindingFactory.from_wafw00f,
    "prowler": FindingFactory.from_prowler,
    "gitleaks": FindingFactory.from_gitleaks,
    "trivy": FindingFactory.from_trivy,
    "dnstwist": FindingFactory.from_dnstwist,
    "crtsh": FindingFactory.from_crtsh,
    "sslyze": FindingFactory.from_sslyze,
    "bloodhound": FindingFactory.from_bloodhound,
    "certipy": FindingFactory.from_certipy,
    "netexec": FindingFactory.from_netexec,
    "linpeas": FindingFactory.from_linpeas,
    "semgrep": FindingFactory.from_semgrep,
    "bandit": FindingFactory.from_bandit,
    "checkov": FindingFactory.from_checkov,
    "kube-bench": FindingFactory.from_kube_bench,
    "poutine": FindingFactory.from_poutine,
    "subfinder": FindingFactory.from_subfinder,
    "httpx": FindingFactory.from_httpx,
    "shodan": FindingFactory.from_shodan,
    "trivy-k8s": FindingFactory.from_trivy_k8s,
    "swaks": FindingFactory.from_swaks,
    "actionlint": FindingFactory.from_actionlint,
    "s3scanner": FindingFactory.from_s3scanner,
    "confused": FindingFactory.from_confused,
    "winpeas": FindingFactory.from_winpeas,
}
