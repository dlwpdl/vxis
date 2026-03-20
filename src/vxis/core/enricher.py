"""Finding enricher for VXIS security automation platform.

Adds contextual metadata to normalized findings including CVSS scores,
MITRE ATT&CK classifications, compliance control mappings, and generic
remediation guidance.

Phase 0 implementation: all enrichment is static/heuristic.
Phase 1+ will add NVD API lookups and live MITRE data.
"""

from __future__ import annotations

from vxis.models.finding import CVSSVector, Finding, MitreAttack, Severity


# ---------------------------------------------------------------------------
# Static mapping constants
# ---------------------------------------------------------------------------

#: Maps finding_type to MITRE ATT&CK technique metadata.
#: Format: finding_type → (tactic_id, tactic_name, technique_id, technique_name, subtechnique_id)
MITRE_MAPPING: dict[str, tuple[str, str, str, str, str | None]] = {
    "vulnerability": ("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application", None),
    "exposure": ("TA0009", "Collection", "T1530", "Data from Cloud Storage", None),
    "misconfiguration": ("TA0003", "Persistence", "T1574", "Hijack Execution Flow", None),
    "secret": ("TA0006", "Credential Access", "T1552", "Unsecured Credentials", "T1552.001"),
    "sqli": ("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application", None),
    "xss": ("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application", None),
    "rce": ("TA0002", "Execution", "T1203", "Exploitation for Client Execution", None),
    "lfi": ("TA0007", "Discovery", "T1083", "File and Directory Discovery", None),
    "ssrf": ("TA0009", "Collection", "T1090", "Proxy", None),
    "injection": ("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application", None),
    "takeover": ("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application", None),
}

#: Maps finding_type to compliance control references.
#: Format: finding_type → {"iso27001": [...], "soc2": [...]}
COMPLIANCE_MAPPING: dict[str, dict[str, list[str]]] = {
    "vulnerability": {
        "iso27001": ["A.12.6.1", "A.14.2.2"],
        "soc2": ["CC7.1", "CC7.2"],
    },
    "exposure": {
        "iso27001": ["A.8.2.1", "A.13.1.1"],
        "soc2": ["CC6.1", "CC6.6"],
    },
    "misconfiguration": {
        "iso27001": ["A.12.1.2", "A.14.1.2"],
        "soc2": ["CC6.1", "CC6.3"],
    },
    "secret": {
        "iso27001": ["A.9.2.4", "A.10.1.1"],
        "soc2": ["CC6.1", "CC6.7"],
    },
    "sqli": {
        "iso27001": ["A.14.2.5", "A.12.6.1"],
        "soc2": ["CC7.1", "CC8.1"],
    },
    "xss": {
        "iso27001": ["A.14.2.5", "A.12.6.1"],
        "soc2": ["CC7.1", "CC8.1"],
    },
    "rce": {
        "iso27001": ["A.12.6.1", "A.14.2.2"],
        "soc2": ["CC7.1", "CC7.2"],
    },
    "lfi": {
        "iso27001": ["A.12.6.1", "A.14.2.5"],
        "soc2": ["CC7.1", "CC6.1"],
    },
    "ssrf": {
        "iso27001": ["A.13.1.3", "A.14.2.5"],
        "soc2": ["CC6.6", "CC7.1"],
    },
    "injection": {
        "iso27001": ["A.14.2.5", "A.12.6.1"],
        "soc2": ["CC7.1", "CC8.1"],
    },
    "takeover": {
        "iso27001": ["A.12.6.1", "A.14.2.2"],
        "soc2": ["CC7.1", "CC7.2"],
    },
}

#: Maps finding_type to generic remediation guidance templates.
REMEDIATION_TEMPLATES: dict[str, str] = {
    "vulnerability": (
        "Apply the vendor-supplied patch or update the affected component to the latest stable version. "
        "If no patch is available, implement compensating controls such as WAF rules or network segmentation. "
        "Follow your organization's vulnerability management SLA based on severity."
    ),
    "exposure": (
        "Review whether the exposed resource or information should be publicly accessible. "
        "Apply appropriate access controls (authentication, authorization, network restrictions). "
        "Audit cloud storage permissions and ensure no sensitive data is publicly readable."
    ),
    "misconfiguration": (
        "Review and harden the configuration according to vendor security guidelines and CIS benchmarks. "
        "Implement configuration management to prevent drift. "
        "Regularly audit configurations against security baselines."
    ),
    "secret": (
        "Immediately revoke and rotate the exposed credential. "
        "Audit all systems that may have been accessed using the compromised secret. "
        "Implement secret scanning in CI/CD pipelines and use a secrets manager "
        "(e.g., HashiCorp Vault, AWS Secrets Manager) to prevent future exposure."
    ),
    "sqli": (
        "Use parameterized queries or prepared statements for all database interactions. "
        "Implement input validation and output encoding. "
        "Apply the principle of least privilege to database accounts. "
        "Consider deploying a WAF with SQLi detection rules."
    ),
    "xss": (
        "Implement proper output encoding for all user-supplied data rendered in HTML context. "
        "Set a strict Content Security Policy (CSP) header. "
        "Use modern frameworks that auto-escape output by default. "
        "Validate and sanitize all inputs server-side."
    ),
    "rce": (
        "Patch the vulnerable component immediately. "
        "Implement network segmentation to limit blast radius. "
        "Apply application-level input validation and sandbox execution environments. "
        "Enable runtime application self-protection (RASP) if available."
    ),
    "lfi": (
        "Validate and sanitize all file path inputs. "
        "Use an allowlist of permitted file paths rather than a blocklist. "
        "Run the application with minimal filesystem permissions. "
        "Disable directory listing and restrict access to sensitive directories."
    ),
    "ssrf": (
        "Validate and restrict URL inputs to allowlisted domains and IP ranges. "
        "Block requests to internal network ranges (RFC 1918 addresses, 169.254.0.0/16). "
        "Use a dedicated egress proxy to control outbound traffic from the application."
    ),
    "injection": (
        "Apply strict input validation and use parameterized interfaces for all injection sinks. "
        "Avoid constructing commands or queries from user-controlled input. "
        "Implement the principle of least privilege for all downstream systems."
    ),
    "takeover": (
        "Claim or remove the dangling resource immediately to prevent hostile takeover. "
        "Implement regular audits of DNS records, cloud resources, and third-party service configurations. "
        "Establish a process to decommission resources before removing DNS entries."
    ),
}

#: Derived CVSS base scores by severity for Phase 0 heuristic enrichment.
_SEVERITY_CVSS_SCORE: dict[Severity, float] = {
    Severity.critical: 9.5,
    Severity.high: 8.0,
    Severity.medium: 5.5,
    Severity.low: 2.5,
    Severity.informational: 0.0,
}

#: Derived CVSS vector strings by severity (simplified heuristic).
_SEVERITY_CVSS_VECTOR: dict[Severity, str] = {
    Severity.critical: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    Severity.high: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    Severity.medium: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    Severity.low: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
    Severity.informational: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}


# ---------------------------------------------------------------------------
# FindingEnricher
# ---------------------------------------------------------------------------


class FindingEnricher:
    """Enriches findings with CVSS, MITRE, compliance, and remediation metadata."""

    def enrich(self, findings: list[Finding]) -> list[Finding]:
        """Run all enrichment steps on each finding.

        Enrichment is non-destructive: existing values are never overwritten.

        Args:
            findings: List of normalized findings.

        Returns:
            Same list with enrichment metadata added in-place.
        """
        for finding in findings:
            self._enrich_cvss(finding)
            self._enrich_mitre(finding)
            self._enrich_compliance(finding)
            self._enrich_remediation(finding)
        return findings

    # ------------------------------------------------------------------
    # CVSS enrichment
    # ------------------------------------------------------------------

    def _enrich_cvss(self, finding: Finding) -> None:
        """Derive a heuristic CVSS score from severity if CVSS is not already set.

        Only applies when the finding has CVE IDs and no existing CVSS vector.
        (NVD API lookup is deferred to Phase 1+.)

        Args:
            finding: Finding to enrich in-place.
        """
        if finding.cvss is not None:
            return
        if not finding.cve_ids:
            return

        score = _SEVERITY_CVSS_SCORE.get(finding.severity, 0.0)
        vector = _SEVERITY_CVSS_VECTOR.get(finding.severity, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")

        finding.cvss = CVSSVector(
            vector_string=vector,
            base_score=score,
        )

    # ------------------------------------------------------------------
    # MITRE ATT&CK enrichment
    # ------------------------------------------------------------------

    def _enrich_mitre(self, finding: Finding) -> None:
        """Map finding_type to a MITRE ATT&CK technique if not already set.

        Args:
            finding: Finding to enrich in-place.
        """
        if finding.mitre_attack is not None:
            return

        mapping = MITRE_MAPPING.get(finding.finding_type)
        if mapping is None:
            return

        tactic_id, tactic_name, technique_id, technique_name, subtechnique_id = mapping
        finding.mitre_attack = MitreAttack(
            tactic_id=tactic_id,
            tactic_name=tactic_name,
            technique_id=technique_id,
            technique_name=technique_name,
            subtechnique_id=subtechnique_id,
        )

    # ------------------------------------------------------------------
    # Compliance enrichment
    # ------------------------------------------------------------------

    def _enrich_compliance(self, finding: Finding) -> None:
        """Map finding_type to compliance control references.

        Stores ISO 27001 and SOC 2 control numbers in analyst_notes
        if not already present. Existing analyst_notes are preserved.

        Args:
            finding: Finding to enrich in-place.
        """
        compliance = COMPLIANCE_MAPPING.get(finding.finding_type)
        if compliance is None:
            return

        iso_controls = ", ".join(compliance.get("iso27001", []))
        soc2_controls = ", ".join(compliance.get("soc2", []))

        compliance_note = (
            f"[compliance] ISO 27001: {iso_controls} | SOC 2: {soc2_controls}"
        )

        # Only append if compliance note not already present
        if finding.analyst_notes and "[compliance]" in finding.analyst_notes:
            return

        if finding.analyst_notes:
            finding.analyst_notes = finding.analyst_notes + "\n" + compliance_note
        else:
            finding.analyst_notes = compliance_note

    # ------------------------------------------------------------------
    # Remediation enrichment
    # ------------------------------------------------------------------

    def _enrich_remediation(self, finding: Finding) -> None:
        """Set a generic remediation template if no remediation is already set.

        Args:
            finding: Finding to enrich in-place.
        """
        if finding.remediation is not None:
            return

        template = REMEDIATION_TEMPLATES.get(finding.finding_type)
        if template is None:
            template = (
                "Review the finding details and apply appropriate security controls "
                "based on your organization's security policies and risk tolerance."
            )

        finding.remediation = template
