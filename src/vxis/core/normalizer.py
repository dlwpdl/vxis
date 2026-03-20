"""Post-processing normalizer for VXIS security automation platform.

Converts raw tool output (nuclei, nmap, testssl, checkdmarc, trufflehog, wafw00f)
into canonical Finding objects and provides deduplication utilities.
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from typing import Any

from vxis.models.evidence import mask_secret
from vxis.models.finding import Evidence, Finding, Severity


# ---------------------------------------------------------------------------
# Severity mapping helpers
# ---------------------------------------------------------------------------

_NUCLEI_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.informational,
    "informational": Severity.informational,
    "unknown": Severity.informational,
}

_TESTSSL_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "warn": Severity.low,
    "fatal": Severity.critical,
}

_TESTSSL_SKIP_SEVERITIES: set[str] = {"ok", "info", "not tested", "not offered"}

_TRUFFLEHOG_CLOUD_DETECTOR_PATTERNS: list[str] = [
    "aws",
    "gcp",
    "azure",
    "github",
    "gitlab",
    "slack",
    "stripe",
    "twilio",
    "sendgrid",
]


def _make_id() -> str:
    return str(uuid.uuid4())


def _extract_cve_ids(data: dict[str, Any]) -> list[str]:
    """Extract CVE IDs from nuclei info.classification or tags."""
    cve_ids: list[str] = []
    classification = data.get("info", {}).get("classification", {})
    raw_cves: list[str] = classification.get("cve-id", []) or []
    if isinstance(raw_cves, str):
        raw_cves = [raw_cves]
    for cve in raw_cves:
        normalized = cve.upper().strip()
        if re.match(r"CVE-\d{4}-\d+", normalized):
            cve_ids.append(normalized)

    # Also scan tags for CVE patterns
    tags: list[str] = data.get("info", {}).get("tags", []) or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    for tag in tags:
        match = re.search(r"(CVE-\d{4}-\d+)", tag, re.IGNORECASE)
        if match:
            cve_id = match.group(1).upper()
            if cve_id not in cve_ids:
                cve_ids.append(cve_id)

    return cve_ids


# ---------------------------------------------------------------------------
# FindingFactory
# ---------------------------------------------------------------------------


class FindingFactory:
    """Convert raw tool-specific output into canonical Finding objects."""

    # ------------------------------------------------------------------
    # nuclei
    # ------------------------------------------------------------------

    @staticmethod
    def from_nuclei(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert nuclei JSON findings to Finding objects.

        Args:
            parsed_data: Dict with key "results" containing a list of nuclei
                         JSON result objects, or a list directly.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects derived from the nuclei output.
        """
        results: list[dict[str, Any]] = parsed_data.get("results", parsed_data) if isinstance(parsed_data, dict) else parsed_data
        if not isinstance(results, list):
            results = [results]

        findings: list[Finding] = []

        for result in results:
            info = result.get("info", {})
            severity_str = info.get("severity", "informational").lower()
            severity = _NUCLEI_SEVERITY_MAP.get(severity_str, Severity.informational)

            host = result.get("host", result.get("ip", ""))
            matched_at = result.get("matched-at", host)
            template_id = result.get("template-id", result.get("templateID", ""))
            name = info.get("name", template_id)
            description = info.get("description", name)

            cve_ids = _extract_cve_ids(result)

            # Build evidence from request/response if present
            evidence_list: list[Evidence] = []
            request_data = result.get("request", "")
            response_data = result.get("response", "")
            if request_data:
                evidence_list.append(Evidence(
                    evidence_type="http_request",
                    title="HTTP Request",
                    content=str(request_data),
                    content_type="text/plain",
                ))
            if response_data:
                evidence_list.append(Evidence(
                    evidence_type="http_response",
                    title="HTTP Response",
                    content=str(response_data),
                    content_type="text/plain",
                ))

            # Extract extracted data as evidence
            extracted = result.get("extracted-results", result.get("extractedResults", []))
            if extracted:
                evidence_list.append(Evidence(
                    evidence_type="extracted_data",
                    title="Extracted Results",
                    content=str(extracted),
                    content_type="text/plain",
                ))

            # Determine port from matched URL
            port: int | None = None
            protocol: str | None = None
            if matched_at:
                url_match = re.match(r"(https?)://[^:/]+(:\d+)?", matched_at)
                if url_match:
                    proto = url_match.group(1)
                    protocol = "tcp"
                    port_str = url_match.group(2)
                    if port_str:
                        port = int(port_str.lstrip(":"))
                    else:
                        port = 443 if proto == "https" else 80

            # Derive finding_type from tags or template-id
            tags: list[str] = info.get("tags", []) or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            finding_type = "vulnerability"
            type_hints = {
                "cve": "vulnerability",
                "sqli": "sqli",
                "xss": "xss",
                "rce": "rce",
                "lfi": "lfi",
                "ssrf": "ssrf",
                "exposure": "exposure",
                "misconfig": "misconfiguration",
                "misconfiguration": "misconfiguration",
                "takeover": "takeover",
                "injection": "injection",
            }
            for tag in tags:
                tag_lower = tag.lower()
                if tag_lower in type_hints:
                    finding_type = type_hints[tag_lower]
                    break

            references_raw = info.get("reference", []) or []
            if isinstance(references_raw, str):
                references_raw = [references_raw]
            from vxis.models.finding import Reference
            references = [
                Reference(title=ref, url=ref)
                for ref in references_raw
                if isinstance(ref, str) and ref.startswith("http")
            ]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=name,
                description=description,
                severity=severity,
                target=host,
                affected_component=matched_at,
                port=port,
                protocol=protocol,
                finding_type=finding_type,
                cve_ids=cve_ids,
                source_plugin="nuclei",
                source_tool_ref=template_id,
                evidence=evidence_list,
                references=references,
                raw_data=result,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # nmap
    # ------------------------------------------------------------------

    @staticmethod
    def from_nmap(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert nmap host/port data to Finding objects.

        Open ports are represented as informational exposure findings.

        Args:
            parsed_data: Dict with key "hosts" containing a list of host
                         objects, each with a "ports" list.
            scan_id: Identifier of the parent scan.

        Returns:
            List of informational Finding objects for each open port.
        """
        hosts: list[dict[str, Any]] = parsed_data.get("hosts", [])
        findings: list[Finding] = []

        for host in hosts:
            host_addr = host.get("address", host.get("ip", ""))
            hostname = host.get("hostname", "")
            target = hostname if hostname else host_addr

            ports: list[dict[str, Any]] = host.get("ports", [])
            for port_info in ports:
                state = port_info.get("state", "").lower()
                if state != "open":
                    continue

                port_num: int | None = None
                raw_port = port_info.get("port", port_info.get("portid"))
                if raw_port is not None:
                    try:
                        port_num = int(raw_port)
                    except (ValueError, TypeError):
                        port_num = None

                protocol = port_info.get("protocol", "tcp").lower()
                service = port_info.get("service", {})
                service_name = service.get("name", "") if isinstance(service, dict) else str(service)
                product = service.get("product", "") if isinstance(service, dict) else ""
                version = service.get("version", "") if isinstance(service, dict) else ""

                title = f"Open Port: {port_num}/{protocol}"
                if service_name:
                    title += f" ({service_name})"

                description_parts = [f"Open port {port_num}/{protocol} detected on {target}."]
                if service_name:
                    description_parts.append(f"Service: {service_name}")
                if product:
                    description_parts.append(f"Product: {product}")
                    if version:
                        description_parts[-1] += f" {version}"
                description = " ".join(description_parts)

                evidence_content = f"Port: {port_num}/{protocol}\nState: open\nService: {service_name}"
                if product:
                    evidence_content += f"\nProduct: {product} {version}".rstrip()

                evidence_list = [Evidence(
                    evidence_type="port_scan",
                    title="Nmap Port Scan Result",
                    content=evidence_content,
                    content_type="text/plain",
                )]

                finding = Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title=title,
                    description=description,
                    severity=Severity.informational,
                    target=target,
                    affected_component=service_name,
                    port=port_num,
                    protocol=protocol,
                    finding_type="exposure",
                    source_plugin="nmap",
                    evidence=evidence_list,
                    raw_data=port_info,
                )
                findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # testssl
    # ------------------------------------------------------------------

    @staticmethod
    def from_testssl(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert testssl findings, skipping OK/INFO severity.

        Args:
            parsed_data: Dict with key "findings" (list) or direct list of
                         testssl finding objects.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for actionable TLS issues.
        """
        raw_findings: list[dict[str, Any]] = parsed_data.get("findings", parsed_data) if isinstance(parsed_data, dict) else parsed_data
        if not isinstance(raw_findings, list):
            raw_findings = [raw_findings]

        findings: list[Finding] = []
        target = parsed_data.get("target_host", parsed_data.get("targetHost", "")) if isinstance(parsed_data, dict) else ""
        port_raw = parsed_data.get("port", 443) if isinstance(parsed_data, dict) else 443

        try:
            default_port = int(port_raw)
        except (ValueError, TypeError):
            default_port = 443

        for item in raw_findings:
            severity_str = item.get("severity", item.get("finding_severity", "")).lower()

            # Skip OK and INFO results
            if severity_str in _TESTSSL_SKIP_SEVERITIES:
                continue

            severity = _TESTSSL_SEVERITY_MAP.get(severity_str, Severity.low)

            item_id = item.get("id", "")
            finding_str = item.get("finding", item.get("output", ""))
            cve_str = item.get("cve", "")

            cve_ids: list[str] = []
            if cve_str:
                for part in cve_str.split():
                    normalized = part.upper().strip(",;")
                    if re.match(r"CVE-\d{4}-\d+", normalized):
                        cve_ids.append(normalized)

            item_target = item.get("ip", item.get("host", target))
            item_port_raw = item.get("port", default_port)
            try:
                item_port = int(item_port_raw)
            except (ValueError, TypeError):
                item_port = default_port

            title = item.get("id", "TLS Issue")
            description = finding_str or f"TLS issue detected: {item_id}"

            evidence_list = [Evidence(
                evidence_type="tls_scan",
                title=f"testssl Finding: {item_id}",
                content=f"ID: {item_id}\nFinding: {finding_str}",
                content_type="text/plain",
            )]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                target=item_target,
                affected_component="TLS/SSL",
                port=item_port,
                protocol="tcp",
                finding_type="misconfiguration",
                cve_ids=cve_ids,
                source_plugin="testssl",
                source_tool_ref=item_id,
                evidence=evidence_list,
                raw_data=item,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # checkdmarc
    # ------------------------------------------------------------------

    @staticmethod
    def from_checkdmarc(parsed_data: dict[str, Any], scan_id: str, domain: str) -> list[Finding]:
        """Analyze SPF/DMARC configuration and generate findings for misconfigurations.

        Severity mapping:
        - Missing DMARC record → critical
        - DMARC p=none → high
        - DMARC p=quarantine with pct<100 → medium
        - SPF ~all (softfail) → medium
        - SPF ?all (neutral) → medium
        - Missing SPF → high
        - SPF +all (passall) → critical

        Args:
            parsed_data: checkdmarc parsed output dict.
            scan_id: Identifier of the parent scan.
            domain: The domain being analyzed.

        Returns:
            List of Finding objects for email security misconfigurations.
        """
        findings: list[Finding] = []
        dmarc = parsed_data.get("dmarc", {})
        spf = parsed_data.get("spf", {})

        # --- DMARC checks ---
        dmarc_valid = dmarc.get("valid", False)
        dmarc_record = dmarc.get("record", "")
        dmarc_tags = dmarc.get("tags", {})

        if not dmarc_record and not dmarc_valid:
            findings.append(Finding(
                id=_make_id(),
                scan_id=scan_id,
                title="Missing DMARC Record",
                description=(
                    f"The domain {domain} does not have a DMARC record. "
                    "Without DMARC, the domain is vulnerable to email spoofing and phishing attacks."
                ),
                severity=Severity.critical,
                target=domain,
                affected_component="DMARC",
                finding_type="misconfiguration",
                source_plugin="checkdmarc",
                remediation=(
                    "Publish a DMARC TXT record at _dmarc." + domain +
                    " with at least p=quarantine. Example: "
                    "v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain
                ),
            ))
        else:
            p_tag = dmarc_tags.get("p", {})
            policy = p_tag.get("value", "") if isinstance(p_tag, dict) else str(p_tag)

            if policy == "none":
                findings.append(Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title="DMARC Policy Set to 'none' (Monitor Only)",
                    description=(
                        f"The domain {domain} has a DMARC record but its policy is 'p=none', "
                        "which means no enforcement is applied. Spoofed emails will still be delivered."
                    ),
                    severity=Severity.high,
                    target=domain,
                    affected_component="DMARC",
                    finding_type="misconfiguration",
                    source_plugin="checkdmarc",
                    remediation="Upgrade DMARC policy to p=quarantine or p=reject to enforce protection.",
                ))
            elif policy == "quarantine":
                pct_tag = dmarc_tags.get("pct", {})
                pct_value = pct_tag.get("value", 100) if isinstance(pct_tag, dict) else 100
                try:
                    pct = int(pct_value)
                except (ValueError, TypeError):
                    pct = 100

                if pct < 100:
                    findings.append(Finding(
                        id=_make_id(),
                        scan_id=scan_id,
                        title=f"DMARC Quarantine Policy Applied to Only {pct}% of Emails",
                        description=(
                            f"The DMARC record for {domain} uses p=quarantine but pct={pct}, "
                            f"meaning {100 - pct}% of failing emails bypass enforcement."
                        ),
                        severity=Severity.medium,
                        target=domain,
                        affected_component="DMARC",
                        finding_type="misconfiguration",
                        source_plugin="checkdmarc",
                        remediation="Set pct=100 to apply the quarantine policy to all emails.",
                    ))

            # Check for DMARC parse errors
            dmarc_errors = dmarc.get("errors", [])
            for error in dmarc_errors:
                findings.append(Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title=f"DMARC Configuration Error: {error}",
                    description=f"checkdmarc reported an error in the DMARC record for {domain}: {error}",
                    severity=Severity.medium,
                    target=domain,
                    affected_component="DMARC",
                    finding_type="misconfiguration",
                    source_plugin="checkdmarc",
                ))

        # --- SPF checks ---
        spf_valid = spf.get("valid", False)
        spf_record = spf.get("record", "")

        if not spf_record and not spf_valid:
            findings.append(Finding(
                id=_make_id(),
                scan_id=scan_id,
                title="Missing SPF Record",
                description=(
                    f"The domain {domain} does not have an SPF record. "
                    "Without SPF, any server can send email claiming to be from this domain."
                ),
                severity=Severity.high,
                target=domain,
                affected_component="SPF",
                finding_type="misconfiguration",
                source_plugin="checkdmarc",
                remediation=(
                    f"Publish an SPF TXT record at {domain}. Example: "
                    "v=spf1 include:_spf.google.com -all"
                ),
            ))
        else:
            # Check SPF all mechanism
            all_mechanism: str = ""
            if spf_record:
                match = re.search(r"([~?+\-])all", spf_record)
                if match:
                    all_mechanism = match.group(0)

            if "+all" in (all_mechanism or ""):
                findings.append(Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title="SPF Record Allows All Senders (+all)",
                    description=(
                        f"The SPF record for {domain} uses '+all', which allows any server "
                        "to send email on behalf of this domain, making SPF protection ineffective."
                    ),
                    severity=Severity.critical,
                    target=domain,
                    affected_component="SPF",
                    finding_type="misconfiguration",
                    source_plugin="checkdmarc",
                    remediation="Replace '+all' with '-all' to reject unauthorized senders.",
                ))
            elif "~all" in (all_mechanism or ""):
                findings.append(Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title="SPF Record Uses Softfail (~all)",
                    description=(
                        f"The SPF record for {domain} uses '~all' (softfail), which marks "
                        "unauthorized senders as suspicious but does not reject them. "
                        "Many mail servers will still deliver these emails."
                    ),
                    severity=Severity.medium,
                    target=domain,
                    affected_component="SPF",
                    finding_type="misconfiguration",
                    source_plugin="checkdmarc",
                    remediation="Upgrade SPF policy from '~all' to '-all' to enforce rejection.",
                ))
            elif "?all" in (all_mechanism or ""):
                findings.append(Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title="SPF Record Uses Neutral (?all)",
                    description=(
                        f"The SPF record for {domain} uses '?all' (neutral), which provides "
                        "no guidance to mail servers about unauthorized senders."
                    ),
                    severity=Severity.medium,
                    target=domain,
                    affected_component="SPF",
                    finding_type="misconfiguration",
                    source_plugin="checkdmarc",
                    remediation="Replace '?all' with '-all' to enforce SPF rejection.",
                ))

            # SPF errors
            spf_errors = spf.get("errors", [])
            for error in spf_errors:
                findings.append(Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title=f"SPF Configuration Error: {error}",
                    description=f"checkdmarc reported an error in the SPF record for {domain}: {error}",
                    severity=Severity.medium,
                    target=domain,
                    affected_component="SPF",
                    finding_type="misconfiguration",
                    source_plugin="checkdmarc",
                ))

        return findings

    # ------------------------------------------------------------------
    # trufflehog
    # ------------------------------------------------------------------

    @staticmethod
    def from_trufflehog(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert TruffleHog secret findings with masked secret values.

        Severity rules:
        - Verified secrets → critical
        - Cloud provider keys (AWS, GCP, Azure, GitHub, etc.) → high
        - All others → medium

        Args:
            parsed_data: Dict with key "results" (list) or direct list of
                         trufflehog result objects.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for detected secrets.
        """
        results: list[dict[str, Any]] = parsed_data.get("results", parsed_data) if isinstance(parsed_data, dict) else parsed_data
        if not isinstance(results, list):
            results = [results]

        findings: list[Finding] = []

        for result in results:
            detector_name = result.get("DetectorName", result.get("detector_name", "Unknown"))
            verified = result.get("Verified", result.get("verified", False))

            source_metadata = result.get("SourceMetadata", result.get("source_metadata", {}))
            data_meta = source_metadata.get("Data", {}) if isinstance(source_metadata, dict) else {}

            # Extract location info
            file_path_str = ""
            target = ""
            for loc_key in ("Git", "Filesystem", "Github", "S3", "GCS"):
                loc_data = data_meta.get(loc_key, {})
                if loc_data:
                    file_path_str = loc_data.get("file", loc_data.get("filename", ""))
                    target = loc_data.get("repository", loc_data.get("link", loc_data.get("bucket", file_path_str)))
                    break

            if not target:
                target = result.get("source_name", result.get("SourceName", "unknown"))

            raw_value = result.get("Raw", result.get("raw", ""))
            masked_value = mask_secret(str(raw_value)) if raw_value else ""

            # Determine severity
            detector_lower = detector_name.lower()
            if verified:
                severity = Severity.critical
            elif any(provider in detector_lower for provider in _TRUFFLEHOG_CLOUD_DETECTOR_PATTERNS):
                severity = Severity.high
            else:
                severity = Severity.medium

            title = f"Secret Detected: {detector_name}"
            description = (
                f"A secret of type '{detector_name}' was detected. "
                f"Verified: {verified}. "
                f"Masked value: {masked_value}"
            )
            if file_path_str:
                description += f"\nFile: {file_path_str}"

            evidence_list = [Evidence(
                evidence_type="secret",
                title=f"Detected Secret ({detector_name})",
                content=f"Detector: {detector_name}\nVerified: {verified}\nMasked Value: {masked_value}",
                content_type="text/plain",
            )]
            if file_path_str:
                evidence_list.append(Evidence(
                    evidence_type="file_reference",
                    title="Source File",
                    content=file_path_str,
                    content_type="text/plain",
                ))

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                target=target,
                affected_component=file_path_str,
                finding_type="secret",
                source_plugin="trufflehog",
                source_tool_ref=detector_name,
                evidence=evidence_list,
                raw_data=result,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # prowler
    # ------------------------------------------------------------------

    @staticmethod
    def from_prowler(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert Prowler FAIL results to Finding objects.

        Severity is derived directly from Prowler's severity field.

        Args:
            parsed_data: Dict with key "cloud_findings" (list) produced by ProwlerPlugin,
                         or a raw list of Prowler check result dicts.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for all FAIL checks.
        """
        _prowler_severity_map: dict[str, Severity] = {
            "critical": Severity.critical,
            "high": Severity.high,
            "medium": Severity.medium,
            "low": Severity.low,
            "informational": Severity.informational,
        }

        raw_findings: list[dict[str, Any]] = (
            parsed_data.get("cloud_findings", parsed_data)
            if isinstance(parsed_data, dict)
            else parsed_data
        )
        if not isinstance(raw_findings, list):
            raw_findings = [raw_findings]

        findings: list[Finding] = []

        for item in raw_findings:
            severity_str = str(item.get("severity", "medium")).lower()
            severity = _prowler_severity_map.get(severity_str, Severity.medium)

            check_id = item.get("check_id", "")
            service_name = item.get("service_name", "")
            description = item.get("description", "")
            risk = item.get("risk", "")
            remediation = item.get("remediation", "")
            resource_arn = item.get("resource_arn", "")

            title = f"Cloud Misconfiguration: {check_id}" if check_id else "Cloud Misconfiguration"

            evidence_list = [Evidence(
                evidence_type="cloud_audit",
                title=f"Prowler Check: {check_id}",
                content=(
                    f"CheckID: {check_id}\n"
                    f"Service: {service_name}\n"
                    f"Status: FAIL\n"
                    f"Risk: {risk}\n"
                    f"Resource: {resource_arn}"
                ),
                content_type="text/plain",
            )]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=severity,
                target=resource_arn or service_name,
                affected_component=service_name,
                finding_type="misconfiguration",
                source_plugin="prowler",
                source_tool_ref=check_id,
                remediation=remediation,
                evidence=evidence_list,
                raw_data=item,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # gitleaks
    # ------------------------------------------------------------------

    @staticmethod
    def from_gitleaks(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert Gitleaks secret findings to Finding objects with masked secret values.

        All gitleaks findings are treated as high severity; secrets with AWS/cloud
        rule IDs are elevated to critical.

        Args:
            parsed_data: Dict with key "code_secrets" (list) produced by GitleaksPlugin,
                         or a raw list of gitleaks result dicts.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for detected secrets.
        """
        _cloud_rule_patterns: list[str] = ["aws", "gcp", "azure", "github", "gitlab", "stripe"]

        raw_findings: list[dict[str, Any]] = (
            parsed_data.get("code_secrets", parsed_data)
            if isinstance(parsed_data, dict)
            else parsed_data
        )
        if not isinstance(raw_findings, list):
            raw_findings = [raw_findings]

        findings: list[Finding] = []

        for item in raw_findings:
            rule_id = item.get("rule_id", "")
            description = item.get("description", "")
            file_path = item.get("file", "")
            start_line = item.get("start_line", 0)
            commit = item.get("commit", "")
            masked_secret = item.get("secret", "")

            # Re-mask raw secret if it slipped through without masking.
            if masked_secret and "*" not in masked_secret:
                masked_secret = mask_secret(masked_secret)

            rule_lower = rule_id.lower()
            if any(pattern in rule_lower for pattern in _cloud_rule_patterns):
                severity = Severity.critical
            else:
                severity = Severity.high

            title = f"Secret Detected: {rule_id}" if rule_id else "Secret Detected"
            full_description = (
                f"{description}\n"
                f"File: {file_path} (line {start_line})\n"
                f"Commit: {commit}\n"
                f"Secret (masked): {masked_secret}"
            ).strip()

            evidence_list = [Evidence(
                evidence_type="secret",
                title=f"Gitleaks Finding: {rule_id}",
                content=(
                    f"RuleID: {rule_id}\n"
                    f"File: {file_path}\n"
                    f"Line: {start_line}\n"
                    f"Commit: {commit}\n"
                    f"Masked Secret: {masked_secret}"
                ),
                content_type="text/plain",
            )]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=full_description,
                severity=severity,
                target=file_path,
                affected_component=file_path,
                finding_type="secret",
                source_plugin="gitleaks",
                source_tool_ref=rule_id,
                evidence=evidence_list,
                raw_data=item,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # trivy
    # ------------------------------------------------------------------

    @staticmethod
    def from_trivy(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert Trivy dependency vulnerability findings to Finding objects.

        Args:
            parsed_data: Dict with key "dependency_vulns" (list) produced by TrivyPlugin,
                         or a raw list of vulnerability dicts.
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects, each representing a CVE in a dependency.
        """
        _trivy_severity_map: dict[str, Severity] = {
            "CRITICAL": Severity.critical,
            "HIGH": Severity.high,
            "MEDIUM": Severity.medium,
            "LOW": Severity.low,
            "UNKNOWN": Severity.informational,
        }

        raw_findings: list[dict[str, Any]] = (
            parsed_data.get("dependency_vulns", parsed_data)
            if isinstance(parsed_data, dict)
            else parsed_data
        )
        if not isinstance(raw_findings, list):
            raw_findings = [raw_findings]

        findings: list[Finding] = []

        for item in raw_findings:
            vuln_id = item.get("vulnerability_id", "")
            pkg_name = item.get("pkg_name", "")
            installed_version = item.get("installed_version", "")
            fixed_version = item.get("fixed_version", "")
            severity_str = item.get("severity", "UNKNOWN")
            title_str = item.get("title", "")
            description_str = item.get("description", "")

            severity = _trivy_severity_map.get(severity_str.upper(), Severity.informational)

            # Extract CVE IDs from vulnerability_id field.
            cve_ids: list[str] = []
            if re.match(r"CVE-\d{4}-\d+", vuln_id, re.IGNORECASE):
                cve_ids.append(vuln_id.upper())

            title = title_str or f"Vulnerable Dependency: {pkg_name} ({vuln_id})"
            full_description = (
                f"{description_str}\n"
                f"Package: {pkg_name} {installed_version}\n"
                f"Fixed in: {fixed_version or 'N/A'}\n"
                f"CVE: {vuln_id}"
            ).strip()

            evidence_list = [Evidence(
                evidence_type="dependency_scan",
                title=f"Trivy Finding: {vuln_id}",
                content=(
                    f"VulnerabilityID: {vuln_id}\n"
                    f"Package: {pkg_name}\n"
                    f"InstalledVersion: {installed_version}\n"
                    f"FixedVersion: {fixed_version}\n"
                    f"Severity: {severity_str}"
                ),
                content_type="text/plain",
            )]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=full_description,
                severity=severity,
                target=pkg_name,
                affected_component=f"{pkg_name}@{installed_version}",
                finding_type="vulnerability",
                cve_ids=cve_ids,
                source_plugin="trivy",
                source_tool_ref=vuln_id,
                evidence=evidence_list,
                raw_data=item,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # dnstwist
    # ------------------------------------------------------------------

    @staticmethod
    def from_dnstwist(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert dnstwist lookalike domain results to Finding objects.

        All registered lookalike domains are treated as medium severity brand risk.

        Args:
            parsed_data: Dict with key "lookalike_domains" (list) produced by DnstwistPlugin,
                         or a raw list of domain dicts.
            scan_id: Identifier of the parent scan.

        Returns:
            List of medium-severity Finding objects for registered lookalike domains.
        """
        raw_findings: list[dict[str, Any]] = (
            parsed_data.get("lookalike_domains", parsed_data)
            if isinstance(parsed_data, dict)
            else parsed_data
        )
        if not isinstance(raw_findings, list):
            raw_findings = [raw_findings]

        findings: list[Finding] = []

        for item in raw_findings:
            fuzzer = item.get("fuzzer", "")
            domain = item.get("domain", "")
            dns_a: list[str] = item.get("dns_a", []) or []
            dns_mx: list[str] = item.get("dns_mx", []) or []

            if not domain:
                continue

            title = f"Lookalike Domain Registered: {domain}"
            description = (
                f"A lookalike domain '{domain}' has been registered and resolves to DNS records. "
                f"Fuzzer technique: {fuzzer}. "
                f"This domain may be used for phishing or brand impersonation attacks."
            )

            evidence_content = (
                f"Domain: {domain}\n"
                f"Fuzzer: {fuzzer}\n"
                f"DNS A: {', '.join(dns_a) if dns_a else 'none'}\n"
                f"DNS MX: {', '.join(dns_mx) if dns_mx else 'none'}"
            )

            evidence_list = [Evidence(
                evidence_type="brand_monitoring",
                title=f"Lookalike Domain: {domain}",
                content=evidence_content,
                content_type="text/plain",
            )]

            finding = Finding(
                id=_make_id(),
                scan_id=scan_id,
                title=title,
                description=description,
                severity=Severity.medium,
                target=domain,
                affected_component="Brand/Domain",
                finding_type="exposure",
                source_plugin="dnstwist",
                source_tool_ref=fuzzer,
                evidence=evidence_list,
                raw_data=item,
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # crtsh
    # ------------------------------------------------------------------

    @staticmethod
    def from_crtsh(parsed_data: dict[str, Any], scan_id: str, domain: str) -> list[Finding]:
        """Convert crt.sh certificate data into Finding objects.

        Generates findings for:
        - Expired certificates (high severity)
        - Wildcard certificates (informational)
        - Certificates from unexpected/unknown CAs (medium severity)

        Args:
            parsed_data: Dict with key "certificates" (list) as produced by CrtshPlugin.
            scan_id: Identifier of the parent scan.
            domain: The domain that was queried.

        Returns:
            List of Finding objects for certificate issues.
        """
        from datetime import datetime, timezone

        _EXPECTED_CA_FRAGMENTS: tuple[str, ...] = (
            "let's encrypt", "letsencrypt", "digicert", "comodo", "sectigo",
            "globalsign", "entrust", "geotrust", "godaddy", "go daddy",
            "amazon", "microsoft", "google", "zerossl", "trust asia",
            "identrust", "actalis", "buypass", "certum", "ssl.com",
        )

        findings_out: list[Finding] = []
        now = datetime.now(tz=timezone.utc)
        certificates: list[dict[str, Any]] = parsed_data.get("certificates", [])

        for cert in certificates:
            common_name: str = cert.get("common_name", "")
            issuer_name: str = cert.get("issuer_name", "")
            not_after_str: str = cert.get("not_after", "")
            name_value: str = cert.get("name_value", "")

            # Parse expiry date
            not_after: datetime | None = None
            if not_after_str:
                for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                    try:
                        dt = datetime.strptime(not_after_str[:19], fmt)
                        not_after = dt.replace(tzinfo=timezone.utc)
                        break
                    except ValueError:
                        continue

            # Expired certificate finding
            if not_after and not_after < now:
                findings_out.append(Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title=f"Expired Certificate: {common_name}",
                    description=(
                        f"The certificate for '{common_name}' on domain '{domain}' "
                        f"expired on {not_after_str}. Expired certificates cause browser "
                        "security warnings and indicate neglected certificate lifecycle management."
                    ),
                    severity=Severity.high,
                    target=domain,
                    affected_component=common_name,
                    finding_type="misconfiguration",
                    source_plugin="crtsh",
                    evidence=[Evidence(
                        evidence_type="certificate",
                        title="Certificate Transparency Record",
                        content=(
                            f"Common Name: {common_name}\n"
                            f"Issuer: {issuer_name}\n"
                            f"Not After: {not_after_str}"
                        ),
                        content_type="text/plain",
                    )],
                    raw_data=cert,
                ))

            # Wildcard certificate finding
            if "*." in common_name or "*." in name_value:
                findings_out.append(Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title=f"Wildcard Certificate Detected: {common_name}",
                    description=(
                        f"A wildcard certificate '{common_name}' was found for domain '{domain}'. "
                        "Wildcard certificates cover all subdomains and increase the blast radius "
                        "if the private key is compromised."
                    ),
                    severity=Severity.informational,
                    target=domain,
                    affected_component=common_name,
                    finding_type="exposure",
                    source_plugin="crtsh",
                    evidence=[Evidence(
                        evidence_type="certificate",
                        title="Wildcard Certificate Record",
                        content=(
                            f"Common Name: {common_name}\n"
                            f"Issuer: {issuer_name}\n"
                            f"Name Value: {name_value}"
                        ),
                        content_type="text/plain",
                    )],
                    raw_data=cert,
                ))

            # Unexpected CA finding
            if issuer_name and not any(
                frag in issuer_name.lower() for frag in _EXPECTED_CA_FRAGMENTS
            ):
                findings_out.append(Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title=f"Certificate from Unexpected CA: {issuer_name}",
                    description=(
                        f"The certificate for '{common_name}' on domain '{domain}' was issued by "
                        f"'{issuer_name}', which is not a commonly recognized public CA. "
                        "This may indicate a private/internal CA, a misissued certificate, or "
                        "a potential man-in-the-middle scenario."
                    ),
                    severity=Severity.medium,
                    target=domain,
                    affected_component=common_name,
                    finding_type="misconfiguration",
                    source_plugin="crtsh",
                    evidence=[Evidence(
                        evidence_type="certificate",
                        title="Certificate Authority Record",
                        content=(
                            f"Common Name: {common_name}\n"
                            f"Issuer: {issuer_name}"
                        ),
                        content_type="text/plain",
                    )],
                    raw_data=cert,
                ))

        return findings_out

    # ------------------------------------------------------------------
    # sslyze
    # ------------------------------------------------------------------

    @staticmethod
    def from_sslyze(parsed_data: dict[str, Any], scan_id: str) -> list[Finding]:
        """Convert sslyze TLS scan results into Finding objects.

        Generates findings for:
        - Weak/deprecated protocols (TLS 1.0, TLS 1.1, SSL 2.0, SSL 3.0) — medium/high
        - Expired certificates — high
        - Self-signed certificates — medium
        - Weak key sizes (RSA < 2048, EC < 224) — medium

        Args:
            parsed_data: Dict with key "tls_detailed" (list) as produced by SSLyzePlugin,
                         or raw sslyze JSON with "server_scan_results".
            scan_id: Identifier of the parent scan.

        Returns:
            List of Finding objects for TLS weaknesses.
        """
        _WEAK_PROTOCOL_MAP: dict[str, str] = {
            "tls_1_0_cipher_suites": "TLS 1.0",
            "tls_1_1_cipher_suites": "TLS 1.1",
            "ssl_2_0_cipher_suites": "SSL 2.0",
            "ssl_3_0_cipher_suites": "SSL 3.0",
        }

        findings_out: list[Finding] = []

        # Support both pre-parsed (from SSLyzePlugin.parse_output) and raw sslyze JSON
        tls_results: list[dict[str, Any]] = parsed_data.get("tls_detailed", [])

        if not tls_results:
            # Fallback: raw sslyze output with "server_scan_results"
            for server_result in parsed_data.get("server_scan_results", []):
                server_location = server_result.get("server_location", {})
                hostname: str = server_location.get("hostname", "")
                port: int = server_location.get("port", 443)
                host_label = f"{hostname}:{port}"
                scan_result: dict[str, Any] = server_result.get("scan_result", {})

                for field, label in _WEAK_PROTOCOL_MAP.items():
                    proto_data = scan_result.get(field, {})
                    if proto_data and proto_data.get("accepted_cipher_suites"):
                        severity = Severity.high if label.startswith("SSL") else Severity.medium
                        findings_out.append(Finding(
                            id=_make_id(),
                            scan_id=scan_id,
                            title=f"Deprecated Protocol Supported: {label} on {host_label}",
                            description=(
                                f"The server {host_label} supports {label}, a deprecated TLS/SSL "
                                "protocol with known cryptographic vulnerabilities. "
                                "Disable it and use TLS 1.2 or TLS 1.3 exclusively."
                            ),
                            severity=severity,
                            target=hostname,
                            affected_component="TLS/SSL",
                            port=port,
                            protocol="tcp",
                            finding_type="misconfiguration",
                            source_plugin="sslyze",
                            evidence=[Evidence(
                                evidence_type="tls_scan",
                                title=f"sslyze: {label} Supported",
                                content=f"Host: {host_label}\nProtocol: {label}",
                                content_type="text/plain",
                            )],
                            raw_data=server_result,
                        ))
            return findings_out

        # Process pre-parsed tls_detailed entries
        for host_entry in tls_results:
            host_label = host_entry.get("host", "")
            hostname_str: str = host_entry.get("hostname", host_label.split(":")[0])
            port_val: int = host_entry.get("port", 443)

            for protocol_label in host_entry.get("weak_protocols", []):
                sev = Severity.high if protocol_label.startswith("SSL") else Severity.medium
                findings_out.append(Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title=f"Deprecated Protocol Supported: {protocol_label} on {host_label}",
                    description=(
                        f"The server {host_label} supports {protocol_label}, a deprecated TLS/SSL "
                        "protocol with known cryptographic vulnerabilities. "
                        "Disable it and use TLS 1.2 or TLS 1.3 exclusively."
                    ),
                    severity=sev,
                    target=hostname_str,
                    affected_component="TLS/SSL",
                    port=port_val,
                    protocol="tcp",
                    finding_type="misconfiguration",
                    source_plugin="sslyze",
                    evidence=[Evidence(
                        evidence_type="tls_scan",
                        title=f"sslyze: {protocol_label} Supported",
                        content=f"Host: {host_label}\nProtocol: {protocol_label}",
                        content_type="text/plain",
                    )],
                ))

            for issue in host_entry.get("certificate_issues", []):
                if issue == "expired":
                    findings_out.append(Finding(
                        id=_make_id(),
                        scan_id=scan_id,
                        title=f"Expired TLS Certificate on {host_label}",
                        description=(
                            f"The TLS certificate on {host_label} has expired. "
                            "Expired certificates cause handshake failures and browser warnings."
                        ),
                        severity=Severity.high,
                        target=hostname_str,
                        affected_component="TLS Certificate",
                        port=port_val,
                        protocol="tcp",
                        finding_type="misconfiguration",
                        source_plugin="sslyze",
                    ))
                elif issue == "self_signed":
                    findings_out.append(Finding(
                        id=_make_id(),
                        scan_id=scan_id,
                        title=f"Self-Signed Certificate on {host_label}",
                        description=(
                            f"The TLS certificate on {host_label} is self-signed and not "
                            "trusted by browsers or clients by default."
                        ),
                        severity=Severity.medium,
                        target=hostname_str,
                        affected_component="TLS Certificate",
                        port=port_val,
                        protocol="tcp",
                        finding_type="misconfiguration",
                        source_plugin="sslyze",
                    ))

            for weak_key in host_entry.get("weak_keys", []):
                findings_out.append(Finding(
                    id=_make_id(),
                    scan_id=scan_id,
                    title=f"Weak Key Size ({weak_key}) on {host_label}",
                    description=(
                        f"The TLS certificate on {host_label} uses a weak key: {weak_key}. "
                        "Upgrade to RSA-2048+ or ECDSA-256+ to meet modern security standards."
                    ),
                    severity=Severity.medium,
                    target=hostname_str,
                    affected_component="TLS Certificate",
                    port=port_val,
                    protocol="tcp",
                    finding_type="misconfiguration",
                    source_plugin="sslyze",
                ))

        return findings_out

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
# FindingDeduplicator
# ---------------------------------------------------------------------------


class FindingDeduplicator:
    """Deduplication and grouping utilities for Finding lists."""

    def deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Group by dedup_hash and merge findings with the same hash.

        The first finding encountered for each hash becomes the canonical
        record. All subsequent findings with the same hash are merged into
        it via Finding.merge_with().

        Args:
            findings: Raw list of findings, potentially with duplicates.

        Returns:
            Deduplicated list preserving insertion order of first occurrence.
        """
        seen: dict[str, Finding] = {}

        for finding in findings:
            h = finding.dedup_hash
            if h not in seen:
                seen[h] = finding
            else:
                seen[h].merge_with(finding)

        return list(seen.values())

    def group_related(self, findings: list[Finding]) -> dict[str, list[Finding]]:
        """Group findings by fuzzy_hash for analyst review of near-duplicates.

        Findings that share the same target + finding_type + primary CVE will
        be clustered together even if they differ in port or affected_component.

        Args:
            findings: List of findings to group.

        Returns:
            Dict mapping fuzzy_hash → list of related findings.
        """
        groups: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            groups[finding.fuzzy_hash].append(finding)
        return dict(groups)
