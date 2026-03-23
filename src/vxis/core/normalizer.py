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
    # bloodhound
    # ------------------------------------------------------------------

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
            cwe_ids: list[str] = item.get("cwe_ids", [])
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
