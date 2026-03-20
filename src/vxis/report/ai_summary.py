"""AI-generated executive summary for VXIS security reports.

Phase 0 implementation: provides a high-quality template-based fallback that
produces a professional executive summary without requiring an API call.
When an API key is supplied, calls Claude Sonnet to generate a bespoke narrative.
"""

from __future__ import annotations

from vxis.models.finding import Finding, Severity

# Severity ordering used in summary prose
_SEVERITY_ORDER: list[str] = [
    Severity.critical.value,
    Severity.high.value,
    Severity.medium.value,
    Severity.low.value,
    Severity.informational.value,
]


def _build_template_summary(findings: list[Finding], client_name: str) -> str:
    """Build a professional template-based executive summary.

    Produces a three-paragraph summary covering scope, findings overview,
    and remediation priority guidance.
    """
    total = len(findings)

    # Count per severity
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        counts[f.effective_severity.value] += 1

    # Build counts string: "3 Critical, 5 High, 2 Medium, 0 Low, 1 Informational"
    counts_parts = [
        f"{counts[s]} {s.capitalize()}" for s in _SEVERITY_ORDER
    ]
    counts_str = ", ".join(counts_parts)

    # Identify the most severe finding for mention in prose
    top_finding: Finding | None = None
    for severity in _SEVERITY_ORDER:
        candidates = [f for f in findings if f.effective_severity.value == severity]
        if candidates:
            top_finding = sorted(candidates, key=lambda f: f.title)[0]
            break

    # Opening paragraph — scope and methodology
    para1 = (
        f"VXIS Security conducted a comprehensive security assessment of "
        f"{client_name}'s environment. The engagement covered the agreed scope "
        f"of assets and services, employing a combination of automated vulnerability "
        f"scanning and manual verification techniques aligned with OWASP, PTES, and "
        f"NIST SP 800-115 frameworks."
    )

    # Findings overview paragraph
    if total == 0:
        para2 = (
            "No security findings were identified during the assessment period. "
            "The target environment demonstrated a strong security posture with no "
            "exploitable vulnerabilities detected within the agreed scope."
        )
    else:
        top_clause = ""
        if top_finding is not None:
            sev_label = top_finding.effective_severity.value.capitalize()
            top_clause = (
                f" The most significant finding identified was '{top_finding.title}' "
                f"({sev_label}), which represents the highest-priority remediation item."
            )
        para2 = (
            f"A total of {total} security finding{'s' if total != 1 else ''} "
            f"{'were' if total != 1 else 'was'} identified: {counts_str}."
            f"{top_clause}"
        )

    # Remediation priority paragraph
    critical_count = counts[Severity.critical.value]
    high_count = counts[Severity.high.value]

    if critical_count > 0 or high_count > 0:
        urgent_parts: list[str] = []
        if critical_count > 0:
            urgent_parts.append(
                f"{critical_count} Critical finding{'s' if critical_count != 1 else ''}"
            )
        if high_count > 0:
            urgent_parts.append(
                f"{high_count} High finding{'s' if high_count != 1 else ''}"
            )
        urgent_str = " and ".join(urgent_parts)
        para3 = (
            f"Immediate remediation is recommended for the {urgent_str}, as these "
            f"represent the greatest risk to {client_name}'s environment. Medium and "
            f"Low severity findings should be addressed in subsequent remediation "
            f"cycles according to the organisation's risk tolerance and change management "
            f"processes. VXIS recommends a remediation validation assessment once "
            f"Critical and High findings have been addressed."
        )
    elif counts[Severity.medium.value] > 0:
        para3 = (
            f"No Critical or High severity findings were identified. Remediation of "
            f"the {counts[Severity.medium.value]} Medium severity "
            f"finding{'s' if counts[Severity.medium.value] != 1 else ''} should be "
            f"prioritised in the next scheduled maintenance window. Low and "
            f"Informational findings may be addressed according to {client_name}'s "
            f"standard change management processes."
        )
    else:
        para3 = (
            f"No Critical, High, or Medium severity findings were identified. "
            f"The identified Low and Informational findings are presented for awareness "
            f"and may be addressed according to {client_name}'s standard change "
            f"management processes."
        )

    return "\n\n".join([para1, para2, para3])


async def generate_executive_summary(
    findings: list[Finding],
    client_name: str,
    api_key: str | None = None,
) -> str:
    """Generate an executive summary for the security assessment.

    When *api_key* is supplied, calls Claude Sonnet via the Anthropic API to
    produce a bespoke narrative summary. Otherwise falls back to a high-quality
    template-based summary that is suitable for production reports.

    Parameters
    ----------
    findings:
        All findings from the assessment (any status).
    client_name:
        Name of the assessed organisation, used in prose.
    api_key:
        Anthropic API key. If ``None`` or empty, the template fallback is used.

    Returns
    -------
    str
        Executive summary text (plain text, suitable for HTML embedding).
    """
    if not api_key:
        return _build_template_summary(findings, client_name)

    try:
        import anthropic  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "The 'anthropic' package is required for AI-generated summaries. "
            "Install it with: pip install anthropic"
        ) from exc

    # Build a concise findings digest to include in the prompt
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        counts[f.effective_severity.value] += 1

    finding_lines: list[str] = []
    for f in sorted(findings, key=lambda x: -x.effective_severity.weight):
        finding_lines.append(
            f"- [{f.effective_severity.value.upper()}] {f.title}: {f.description[:200]}"
        )

    findings_digest = "\n".join(finding_lines[:30])  # cap to avoid token overflow
    counts_str = ", ".join(
        f"{counts[s]} {s}" for s in _SEVERITY_ORDER if counts[s] > 0
    )

    prompt = (
        f"You are a senior penetration tester writing an executive summary for a "
        f"security assessment report. Write a professional, concise executive summary "
        f"(3-4 paragraphs) for the following assessment:\n\n"
        f"Client: {client_name}\n"
        f"Total findings: {len(findings)} ({counts_str})\n\n"
        f"Findings summary:\n{findings_digest}\n\n"
        f"The executive summary should:\n"
        f"1. Briefly describe the scope and methodology\n"
        f"2. Summarise the key findings and their business risk\n"
        f"3. Provide clear remediation prioritisation guidance\n"
        f"4. Use professional language suitable for C-suite readers\n\n"
        f"Do not use bullet points. Write in prose only."
    )

    client = anthropic.AsyncAnthropic(api_key=api_key)
    message = await client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )

    content = message.content[0]
    if hasattr(content, "text"):
        return content.text.strip()

    # Fallback if response format is unexpected
    return _build_template_summary(findings, client_name)
