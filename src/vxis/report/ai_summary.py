"""AI-generated executive summary for VXIS security reports.

Phase 0 implementation: provides a high-quality template-based fallback that
produces a professional executive summary without requiring an API call.
When an API key is supplied, calls Claude Sonnet to generate a bespoke narrative.
"""

from __future__ import annotations

from vxis.models.finding import Finding, Severity


def _en(text: str) -> str:
    """Take the English half of a bilingual 'EN|||KO' string.

    Finding titles/descriptions are stored as 'English|||한국어' and MUST be
    split before being interpolated into a single-language paragraph — naive
    concatenation causes nested '|||' separators that break downstream
    bilingual filters. Returns the input unchanged if no separator is present.
    """
    if not text:
        return ""
    return text.split("|||", 1)[0].strip()


def _ko(text: str) -> str:
    """Take the Korean half of a bilingual 'EN|||KO' string."""
    if not text:
        return ""
    parts = text.split("|||", 1)
    if len(parts) == 2:
        return parts[1].strip()
    # No separator — text is already single language; return as-is
    return text.strip()

# Severity ordering used in summary prose
_SEVERITY_ORDER: list[str] = [
    Severity.critical.value,
    Severity.high.value,
    Severity.medium.value,
    Severity.low.value,
    Severity.informational.value,
]


def _build_template_summary_en(findings: list[Finding], client_name: str) -> str:
    """Build the ENGLISH half of the executive summary.

    Paragraph 1: scope + methodology
    Paragraph 2: findings overview (with top finding title in ENGLISH only)
    Paragraph 3: remediation priority guidance
    """
    total = len(findings)
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        counts[f.effective_severity.value] += 1

    counts_str = ", ".join(
        f"{counts[s]} {s.capitalize()}" for s in _SEVERITY_ORDER
    )

    # Top finding — pull EN title only to avoid '|||' contamination
    top_finding: Finding | None = None
    for severity in _SEVERITY_ORDER:
        candidates = [f for f in findings if f.effective_severity.value == severity]
        if candidates:
            top_finding = sorted(candidates, key=lambda f: _en(f.title))[0]
            break

    para1 = (
        f"VXIS Security conducted a comprehensive security assessment of "
        f"{client_name}'s environment. The engagement covered the agreed scope "
        f"of assets and services, employing a combination of automated vulnerability "
        f"scanning and manual verification techniques aligned with OWASP, PTES, and "
        f"NIST SP 800-115 frameworks."
    )

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
                f" The most significant finding identified was '{_en(top_finding.title)}' "
                f"({sev_label}), which represents the highest-priority remediation item."
            )
        para2 = (
            f"A total of {total} security finding{'s' if total != 1 else ''} "
            f"{'were' if total != 1 else 'was'} identified: {counts_str}."
            f"{top_clause}"
        )

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


def _build_template_summary_ko(findings: list[Finding], client_name: str) -> str:
    """Build the KOREAN half of the executive summary.

    Mirror the English structure so that the bilingual toggle shows equally
    detailed content on both sides. Top finding is referenced using its
    Korean title (after the '|||' separator).
    """
    total = len(findings)
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        counts[f.effective_severity.value] += 1

    sev_ko = {
        "critical": "심각",
        "high": "높음",
        "medium": "중간",
        "low": "낮음",
        "informational": "정보",
    }
    counts_str = ", ".join(
        f"{counts[s]}건 {sev_ko.get(s, s)}" for s in _SEVERITY_ORDER
    )

    top_finding: Finding | None = None
    for severity in _SEVERITY_ORDER:
        candidates = [f for f in findings if f.effective_severity.value == severity]
        if candidates:
            top_finding = sorted(candidates, key=lambda f: _en(f.title))[0]
            break

    para1 = (
        f"VXIS Security는 {client_name} 환경에 대해 종합 보안 평가를 수행했습니다. "
        f"합의된 자산과 서비스 범위 내에서 자동화 취약점 스캔과 수동 검증을 "
        f"결합했으며, OWASP Testing Guide·PTES·NIST SP 800-115 프레임워크에 "
        f"맞춰 진행했습니다."
    )

    if total == 0:
        para2 = (
            "평가 기간 동안 보안 취약점이 식별되지 않았습니다. "
            "대상 환경은 합의된 범위 내에서 익스플로잇 가능한 취약점 없이 "
            "견고한 보안 태세를 보였습니다."
        )
    else:
        top_clause = ""
        if top_finding is not None:
            sev_label = sev_ko.get(top_finding.effective_severity.value, "")
            top_clause = (
                f" 가장 심각한 항목은 '{_ko(top_finding.title)}' ({sev_label}) 이며, "
                f"최우선 조치 대상입니다."
            )
        para2 = (
            f"총 {total}건의 보안 취약점이 식별되었습니다: {counts_str}."
            f"{top_clause}"
        )

    critical_count = counts[Severity.critical.value]
    high_count = counts[Severity.high.value]

    if critical_count > 0 or high_count > 0:
        urgent_parts: list[str] = []
        if critical_count > 0:
            urgent_parts.append(f"심각 {critical_count}건")
        if high_count > 0:
            urgent_parts.append(f"높음 {high_count}건")
        urgent_str = " 및 ".join(urgent_parts)
        para3 = (
            f"{urgent_str} 항목은 {client_name} 환경에 가장 큰 위험을 "
            f"초래하므로 즉시 조치가 권장됩니다. 중간 및 낮음 심각도 항목은 "
            f"조직의 위험 허용 수준과 변경 관리 절차에 따라 후속 조치 주기에 "
            f"반영해야 합니다. VXIS는 심각·높음 항목 조치가 완료된 이후 "
            f"재검증 평가를 수행할 것을 권장합니다."
        )
    elif counts[Severity.medium.value] > 0:
        para3 = (
            f"심각·높음 항목은 식별되지 않았습니다. "
            f"중간 심각도 {counts[Severity.medium.value]}건은 "
            f"다음 정기 유지보수 주기에 우선 조치되어야 합니다. 낮음 및 정보 "
            f"항목은 {client_name}의 표준 변경 관리 절차에 따라 처리할 수 있습니다."
        )
    else:
        para3 = (
            f"심각·높음·중간 항목은 식별되지 않았습니다. "
            f"확인된 낮음 및 정보 항목은 인지 차원에서 제시되며, "
            f"{client_name}의 표준 변경 관리 절차에 따라 처리할 수 있습니다."
        )

    return "\n\n".join([para1, para2, para3])


def _build_template_summary(findings: list[Finding], client_name: str) -> str:
    """Back-compat: return the English half only (used by non-bilingual callers)."""
    return _build_template_summary_en(findings, client_name)


async def generate_executive_summary(
    findings: list[Finding],
    client_name: str,
    api_key: str | None = None,
    target: str | None = None,
    vxis_score: float | None = None,
    bilingual: bool = False,
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
        en = _build_template_summary_en(findings, client_name)
        if bilingual:
            ko = _build_template_summary_ko(findings, client_name)
            return f"{en}|||{ko}"
        return en

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
        # Strip bilingual '|||' to avoid nested separators in the prompt
        t = _en(f.title)
        d = _en(f.description or "")[:200]
        finding_lines.append(
            f"- [{f.effective_severity.value.upper()}] {t}: {d}"
        )

    findings_digest = "\n".join(finding_lines[:30])  # cap to avoid token overflow
    counts_str = ", ".join(
        f"{counts[s]} {s}" for s in _SEVERITY_ORDER if counts[s] > 0
    )

    target_line = f"Target: {target}\n" if target else ""
    score_line = f"VXIS Score: {vxis_score}\n" if vxis_score is not None else ""
    bilingual_instr = (
        "\n\nIMPORTANT: Output BOTH English and Korean versions separated by exactly '|||'. "
        "Format: <English summary>|||<한국어 요약>. Both versions must be equally detailed (3-4 paragraphs each)."
        if bilingual else ""
    )
    prompt = (
        f"You are a senior penetration tester writing an executive summary for a "
        f"security assessment report. Write a professional, concise executive summary "
        f"(3-4 paragraphs) for the following assessment:\n\n"
        f"Client: {client_name}\n"
        f"{target_line}{score_line}"
        f"Total findings: {len(findings)} ({counts_str})\n\n"
        f"Findings summary:\n{findings_digest}\n\n"
        f"The executive summary should:\n"
        f"1. Briefly describe the scope and methodology\n"
        f"2. Summarise the key findings and their business risk\n"
        f"3. Provide clear remediation prioritisation guidance\n"
        f"4. Use professional language suitable for C-suite readers\n\n"
        f"Do not use bullet points. Write in prose only."
        f"{bilingual_instr}"
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
    fallback = _build_template_summary(findings, client_name)
    if bilingual:
        return f"{fallback}|||{fallback}"
    return fallback
