"""Finding CRUD tools — Brain reports / queries / chains discovered vulnerabilities.

State is held in a per-scan FindingStore. Direct tool use falls back to a
process-default store for compatibility, but production scans bind an active
store through a context variable so findings/chains do not leak across runs.

Tools:
- report_finding: Brain submits a new finding. Assigns an ID, stores it, returns the ID.
- query_findings: Brain searches existing findings by type/severity/component/free text.
- link_chain: Brain asserts a causal attack chain between N previously-reported findings.
"""

from __future__ import annotations

import json
import logging
import re
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from vxis.agent.tool_registry import ToolResult
from vxis.agent.tools._poc_signals import (
    CONTROL_MARKERS as _CONTROL_MARKERS,
    POC_ATTEMPT_MARKERS as _POC_ATTEMPT_MARKERS,
    POC_RESULT_MARKERS as _POC_RESULT_MARKERS,
    finding_type_needs_control as _finding_type_needs_control,
)

logger = logging.getLogger(__name__)


@dataclass
class FindingStore:
    findings: list[dict[str, Any]] = field(default_factory=list)
    chains: list[dict[str, Any]] = field(default_factory=list)
    event_callback: Callable[[str, dict[str, Any]], None] | None = None


_DEFAULT_STORE = FindingStore()
_ACTIVE_STORE: ContextVar[FindingStore] = ContextVar(
    "vxis_finding_store",
    default=_DEFAULT_STORE,
)


def new_finding_store() -> FindingStore:
    return FindingStore()


def set_active_finding_store(store: FindingStore) -> Token[FindingStore]:
    return _ACTIVE_STORE.set(store)


def reset_active_finding_store(token: Token[FindingStore]) -> None:
    _ACTIVE_STORE.reset(token)


def _store() -> FindingStore:
    return _ACTIVE_STORE.get()

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "informational")
_REPEAT_MARKERS = (
    "repeat_count",
    "reproduced twice",
    "reproduced 2",
    "replayed twice",
    "replay twice",
    "second run",
    "run 2",
    "attempt 2",
    "two runs",
    "twice",
)
_NEGATIVE_MARKERS = (
    "negative",
    "negative_control",
    "should fail",
    "expected fail",
    "failed as expected",
    "baseline denied",
    "control denied",
    "invalid credentials",
    "without auth",
    "unauthenticated",
    "403",
    "401",
    "no sql error",
    "no token",
    "not reflected",
)
_HTTP_STATUS_LINE_RE = re.compile(r"(?m)^\s*HTTP/\d(?:\.\d)?\s+\d{3}\b", re.IGNORECASE)
_STATUS_ASSIGNMENT_RE = re.compile(
    r"\b(?:status|status_code|response_status|code)\b\s*[=:]\s*[\"']?\d{3}\b",
    re.IGNORECASE,
)
_REPEAT_COUNT_RE = re.compile(r"\brepeat(?:_count)?\b\s*[=:]\s*[\"']?(\d+)\b", re.IGNORECASE)
_CHAIN_HIGH_VALUE_CROWN_TERMS = (
    "admin",
    "takeover",
    "db",
    "database",
    "dump",
    "rce",
    "exfil",
    "data",
    "session",
    "token",
    "credential",
    "key",
    "privileged",
    "crown",
)
_CHAIN_ARTIFACT_FIELDS = (
    "source_finding_id",
    "target_finding_id",
    "source_output",
    "pivot_action",
    "observed_result",
    "control_result",
    "crown_jewel_evidence",
    "repeat_count",
    "negative_result",
    "negative_control",
    "source_output_used_in_pivot",
    "verification_method",
    "trace_id",
)
_CHAIN_HOP_FIELDS = (
    "source_finding_id",
    "target_finding_id",
    "source_output",
    "pivot_action",
    "observed_result",
    "control_result",
    "repeat_count",
    "negative_result",
    "negative_control",
    "source_output_used_in_pivot",
    "trace_id",
)
_CHAIN_SOURCE_STOPWORDS = {
    "http",
    "https",
    "host",
    "status",
    "response",
    "request",
    "control",
    "payload",
    "baseline",
    "finding",
    "vxis",
}

# Compiled regex used by _base_path — hoisted here so it is not recompiled per call.
_NUMERIC_SEGMENT_RE = re.compile(r"/\d+(/|$)")


def _normalize(s: str) -> str:
    """Normalize finding_type and affected_component for dedup matching."""
    s = str(s).lower().strip()
    s = s.rstrip("/")
    s = " ".join(s.split())
    return s


def _base_path(component: str) -> str:
    """Extract base API path, stripping numeric IDs and query params.

    /api/Orders/1      → /api/orders
    /api/Orders/2      → /api/orders
    /api/Baskets/1/items → /api/baskets
    http://x:3000/api/Orders/1 → /api/orders
    /rest/products/search?q=test' → /rest/products/search

    Phase Q8: when affected_component carries an explicit '#'
    discriminator (set by scan_loop's desktop promotion block), the
    suffix MUST be preserved — otherwise 20 distinct dylib_hijack
    findings on the same binary all collapse to the binary path and
    dedup into a single VXIS-NNNN with everything in
    affected_endpoints. urlparse treats '#' as a URI fragment and
    drops it by default; we re-attach it so the discriminator
    actually discriminates.
    """
    try:
        parsed = urlparse(component)
        path = parsed.path or component
        if parsed.fragment:
            # Reattach the discriminator the desktop promotion block
            # appended (e.g. "<binary>#<dylib>@<candidate_path>").
            path = f"{path}#{parsed.fragment}"
    except Exception:
        path = component
    path = path.lower().strip().rstrip("/")
    # Remove query string
    path = path.split("?")[0]
    # Strip trailing numeric segments (/1, /2, /123)
    path = _NUMERIC_SEGMENT_RE.sub("/", path).rstrip("/")
    return path


def _canonical_finding_type(value: str) -> str:
    ft = str(value or "").lower().strip()
    if not ft:
        return ft
    if ft.startswith("xss_") or ft == "xss":
        return "xss"
    if ft.startswith("sqli") or ft in {"sql_injection", "sqli_blind", "sqli_time"}:
        return "sql_injection"
    if ft.startswith("ssrf"):
        return "ssrf"
    if ft in {
        "jwt_alg_none",
        "jwt_alg_confusion",
        "session_fixation",
        "password_reset_poisoning",
        "default_credentials",
        "weak_auth",
    }:
        return "weak_auth"
    return ft


def _reset_for_tests() -> None:
    """Reset the active in-memory store. Called from test fixtures and scan setup."""
    store = _store()
    store.findings.clear()
    store.chains.clear()
    store.event_callback = None


def _get_findings() -> list[dict[str, Any]]:
    """Public accessor for integration (ScanAgentLoop) to read the findings list."""
    return list(_store().findings)


def _get_chains() -> list[dict[str, Any]]:
    """Public accessor for integration to read the chains list."""
    return list(_store().chains)


def set_event_callback(callback: Callable[[str, dict[str, Any]], None] | None) -> None:
    """Register a lightweight callback for live TUI events."""
    _store().event_callback = callback


def _emit_event(event_type: str, data: dict[str, Any]) -> None:
    callback = _store().event_callback
    if callback is None:
        return
    try:
        callback(event_type, data)
    except Exception:
        logger.debug("finding tool event callback failed for %s", event_type, exc_info=True)


def _severity_to_level(severity: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 1,
    }.get(str(severity).lower(), 1)


def _finding_by_id(finding_id: str) -> dict[str, Any] | None:
    for finding in _store().findings:
        if finding.get("id") == finding_id:
            return finding
    return None


def _chain_signature(finding_ids: list[str], crown_jewel: str) -> tuple[str, str, str]:
    source_type = ""
    target_type = ""
    if finding_ids:
        source = _finding_by_id(str(finding_ids[0])) or {}
        target = _finding_by_id(str(finding_ids[-1])) or {}
        source_type = _canonical_finding_type(str(source.get("finding_type", "")))
        target_type = _canonical_finding_type(str(target.get("finding_type", "")))
    return (
        source_type,
        target_type,
        str(crown_jewel or "").strip().lower(),
    )


def _stringify_artifact_value(value: Any, *, limit: int = 3000) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return _normalize_poc_transcript(value)[:limit]
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)[:limit]
    except TypeError:
        return str(value)[:limit]


def _normalize_chain_artifact(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {"observed_result": _normalize_poc_transcript(text)}
        value = parsed
    if not isinstance(value, dict):
        return {}

    normalized: dict[str, Any] = {}
    for artifact_field in _CHAIN_ARTIFACT_FIELDS:
        if artifact_field not in value:
            continue
        if artifact_field == "source_output_used_in_pivot":
            normalized[artifact_field] = bool(value.get(artifact_field))
        elif artifact_field == "repeat_count":
            try:
                normalized[artifact_field] = int(value.get(artifact_field) or 0)
            except (TypeError, ValueError):
                normalized[artifact_field] = 0
        else:
            normalized[artifact_field] = _stringify_artifact_value(value.get(artifact_field))

    hops: list[dict[str, Any]] = []
    raw_hops = value.get("hops")
    if isinstance(raw_hops, list):
        for raw_hop in raw_hops[:12]:
            if not isinstance(raw_hop, dict):
                continue
            hop: dict[str, Any] = {}
            for hop_field in _CHAIN_HOP_FIELDS:
                if hop_field not in raw_hop:
                    continue
                if hop_field == "source_output_used_in_pivot":
                    hop[hop_field] = bool(raw_hop.get(hop_field))
                elif hop_field == "repeat_count":
                    try:
                        hop[hop_field] = int(raw_hop.get(hop_field) or 0)
                    except (TypeError, ValueError):
                        hop[hop_field] = 0
                else:
                    hop[hop_field] = _stringify_artifact_value(raw_hop.get(hop_field))
            if hop:
                hops.append(hop)
    if hops:
        normalized["hops"] = hops
    return normalized


def _artifact_has_observed_result(value: Any) -> bool:
    text = _stringify_artifact_value(value)
    lower = text.lower()
    return (
        _HTTP_STATUS_LINE_RE.search(text) is not None
        or _STATUS_ASSIGNMENT_RE.search(text) is not None
        or any(marker.lower() in lower for marker in _POC_RESULT_MARKERS)
        or any(token in lower for token in ("token=", "session=", "role=admin", "rows", "dumped"))
    )


def _artifact_has_control(value: Any) -> bool:
    text = _stringify_artifact_value(value)
    lower = text.lower()
    return _artifact_has_observed_result(text) or any(
        marker in lower for marker in _CONTROL_MARKERS
    )


def _artifact_repeat_count(value: Any) -> int:
    if isinstance(value, dict):
        try:
            return int(value.get("repeat_count") or 0)
        except (TypeError, ValueError):
            return 0
    text = _stringify_artifact_value(value)
    match = _REPEAT_COUNT_RE.search(text)
    if match:
        try:
            return int(match.group(1))
        except (TypeError, ValueError):
            return 0
    lower = text.lower()
    return 2 if any(marker in lower for marker in _REPEAT_MARKERS) else 0


def _artifact_has_negative_result(*values: Any) -> bool:
    text = "\n".join(_stringify_artifact_value(value) for value in values if value is not None)
    lower = text.lower()
    if any(marker in lower for marker in _NEGATIVE_MARKERS):
        return True
    return _HTTP_STATUS_LINE_RE.search(text) is not None and any(
        code in lower for code in (" 401", " 403")
    )


def _source_output_reused(source_output: Any, reuse_context: Any, *, explicit: bool) -> bool:
    if explicit:
        return True
    source = _stringify_artifact_value(source_output).lower()
    context = _stringify_artifact_value(reuse_context).lower()
    tokens = {
        token
        for token in re.findall(r"[a-z0-9_./:-]{4,}", source)
        if token not in _CHAIN_SOURCE_STOPWORDS
    }
    if not tokens:
        return False
    return any(token in context for token in sorted(tokens, key=len, reverse=True)[:20])


def _crown_jewel_evidence_aligned(crown_jewel: str, evidence: Any) -> bool:
    crown = str(crown_jewel or "").lower()
    text = _stringify_artifact_value(evidence).lower()
    if not crown.strip():
        return True
    groups = []
    if any(token in crown for token in ("admin", "privilege", "takeover")):
        groups.append(("admin", "privileged", "role", "/admin", "200"))
    if any(token in crown for token in ("db", "database", "dump", "data", "exfil", "order")):
        groups.append(("data", "row", "record", "dump", "table", "export", "order", "token"))
    if any(token in crown for token in ("session", "auth", "credential", "token")):
        groups.append(("session", "token", "cookie", "credential", "authenticated"))
    if any(token in crown for token in ("rce", "command", "code execution")):
        groups.append(("command", "stdout", "shell", "rce", "uid="))
    if any(token in crown for token in ("key", "secret")):
        groups.append(("key", "secret", "credential", "token"))
    if not groups:
        return True
    return any(any(marker in text for marker in group) for group in groups)


def _chain_requires_verified_artifact(finding_ids: list[str], crown_jewel: str) -> bool:
    crown = str(crown_jewel or "").lower()
    if any(term in crown for term in _CHAIN_HIGH_VALUE_CROWN_TERMS):
        return True
    for fid in finding_ids:
        finding = _finding_by_id(str(fid)) or {}
        if str(finding.get("severity", "")).lower() in {"high", "critical"}:
            return True
    return False


def _evaluate_chain_artifact(
    *,
    finding_ids: list[str],
    rationale: str,
    crown_jewel: str,
    evidence_artifact: dict[str, Any],
) -> dict[str, Any]:
    required = _chain_requires_verified_artifact(finding_ids, crown_jewel)
    if not required:
        return {
            "ok": True,
            "required": False,
            "verified": bool(evidence_artifact),
            "missing": [],
        }

    missing: list[str] = []
    if not evidence_artifact:
        return {
            "ok": False,
            "required": True,
            "verified": False,
            "missing": ["evidence_artifact"],
        }

    crown_evidence = evidence_artifact.get("crown_jewel_evidence", "")
    if not crown_evidence:
        missing.append("crown_jewel_evidence")
    elif not _crown_jewel_evidence_aligned(crown_jewel, crown_evidence):
        missing.append("crown_jewel_evidence_alignment")
    if _artifact_repeat_count(evidence_artifact) < 2:
        missing.append("repeat_reproduction")
    if not _artifact_has_negative_result(
        evidence_artifact.get("negative_result"),
        evidence_artifact.get("negative_control"),
        evidence_artifact.get("control_result"),
    ):
        missing.append("negative_or_refutation")

    hops = list(evidence_artifact.get("hops") or [])
    if not hops and len(finding_ids) == 2:
        hops = [
            {
                field: evidence_artifact.get(field)
                for field in _CHAIN_HOP_FIELDS
                if field in evidence_artifact
            }
        ]

    expected_pairs = list(zip(finding_ids, finding_ids[1:]))
    if len(hops) < len(expected_pairs):
        missing.append("complete_hop_evidence")
    for index, (source_id, target_id) in enumerate(expected_pairs):
        hop = hops[index] if index < len(hops) and isinstance(hops[index], dict) else {}
        label = f"hop_{index + 1}"
        if hop.get("source_finding_id") and hop.get("source_finding_id") != source_id:
            missing.append(f"{label}_source_id")
        if hop.get("target_finding_id") and hop.get("target_finding_id") != target_id:
            missing.append(f"{label}_target_id")
        source_output = hop.get("source_output") or evidence_artifact.get("source_output", "")
        pivot_action = hop.get("pivot_action") or evidence_artifact.get("pivot_action", "")
        observed_result = hop.get("observed_result") or evidence_artifact.get("observed_result", "")
        control_result = hop.get("control_result") or evidence_artifact.get("control_result", "")
        negative_result = (
            hop.get("negative_result")
            or hop.get("negative_control")
            or evidence_artifact.get("negative_result")
            or evidence_artifact.get("negative_control")
        )
        if not source_output:
            missing.append(f"{label}_source_output")
        if not pivot_action:
            missing.append(f"{label}_pivot_action")
        if not observed_result or not _artifact_has_observed_result(observed_result):
            missing.append(f"{label}_observed_result")
        if not control_result or not _artifact_has_control(control_result):
            missing.append(f"{label}_control_result")
        if _artifact_repeat_count(hop) < 2 and _artifact_repeat_count(evidence_artifact) < 2:
            missing.append(f"{label}_repeat_reproduction")
        if not _artifact_has_negative_result(negative_result, control_result):
            missing.append(f"{label}_negative_or_refutation")
        reuse_context = "\n".join(
            part
            for part in (
                pivot_action,
                observed_result,
                crown_evidence,
                rationale,
            )
            if part
        )
        explicit_reuse = bool(
            hop.get("source_output_used_in_pivot")
            or evidence_artifact.get("source_output_used_in_pivot")
        )
        if source_output and not _source_output_reused(
            source_output,
            reuse_context,
            explicit=explicit_reuse,
        ):
            missing.append(f"{label}_source_output_reuse")

    return {
        "ok": not missing,
        "required": True,
        "verified": not missing,
        "missing": missing,
        "hop_count": len(hops),
    }


def _coalesce_report_fields(kwargs: dict[str, Any]) -> dict[str, str]:
    """Normalize legacy VXIS fields into a Strix-style report contract."""
    description = str(kwargs.get("description", "")).strip()
    remediation_steps = str(
        kwargs.get("remediation_steps") or kwargs.get("remediation") or ""
    ).strip()
    technical_analysis = str(kwargs.get("technical_analysis") or description or "").strip()
    poc_description = str(kwargs.get("poc_description") or kwargs.get("evidence") or "").strip()
    poc_script_code = _normalize_poc_transcript(
        kwargs.get("poc_script_code") or kwargs.get("evidence") or ""
    )
    impact = str(kwargs.get("impact") or description or "").strip()
    method = str(kwargs.get("method", "")).strip()
    endpoint = str(kwargs.get("endpoint") or kwargs.get("affected_component") or "").strip()
    return {
        "description": description,
        "impact": impact,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "remediation_steps": remediation_steps,
        "method": method,
        "endpoint": endpoint,
    }


def _normalize_poc_transcript(value: Any) -> str:
    text = str(value or "").strip()
    if "\\n" not in text and "\\r" not in text and "\\t" not in text:
        return text
    return (
        text.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n").replace("\\t", "\t")
    )


def _normalize_extra_evidence(value: Any) -> list[dict[str, str]]:
    """Coerce arbitrary extra evidence blobs into a safe structured list."""
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        evidence_type = str(item.get("evidence_type", "")).strip().lower()
        title = str(item.get("title", "")).strip()
        content = str(item.get("content", "")).strip()
        if not evidence_type or not title or not content:
            continue
        normalized.append(
            {
                "evidence_type": evidence_type[:64],
                "title": title[:160],
                "content": content[:4000],
                "content_type": str(item.get("content_type", "text/plain")).strip()[:120]
                or "text/plain",
            }
        )
    return normalized


def _evaluate_high_severity_poc(
    *,
    finding_type: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
) -> dict[str, Any]:
    combined = "\n".join(
        part
        for part in (technical_analysis, poc_description, poc_script_code)
        if str(part or "").strip()
    )
    lower = combined.lower()
    poc_lower = str(poc_script_code or "").lower()
    has_attempt = any(marker.lower() in poc_lower for marker in _POC_ATTEMPT_MARKERS)
    has_observed_status = _HTTP_STATUS_LINE_RE.search(str(poc_script_code or "")) is not None
    has_observed_status = (
        has_observed_status or _STATUS_ASSIGNMENT_RE.search(str(poc_script_code or "")) is not None
    )
    has_result = has_observed_status or any(
        marker.lower() in poc_lower for marker in _POC_RESULT_MARKERS
    )
    repeat_count = _artifact_repeat_count(combined)
    has_repeat = repeat_count >= 2
    has_negative = _artifact_has_negative_result(combined)
    needs_control = _finding_type_needs_control(finding_type)
    has_control = any(marker in lower for marker in _CONTROL_MARKERS)
    missing: list[str] = []
    if not has_attempt:
        missing.append("exploit_attempt")
    if not has_result:
        missing.append("observed_result")
    if needs_control and not has_control:
        missing.append("control_or_baseline")
    if not has_repeat:
        missing.append("repeat_reproduction")
    if not has_negative:
        missing.append("negative_or_refutation")
    return {
        "ok": not missing,
        "missing": missing,
        "has_attempt": has_attempt,
        "has_result": has_result,
        "needs_control": needs_control,
        "has_control": has_control,
        "repeat_count": repeat_count,
        "has_repeat": has_repeat,
        "has_negative": has_negative,
    }


class ReportFindingTool:
    name = "report_finding"
    description = (
        "Submit a discovered vulnerability. Returns the assigned finding ID. "
        "Include enough detail (title, severity, component, evidence, description) "
        "for a penetration test report. HIGH/CRITICAL findings must include control, "
        "repeat_count>=2, and a negative/refutation result. The ID is stable and can "
        "be used in link_chain."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": list(_VALID_SEVERITIES)},
            "finding_type": {
                "type": "string",
                "description": "snake_case vuln type e.g. 'sql_injection', 'xss_reflected'",
            },
            "affected_component": {"type": "string"},
            "description": {"type": "string"},
            "impact": {
                "type": "string",
                "description": "Concrete business/security impact validated for this finding",
            },
            "technical_analysis": {
                "type": "string",
                "description": "Why this issue is real, including control checks, repeat_count>=2, and negative/refutation reasoning",
            },
            "poc_description": {
                "type": "string",
                "description": "Step-by-step reproduction summary for the validated exploit and its control/negative tests",
            },
            "poc_script_code": {
                "type": "string",
                "description": "Actual exploit payload / HTTP exchange / command transcript with control, repeat_count>=2, and negative result",
            },
            "evidence": {
                "type": "string",
                "description": "Legacy alias for PoC transcript; prefer poc_script_code",
            },
            "remediation": {"type": "string", "description": "Legacy alias for remediation_steps"},
            "remediation_steps": {"type": "string", "description": "Specific remediation guidance"},
            "endpoint": {"type": "string"},
            "method": {"type": "string"},
            "cwe": {"type": "string", "description": "e.g. 'CWE-89'"},
            "extra_evidence": {
                "type": "array",
                "description": "Additional evidence artifacts such as callback hits, retrieval previews, or exfil traces",
            },
        },
        "required": ["title", "severity", "finding_type", "affected_component", "description"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        findings = _store().findings
        severity = kwargs.get("severity", "").lower()
        if severity not in _VALID_SEVERITIES:
            return ToolResult(
                ok=False,
                summary=f"report_finding: invalid severity '{severity}'. Use one of {_VALID_SEVERITIES}.",
                error="invalid_severity",
            )

        required = ["title", "finding_type", "affected_component", "description"]
        missing = [k for k in required if not kwargs.get(k)]
        if missing:
            return ToolResult(
                ok=False,
                summary=f"report_finding: missing required fields: {missing}",
                error="missing_fields",
            )

        normalized = _coalesce_report_fields(kwargs)
        if severity in ("high", "critical"):
            missing_report_parts = [
                field_name
                for field_name in (
                    "impact",
                    "technical_analysis",
                    "poc_description",
                    "poc_script_code",
                    "remediation_steps",
                )
                if not normalized[field_name]
            ]
            if missing_report_parts:
                pretty = ", ".join(missing_report_parts)
                return ToolResult(
                    ok=False,
                    summary=(
                        "report_finding: HIGH/CRITICAL findings must include Strix-style "
                        f"report fields before they can be recorded. Missing: {pretty}."
                    ),
                    error="missing_report_fields",
                    data={"missing_fields": missing_report_parts},
                )

        if severity in ("medium", "low", "informational") and not normalized["poc_script_code"]:
            normalized["poc_script_code"] = str(kwargs.get("evidence", "")).strip()
        if severity in ("medium", "low", "informational") and not normalized["poc_description"]:
            normalized["poc_description"] = str(kwargs.get("evidence", "")).strip()
        if severity in ("medium", "low", "informational") and not normalized["remediation_steps"]:
            normalized["remediation_steps"] = str(kwargs.get("remediation", "")).strip()

        if severity in ("high", "critical") and not normalized["poc_script_code"]:
            return ToolResult(
                ok=False,
                summary=(
                    "report_finding: HIGH/CRITICAL findings require actual exploit "
                    "payload/transcript in poc_script_code."
                ),
                error="missing_poc_script",
            )
        proof = _evaluate_high_severity_poc(
            finding_type=str(kwargs["finding_type"]),
            technical_analysis=normalized["technical_analysis"],
            poc_description=normalized["poc_description"],
            poc_script_code=normalized["poc_script_code"],
        )
        if severity in ("high", "critical") and not proof["ok"]:
            missing = ", ".join(proof["missing"])
            return ToolResult(
                ok=False,
                summary=(
                    "report_finding: HIGH/CRITICAL findings require a replayable PoC "
                    "with exploit attempt, observed result, control/baseline, "
                    f"repeat_count>=2, and negative/refutation result. Missing: {missing}."
                ),
                error="weak_poc",
                data={"proof": proof},
            )

        # Phase B: simple dedup — if a finding with the same (finding_type,
        # affected_component) already exists, skip re-creation and return the
        # existing id. Prevents Brain from reporting the same issue twice when
        # it loses track of its own state.
        # _normalize and _base_path are module-level functions (not closures)
        # so they are not rebuilt on every call.
        new_type = _normalize(_canonical_finding_type(kwargs["finding_type"]))
        new_component = _normalize(kwargs["affected_component"])
        new_base = _base_path(kwargs["affected_component"])
        normalized_extra_evidence = _normalize_extra_evidence(kwargs.get("extra_evidence"))

        for existing in findings:
            ex_type = _normalize(_canonical_finding_type(existing["finding_type"]))
            ex_component = _normalize(existing["affected_component"])
            ex_base = _base_path(existing["affected_component"])

            # Exact match OR same base path + same finding type
            if ex_type == new_type and (ex_component == new_component or ex_base == new_base):
                variants = existing.setdefault("variant_titles", [])
                title = str(kwargs.get("title", "")).strip()
                if title and title not in variants:
                    variants.append(title)
                variant_types = existing.setdefault("variant_finding_types", [])
                raw_type = str(kwargs.get("finding_type", "")).strip()
                if raw_type and raw_type not in variant_types:
                    variant_types.append(raw_type)
                new_poc = str(normalized["poc_script_code"]).strip()
                old_poc = str(existing.get("poc_script_code", "")).strip()
                if new_poc and new_poc not in old_poc:
                    existing["poc_script_code"] = (
                        old_poc + ("\n\n--- Variant replay ---\n" if old_poc else "") + new_poc
                    )
                    existing["evidence"] = existing["poc_script_code"]
                new_analysis = str(normalized["technical_analysis"]).strip()
                old_analysis = str(existing.get("technical_analysis", "")).strip()
                if new_analysis and new_analysis not in old_analysis:
                    existing["technical_analysis"] = (
                        old_analysis + ("\n\nVariant note: " if old_analysis else "") + new_analysis
                    )
                if normalized_extra_evidence:
                    existing_extra = existing.setdefault("extra_evidence", [])
                    existing_keys = {
                        (
                            str(ev.get("evidence_type", "")),
                            str(ev.get("title", "")),
                            str(ev.get("content", "")),
                        )
                        for ev in existing_extra
                        if isinstance(ev, dict)
                    }
                    for ev in normalized_extra_evidence:
                        key = (ev["evidence_type"], ev["title"], ev["content"])
                        if key not in existing_keys:
                            existing_extra.append(ev)
                            existing_keys.add(key)
                # If base-path match, append this variant to affected_endpoints
                if ex_component != new_component:
                    endpoints = existing.get("affected_endpoints", [existing["affected_component"]])
                    if kwargs["affected_component"] not in endpoints:
                        endpoints.append(kwargs["affected_component"])
                    existing["affected_endpoints"] = endpoints
                    logger.info(
                        "[Finding] base-path dedup: %s grouped into %s (%d endpoints)",
                        new_component,
                        existing["id"],
                        len(endpoints),
                    )
                else:
                    logger.info(
                        "[Finding] exact dedup: %s %s (already %s)",
                        new_type,
                        new_component,
                        existing["id"],
                    )
                # NOW-1/1.3: upgrade the deduped finding's verdict UPGRADE-ONLY — a
                # later CONFIRMED re-report promotes a previously-unconfirmed finding
                # (so it stops being excluded); a later UNCONFIRMED must never
                # un-confirm an already-CONFIRMED finding.
                if (
                    str(kwargs.get("verifier_verdict", "")).upper() == "CONFIRMED"
                    and existing.get("verifier_verdict") != "CONFIRMED"
                ):
                    existing["verifier_verdict"] = "CONFIRMED"
                    existing["verified"] = True
                    existing["verifier_confidence"] = str(kwargs.get("verifier_confidence", ""))
                    existing["verifier_reasoning"] = str(kwargs.get("verifier_reasoning", ""))
                return ToolResult(
                    ok=True,
                    data={
                        "id": existing["id"],
                        "total_findings": len(findings),
                        "deduped": True,
                        "affected_endpoints": existing.get("affected_endpoints", []),
                    },
                    summary=(
                        f"finding grouped into {existing['id']} "
                        f"(same base path {ex_base}). "
                        f"Try a DIFFERENT endpoint or attack type instead."
                    ),
                )

        finding_id = f"VXIS-{len(findings) + 1:04d}"
        finding = {
            "id": finding_id,
            "title": str(kwargs["title"]),
            "severity": severity,
            "finding_type": str(kwargs["finding_type"]),
            "affected_component": str(kwargs["affected_component"]),
            "description": normalized["description"],
            "impact": normalized["impact"],
            "technical_analysis": normalized["technical_analysis"],
            "poc_description": normalized["poc_description"],
            "poc_script_code": normalized["poc_script_code"],
            "evidence": normalized["poc_script_code"],
            "remediation": normalized["remediation_steps"],
            "remediation_steps": normalized["remediation_steps"],
            "endpoint": normalized["endpoint"],
            "method": normalized["method"],
            "cwe": str(kwargs.get("cwe", "")),
            "extra_evidence": normalized_extra_evidence,
            "proof": proof if severity in ("high", "critical") else {},
            # NOW-1/1.3: adversarial-verifier verdict stamped by _verify_and_gate.
            # Blank verdict (info / verify_finding absent / legacy) => kept, not excluded.
            "verifier_verdict": str(kwargs.get("verifier_verdict", "")),
            "verifier_confidence": str(kwargs.get("verifier_confidence", "")),
            "verifier_reasoning": str(kwargs.get("verifier_reasoning", "")),
            "verified": str(kwargs.get("verifier_verdict", "")).upper() == "CONFIRMED",
        }
        findings.append(finding)
        logger.info(
            "[Finding] %s [%s] %s — %s",
            finding_id,
            severity.upper(),
            kwargs["finding_type"],
            str(kwargs["title"])[:80],
        )
        _emit_event(
            "hit",
            {
                "finding_id": finding_id,
                "vector_id": finding["finding_type"],
                "level": _severity_to_level(severity),
                "confidence": severity,
                "severity": severity,
                "title": finding["title"],
                "hint": finding["title"][:60],
                "endpoint": finding["affected_component"],
            },
        )

        return ToolResult(
            ok=True,
            data={"id": finding_id, "total_findings": len(findings), "proof": finding["proof"]},
            summary=f"finding recorded: {finding_id} [{severity}] {str(kwargs['title'])[:60]}",
        )


class QueryFindingsTool:
    name = "query_findings"
    description = (
        "Search previously-reported findings. Filter by severity, finding_type, "
        "affected_component substring, or free-text substring match against title/description. "
        "Returns matching finding IDs and summaries."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "severity": {"type": "string", "enum": list(_VALID_SEVERITIES)},
            "finding_type": {"type": "string"},
            "component_contains": {"type": "string"},
            "text_contains": {"type": "string"},
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "description": "Max results (default 20)",
            },
        },
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        findings = _store().findings
        severity = kwargs.get("severity")
        finding_type = kwargs.get("finding_type")
        component_substr = (kwargs.get("component_contains") or "").lower()
        text_substr = (kwargs.get("text_contains") or "").lower()
        try:
            limit = int(kwargs.get("limit", 20))
        except (TypeError, ValueError):
            limit = 20
        limit = max(1, min(100, limit))

        results = []
        for f in findings:
            if severity and f["severity"] != severity:
                continue
            if finding_type and f["finding_type"] != finding_type:
                continue
            if component_substr and component_substr not in f["affected_component"].lower():
                continue
            if text_substr:
                blob = (f["title"] + " " + f["description"]).lower()
                if text_substr not in blob:
                    continue
            results.append(
                {
                    "id": f["id"],
                    "severity": f["severity"],
                    "finding_type": f["finding_type"],
                    "title": f["title"][:120],
                    "affected_component": f["affected_component"],
                }
            )
            if len(results) >= limit:
                break

        return ToolResult(
            ok=True,
            data={"count": len(results), "findings": results, "total_in_store": len(findings)},
            summary=f"query_findings: {len(results)} match(es) (of {len(findings)} total)",
        )


class LinkChainTool:
    name = "link_chain"
    description = (
        "Assert that a sequence of previously-reported findings forms a causal attack chain. "
        "Example: low-sev info disclosure → medium-sev IDOR → high-sev privilege escalation. "
        "Finding IDs must be in the store (report_finding first). High-value chains must "
        "include evidence_artifact proving source output reuse, observed result, control "
        "result, repeat_count>=2, negative/refutation result, and crown-jewel impact."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "finding_ids": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 2,
                "description": "Ordered list of finding IDs forming the chain, e.g. ['VXIS-0001', 'VXIS-0003', 'VXIS-0007']",
            },
            "rationale": {
                "type": "string",
                "description": "Why these findings chain together — the attack narrative",
            },
            "crown_jewel": {
                "type": "string",
                "description": "What the chain ultimately compromises (e.g. 'admin account takeover', 'full DB dump')",
            },
            "evidence_artifact": {
                "type": "object",
                "description": (
                    "VerifiedChainArtifact. Required for high/critical or crown-jewel chains: "
                    "source_output, pivot_action, observed_result, control_result, "
                    "repeat_count>=2, negative_result or negative_control, "
                    "crown_jewel_evidence, and optional hops for 3+ finding chains."
                ),
            },
            "chain_evidence": {
                "description": "Legacy alias for evidence_artifact.",
            },
        },
        "required": ["finding_ids", "rationale"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        store = _store()
        findings = store.findings
        chains = store.chains
        finding_ids = kwargs.get("finding_ids") or []
        rationale = kwargs.get("rationale", "")
        crown_jewel = kwargs.get("crown_jewel", "")
        evidence_artifact = _normalize_chain_artifact(
            kwargs.get("evidence_artifact")
            or kwargs.get("chain_evidence")
            or kwargs.get("proof")
            or kwargs.get("evidence")
            or {}
        )

        if not isinstance(finding_ids, list) or len(finding_ids) < 2:
            return ToolResult(
                ok=False,
                summary="link_chain: need at least 2 finding IDs",
                error="insufficient_findings",
            )
        if not rationale:
            return ToolResult(
                ok=False, summary="link_chain: rationale is required", error="missing_rationale"
            )

        known_ids = {f["id"] for f in findings}
        unknown = [fid for fid in finding_ids if fid not in known_ids]
        if unknown:
            return ToolResult(
                ok=False,
                summary=f"link_chain: unknown finding IDs {unknown}. Use report_finding first.",
                error="unknown_finding_ids",
            )

        proof = _evaluate_chain_artifact(
            finding_ids=[str(fid) for fid in finding_ids],
            rationale=str(rationale),
            crown_jewel=str(crown_jewel),
            evidence_artifact=evidence_artifact,
        )
        if not proof["ok"]:
            missing = ", ".join(proof["missing"])
            return ToolResult(
                ok=False,
                summary=(
                    "link_chain: high-value chains require a VerifiedChainArtifact "
                    "with source output reuse, observed result, control result, "
                    "repeat_count>=2, negative/refutation result, and crown-jewel "
                    f"evidence. Missing: {missing}."
                ),
                error="weak_chain_proof",
                data={"proof": proof},
            )

        new_signature = _chain_signature(list(finding_ids), str(crown_jewel))
        for existing in chains:
            existing_ids = list(existing.get("finding_ids") or [])
            if tuple(existing_ids) == tuple(finding_ids):
                return ToolResult(
                    ok=True,
                    data={
                        "id": existing.get("id", ""),
                        "length": len(existing_ids),
                        "total_chains": len(chains),
                        "dedup": True,
                        "verification_status": existing.get("verification_status", "narrative"),
                        "proof": existing.get("proof", {}),
                    },
                    summary=f"link_chain: duplicate chain ignored ({existing.get('id', '')})",
                )
            if (
                _chain_signature(existing_ids, str(existing.get("crown_jewel", "")))
                == new_signature
            ):
                return ToolResult(
                    ok=True,
                    data={
                        "id": existing.get("id", ""),
                        "length": len(existing_ids),
                        "total_chains": len(chains),
                        "dedup": True,
                        "verification_status": existing.get("verification_status", "narrative"),
                        "proof": existing.get("proof", {}),
                    },
                    summary=f"link_chain: similar chain ignored ({existing.get('id', '')})",
                )

        chain_id = f"CHAIN-{len(chains) + 1:03d}"
        chain = {
            "id": chain_id,
            "finding_ids": list(finding_ids),
            "rationale": str(rationale),
            "crown_jewel": str(crown_jewel),
            "length": len(finding_ids),
            "evidence_artifact": evidence_artifact,
            "proof": proof,
            "verification_status": "verified" if proof.get("verified") else "narrative",
        }
        chains.append(chain)
        logger.info("[Chain] %s: %s → %s", chain_id, " → ".join(finding_ids), str(crown_jewel)[:60])
        first = _finding_by_id(finding_ids[0]) or {}
        _emit_event(
            "chain_start",
            {
                "chain_id": chain_id,
                "finding_type": str(first.get("finding_type", "chain")),
                "endpoint": str(first.get("affected_component", "")),
                "vector_id": str(first.get("finding_type", "chain")),
                "finding_ids": list(finding_ids),
                "source_id": str(finding_ids[0]) if finding_ids else "",
                "target_id": str(finding_ids[-1]) if finding_ids else "",
                "source_title": str(first.get("title", "")),
                "rationale": str(rationale),
                "crown_jewel": str(crown_jewel),
                "verification_status": chain["verification_status"],
            },
        )
        for fid in finding_ids:
            finding = _finding_by_id(fid) or {}
            _emit_event(
                "chain_step",
                {
                    "chain_id": chain_id,
                    "finding_id": fid,
                    "vector_id": str(finding.get("finding_type", fid)),
                    "endpoint": str(finding.get("affected_component", "")),
                    "level": _severity_to_level(str(finding.get("severity", "low"))),
                    "reasoning": str(finding.get("title", rationale))[:60],
                    "title": str(finding.get("title", "")),
                    "severity": str(finding.get("severity", "low")),
                },
            )

        return ToolResult(
            ok=True,
            data={
                "id": chain_id,
                "length": len(finding_ids),
                "total_chains": len(chains),
                "verification_status": chain["verification_status"],
                "proof": proof,
            },
            summary=(
                f"chain recorded: {chain_id} ({len(finding_ids)} findings) "
                f"[{chain['verification_status']}] → {str(crown_jewel)[:60]}"
            ),
        )
