"""ScanPipelineV2 — Strix-parity thin shim over ScanAgentLoop.

Replaces the 5234-line ScanPipeline (pipeline.py) with a clean entrypoint
that delegates actual scanning to the new single-loop ReAct architecture.

Flow:
    1. Build ScanContext (target, scan_id, ghost activation)
    2. Build ToolRegistry via tools.build_default_registry()
    3. Reset finding_tools state (clean per-scan findings store)
    4. Create ScanAgentLoop(target, registry, brain=brain, max_iters=...)
    5. Run the loop
    6. Copy findings from finding_tools._get_findings() into ctx.findings as
       Finding objects (using minimal valid field set)
    7. Copy chains from finding_tools._get_chains() into ctx.attack_chains
    8. If deferred actions accumulated, run _execute_deferred_actions
    9. Generate the HTML report via ReportGenerator
    10. Compute a simple VXIS score
    11. Return ctx

Preserves the ScanPipeline constructor signature for backward compatibility
with cli/main.py:590.

Phase A adaptations (documented):
  - Finding is imported from `vxis.models.finding` (NOT `vxis.evidence.schema`,
    which only exposes Severity/Evidence/EvidenceType).
  - ReportData is re-exported from `vxis.report.generator` (there is no
    `vxis.report.schema` module).
  - `ctx.duration_seconds` is a read-only @property on ScanContext, so we do
    NOT assign to it — we just let it compute from `started_at`.
  - `ctx.attack_chains` is typed `list[dict]`, so chains from the finding
    store are wrapped as dicts rather than flat id-lists.
  - `ctx.vxis_score` is NOT a dataclass field; it is attached as a dynamic
    attribute (ScanContext is not frozen).
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

from vxis.agent.brain import (
    get_brain_decision_count,
    get_llm_call_count,
    get_llm_usage_stats,
    reset_brain_decision_count,
    reset_llm_call_count,
    reset_llm_usage_stats,
)
from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tools import build_default_registry
from vxis.agent.tools.finding_tools import _get_chains as _get_chain_dicts
from vxis.agent.tools.finding_tools import _get_findings as _get_finding_dicts
from vxis.agent.tools.finding_tools import _reset_for_tests as _reset_finding_store
from vxis.agent.tools.finding_tools import set_event_callback as _set_finding_event_callback
from vxis.agent.tools.memory_tools import (
    load_target_memory_profile as _load_target_memory_profile,
    record_scan_result as _record_scan_memory,
)
from vxis.interaction.surface import TargetKind
from vxis.pipeline.context import ScanContext
from vxis.pipeline.launcher import prepare_target_runtime

logger = logging.getLogger(__name__)


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("invalid %s=%r; using %d", name, raw, default)
        return default
    return max(minimum, value)


def _split_proxy_env(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _ghost_proxy_pool_from_config(config: Any | None) -> list[str]:
    proxies: list[str] = []
    if config is not None:
        proxies.extend(_split_proxy_env(getattr(config, "proxy_pool", [])))
    proxies.extend(_split_proxy_env(os.environ.get("VXIS_PROXY_POOL", "")))
    proxies.extend(_split_proxy_env(os.environ.get("VXIS_GHOST_PROXIES", "")))

    deduped: list[str] = []
    seen: set[str] = set()
    for proxy in proxies:
        if proxy in seen:
            continue
        seen.add(proxy)
        deduped.append(proxy)
    return deduped


def _resolve_scan_loop_budget() -> tuple[int, int, int]:
    """Return (soft_max, hard_max, extension_chunk) for the Brain loop."""
    provider = os.environ.get("UPSTREAM_LLM_PROVIDER", "").strip().lower()
    is_local = provider in {"llamacpp", "ollama"}

    # 50 was a Phase-A safety cap. Local models need room to pursue live leads;
    # cloud runs keep a lower default to limit accidental spend.
    default_soft = 300 if is_local else 120
    default_hard = 1000 if is_local else 300
    soft_max = _env_int("VXIS_SCAN_MAX_ITERS", default_soft, minimum=10)
    hard_max = _env_int("VXIS_SCAN_HARD_MAX_ITERS", default_hard, minimum=soft_max)
    extension_chunk = _env_int("VXIS_SCAN_EXTEND_ITERS", 50, minimum=10)
    return soft_max, max(soft_max, hard_max), extension_chunk


def _extract_final_report_sections(messages: list[dict[str, Any]]) -> dict[str, str]:
    """Extract the last successful finish_scan payload from loop messages."""
    for msg in reversed(messages):
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if not isinstance(content, dict):
            continue
        if content.get("name") != "finish_scan":
            continue
        result = content.get("result") or {}
        if not isinstance(result, dict) or not result.get("ok"):
            continue
        data = result.get("data") or {}
        if not isinstance(data, dict):
            continue
        final_report = data.get("final_report") or {}
        if not isinstance(final_report, dict):
            continue
        return {
            "executive_summary": str(final_report.get("executive_summary", "")).strip(),
            "methodology": str(final_report.get("methodology", "")).strip(),
            "technical_analysis": str(final_report.get("technical_analysis", "")).strip(),
            "recommendations": str(final_report.get("recommendations", "")).strip(),
        }
    return {}


def _memory_finding_to_vector_seed(
    finding_type: str, title: str, component: str
) -> tuple[str, str, int] | None:
    ft = str(finding_type or "").lower()
    if ft in {"auth_bypass", "weak_auth", "default_credentials"}:
        return ("WEB-AUTH-001", title or "Authentication bypass or weak login", 90)
    if ft in {"sql_injection", "sqli", "sqli_time", "sqli_blind"}:
        return ("WEB-SQLI-001", title or "SQL injection toward DB/admin data", 92)
    if ft in {"idor", "broken_access_control"}:
        return ("WEB-AC-001", title or "IDOR or broken access control", 88)
    if ft in {"information_disclosure", "misconfiguration"}:
        return ("WEB-MISCONF-001", title or "Sensitive files or exposed config", 78)
    if ft.startswith("xss") or ft == "xss":
        return ("WEB-XSS-001", title or "XSS toward session theft", 72)
    if ft == "ssrf":
        return ("WEB-SSRF-001", title or "SSRF/internal reachability", 70)
    if ft == "csrf":
        return ("WEB-CSRF-001", title or "CSRF on state-changing flow", 65)
    if not ft:
        return None
    return (f"MEM-{ft.upper()[:12]}", title or component or ft, 60)


def _memory_branch_priority(lead: dict[str, Any]) -> int:
    role = str(lead.get("role", "")).lower()
    phase = str(lead.get("phase", "")).lower()
    status = str(lead.get("status", "")).lower()
    priority = 78
    if role == "post_exploit_worker":
        priority += 10
    if phase in {"privilege_probe", "data_access", "chain_closure"}:
        priority += 6
    if status in {"active", "retryable", "open"}:
        priority += 4
    return min(priority, 95)


def _normalize_carryover_title(title: str) -> str:
    value = str(title or "").strip().lower()
    while value.startswith("carryover:"):
        value = value[len("carryover:") :].strip()
    return value


def _build_finding_from_dict(
    d: dict[str, Any],
    scan_id: str,
    target: str,
    *,
    kind: TargetKind = TargetKind.WEB,
) -> Any:
    """Convert a finding_tools dict into a Finding object for the report.

    Uses minimal valid field set; richer structure (MITRE, bilingual PoC) is
    filled with safe defaults because Phase A's ScanAgentLoop doesn't yet
    emit them. Phase B will enrich.

    `kind` (phase-G) tags every Evidence with the originating Surface so
    cross_protocol synthesis can flag chains that span >1 surface kind.
    Defaults to WEB so legacy callers and single-target web scans behave
    identically to the pre-phase-G build.
    """
    from vxis.evidence.schema import Severity
    from vxis.agent.tools.finding_tools import _canonical_finding_type
    from vxis.models.finding import CVSSVector, Evidence, Finding

    sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "informational": Severity.INFO,
    }
    severity = sev_map.get(str(d.get("severity", "medium")).lower(), Severity.MEDIUM)

    title = str(d.get("title", "Untitled finding"))
    desc_body = str(d.get("description", ""))
    impact_body = str(d.get("impact", ""))
    technical_body = str(d.get("technical_analysis", ""))
    poc_description = str(d.get("poc_description", ""))
    poc_script_code = str(d.get("poc_script_code", ""))
    remediation_body = str(d.get("remediation_steps") or d.get("remediation", ""))

    bilingual_title = f"{title}|||{title}"
    bilingual_desc = f"{desc_body}|||{desc_body}"
    bilingual_impact = f"{impact_body}|||{impact_body}" if impact_body else None
    bilingual_technical = f"{technical_body}|||{technical_body}" if technical_body else None
    bilingual_poc = f"{poc_description}|||{poc_description}" if poc_description else None
    bilingual_remediation = (
        f"{remediation_body}|||{remediation_body}" if remediation_body else "TBD|||TBD"
    )

    evidence_text = poc_script_code or str(d.get("evidence", "")) or "No evidence captured."
    evidence_list = [
        Evidence(
            evidence_type="exploit" if poc_script_code else "log",
            title="Proof of Concept" if poc_script_code else "Supporting evidence",
            content=evidence_text,
            surface=kind,
        )
    ]
    for item in d.get("extra_evidence") or []:
        if not isinstance(item, dict):
            continue
        evidence_type = str(item.get("evidence_type", "")).strip()
        title_text = str(item.get("title", "")).strip()
        content_text = str(item.get("content", "")).strip()
        if not evidence_type or not title_text or not content_text:
            continue
        evidence_list.append(
            Evidence(
                evidence_type=evidence_type,
                title=title_text,
                content=content_text,
                content_type=str(item.get("content_type", "text/plain")).strip() or "text/plain",
                surface=kind,
            )
        )

    cvss_score_by_sev = {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.5,
        Severity.LOW: 3.5,
        Severity.INFO: 1.0,
    }
    cvss = CVSSVector(
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=cvss_score_by_sev[severity],
    )

    cwe_raw = str(d.get("cwe", ""))
    cwe_ids = [cwe_raw] if cwe_raw else []

    return Finding(
        id=str(d.get("id", "VXIS-0000")),
        scan_id=scan_id,
        target=target,
        title=bilingual_title,
        description=bilingual_desc,
        impact=bilingual_impact,
        technical_analysis=bilingual_technical,
        poc_description=bilingual_poc,
        poc_script_code=poc_script_code or None,
        severity=severity,
        finding_type=_canonical_finding_type(str(d.get("finding_type", "generic"))),
        source_plugin="scan_agent_loop",
        affected_component=str(d.get("affected_component", "")),
        cvss=cvss,
        cwe_ids=cwe_ids,
        evidence=evidence_list,
        remediation=bilingual_remediation,
        references=[],
    )


# Back-compat alias — older callers reference the legacy name. New code should
# import _build_finding_from_dict.
_finding_dict_to_finding_object = _build_finding_from_dict


# Sandbox command fingerprint → vector IDs. Credits VC (Vector Coverage) when
# Brain uses shell_exec/python_exec instead of (or alongside) run_skill.
# Phase 3 made sandbox the primary attack surface; Phase 4 makes the score
# reflect that. Conservative mapping: only clear pentest-tool keywords count.
#
# Order matters — python jwt check runs before generic command matching so
# that `python -c "import jwt"` doesn't also match a made-up `jwt` command.
_SANDBOX_TOOL_VECTORS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sqlmap", ("WEB-SQLI-001",)),
    ("nuclei", ("WEB-INFO-001", "WEB-MISC-001")),
    ("nikto", ("WEB-MISC-001", "WEB-INFO-001")),
    ("wapiti", ("WEB-SQLI-001", "WEB-XSS-001")),
    ("hydra", ("WEB-AUTH-001",)),
    ("ffuf", ("WEB-INFO-001",)),
    ("gobuster", ("WEB-INFO-001",)),
    ("dirsearch", ("WEB-INFO-001",)),
    ("wfuzz", ("WEB-INFO-001",)),
)

# Python code fingerprints — substring match on source.
_PYTHON_CODE_VECTORS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("import jwt", ("WEB-JWT-001",)),
    ("jwt.encode", ("WEB-JWT-001",)),
    ("jwt.decode", ("WEB-JWT-001",)),
    ("alg.*none", ("WEB-JWT-001",)),
)


def _sandbox_cmd_to_vectors(cmd: str) -> list[str]:
    """Map a sandbox command/code string to vector IDs it likely exercises.

    Returns [] for unknown or empty input — no VC inflation. Case-insensitive
    substring match; tolerates absolute paths (`/usr/bin/sqlmap`), quoted args,
    and mixed case. Python keywords (`import jwt`, `jwt.encode`) credit JWT
    vector so that hand-rolled JWT confusion PoCs aren't scored below run_skill.
    """
    if not cmd or not isinstance(cmd, str):
        return []
    lowered = cmd.lower()
    hits: list[str] = []
    seen: set[str] = set()
    for keyword, vectors in _SANDBOX_TOOL_VECTORS:
        if keyword in lowered:
            for v in vectors:
                if v not in seen:
                    hits.append(v)
                    seen.add(v)
    for keyword, vectors in _PYTHON_CODE_VECTORS:
        if keyword in lowered:
            for v in vectors:
                if v not in seen:
                    hits.append(v)
                    seen.add(v)
    return hits


# Module-level mappings — lifted from `_compute_vxis_score()` so tests can pin
# the symmetry between dispatchable skills (`scan_loop._DESKTOP_SKILLS`) and
# vector denominator entries. Inline definitions hid a regression where new
# skills added to the mapping never made it into the dispatch frozenset,
# producing a permanent VC penalty (commit history: see Phase-F → smoke C1).
_WEB_SKILL_TO_VECTORS: dict[str, list[str]] = {
    "enumerate_endpoints": ["WEB-INFO-001", "WEB-INFO-002"],
    "test_sensitive_files": ["WEB-INFO-001"],
    "test_infra": ["WEB-MISC-001", "WEB-INFO-001"],
    "attempt_auth": ["WEB-AUTH-001"],
    "post_auth_enum": ["WEB-BAC-001"],
    "test_injection": ["WEB-SQLI-001", "WEB-CMDI-001"],
    "test_xss": ["WEB-XSS-001", "WEB-XSS-002"],
    "test_ssrf": ["WEB-SSRF-001"],
    "test_idor": ["WEB-IDOR-001"],
    "test_auth_deep": ["WEB-JWT-001", "WEB-AUTH-001"],
    "test_csrf": ["WEB-CSRF-001"],
    "test_misconfig": ["WEB-MISC-001"],
    "test_api_security": ["WEB-BAC-001", "WEB-IDOR-001"],
    "test_business_logic": ["WEB-LOGIC-001"],
    "test_crypto": ["WEB-CRYPTO-001"],
}

_DESKTOP_SKILL_TO_VECTORS: dict[str, list[str]] = {
    "test_local_storage_secrets": ["DESK-LSS-001"],
    "test_electron_misconfig": ["DESK-ELC-001", "DESK-ELC-002", "DESK-ELC-003"],
    "test_signature_audit": [
        "DESK-RECON-001",
        "DESK-SIG-001",
        "DESK-SIG-002",
        "DESK-SIG-003",
        "DESK-SIG-004",
    ],
    "test_entitlement_audit": [
        "DESK-RECON-001",
        "DESK-ENT-001",
        "DESK-ENT-002",
        "DESK-ENT-003",
    ],
    "test_dylib_hijack": ["DESK-DYL-001", "DESK-DYL-002", "DESK-DYL-003"],
    "test_deeplink_abuse": ["DESK-DLK-001", "DESK-DLK-002", "DESK-DLK-003"],
    "test_ipc_injection": ["DESK-IPC-001"],
    "test_binary_protections": ["DESK-PIE-001", "DESK-PIE-002", "DESK-PIE-003"],
}


def _compute_vxis_score(ctx: Any) -> tuple[float, str]:
    """Compute VXIS score using the full 5-dimension ScoringEngine.

    Populates a ScoreTracker from scan findings, then runs ScoringEngine.
    Falls back to simple severity sum if ScoringEngine fails.
    """
    try:
        from vxis.scoring.engine import ScoringEngine
        from vxis.scoring.tracker import ScoreTracker

        tracker = ScoreTracker(target_type=ctx.kind.value)

        # Map finding types to vector IDs
        _type_to_vector = {
            "sql_injection": "WEB-SQLI-001",
            "xss_reflected": "WEB-XSS-001",
            "xss_stored": "WEB-XSS-002",
            "xss": "WEB-XSS-001",
            "ssrf": "WEB-SSRF-001",
            "idor": "WEB-IDOR-001",
            "broken_access_control": "WEB-BAC-001",
            "information_disclosure": "WEB-INFO-001",
            "path_traversal": "WEB-TRAV-001",
            "auth_bypass": "WEB-AUTH-001",
            "weak_auth": "WEB-AUTH-001",
            "csrf": "WEB-CSRF-001",
            "xxe": "WEB-XXE-001",
            "rce": "WEB-RCE-001",
            "command_injection": "WEB-CMDI-001",
            "error_oracle": "WEB-INFO-002",
            "misconfiguration": "WEB-MISC-001",
            "open_redirect": "WEB-REDIR-001",
            "jwt_confusion": "WEB-JWT-001",
            "weak_crypto": "WEB-CRYPTO-001",
            "business_logic": "WEB-LOGIC-001",
        }

        # Severity → exploitation level
        _sev_to_level = {
            "critical": 3,  # exploit successful + post-exploit
            "high": 2,  # exploit successful
            "medium": 1,  # vulnerability confirmed
            "low": 0,  # recon only
            "informational": 0,
        }

        # Record vectors from ALL executed skills (including clean results)
        # so that vector_coverage reflects attempted vectors, not just findings.
        # Mappings live at module scope (top of file) so the symmetry test
        # can pin them against `scan_loop._DESKTOP_SKILLS`.
        _kind_value = ctx.kind.value if hasattr(ctx.kind, "value") else str(ctx.kind)
        _skill_to_vectors = (
            _DESKTOP_SKILL_TO_VECTORS if _kind_value == "desktop" else _WEB_SKILL_TO_VECTORS
        )
        # Get completed skills from scan loop result
        _completed_skills: set[str] = set(getattr(ctx, "skills_completed", []) or [])

        for skill_name, vector_ids in _skill_to_vectors.items():
            if skill_name in _completed_skills:
                for vid in vector_ids:
                    tracker.record_vector_attempt(vid)

        # Phase 4: credit sandbox (shell_exec / python_exec) usage.
        # Brain-First + Phase 3 sandbox primacy require scoring to reward
        # creative tool use, not just the 15 pre-built skills.
        _sandbox_invocations = getattr(ctx, "sandbox_invocations", []) or []
        for inv in _sandbox_invocations:
            if not isinstance(inv, dict):
                continue
            _cmd = inv.get("cmd") or inv.get("code") or inv.get("command") or ""
            for vid in _sandbox_cmd_to_vectors(str(_cmd)):
                tracker.record_vector_attempt(vid)

        # Phase E: first-class vector candidate state. The scan loop now
        # preserves durable hypotheses and concrete attempt outcomes, so
        # vector coverage can credit any real attempt even when it was clean,
        # blocked, or failed before producing a finding.
        _attempt_outcomes = getattr(ctx, "attempt_outcomes", []) or []
        for outcome in _attempt_outcomes:
            if not isinstance(outcome, dict):
                continue
            vid = str(outcome.get("vector_id") or "")
            if vid:
                tracker.record_vector_attempt(vid)
                if str(outcome.get("status") or "") == "found":
                    tracker.vectors_found.add(vid)

        for f in ctx.findings:
            ftype = (
                f.finding_type
                if hasattr(f, "finding_type")
                else str(getattr(f, "finding_type", ""))
            )
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            fid = f.id if hasattr(f, "id") else str(getattr(f, "id", ""))

            vector_id = _type_to_vector.get(ftype, f"WEB-{ftype.upper()[:8]}-001")
            level = _sev_to_level.get(sev, 0)

            tracker.record_vector_attempt(vector_id)
            if level >= 1:
                tracker.vectors_found.add(vector_id)
            tracker.exploitation_levels[fid] = level
            tracker.finding_vectors[fid] = vector_id

            # Evidence count from finding
            evidence_count = 0
            if hasattr(f, "evidence") and f.evidence:
                evidence_count = len(f.evidence) if isinstance(f.evidence, list) else 1
            tracker.evidence_counts[fid] = evidence_count

        # Verifier verdicts → precision
        confirmed = getattr(ctx, "confirmed_findings", []) or []
        refuted = getattr(ctx, "refuted_findings", []) or []
        for cf in confirmed:
            fid = cf.get("title", "")[:20]
            tracker.analyst_verdicts[fid] = True
        for rf in refuted:
            fid = rf.get("title", "")[:20]
            tracker.analyst_verdicts[fid] = False

        # Attack chains
        chains = getattr(ctx, "attack_chains", []) or []
        if chains:
            from vxis.scoring.tracker import AttackChain

            for i, chain in enumerate(chains):
                ac = AttackChain(chain_id=f"chain-{i}")
                ids = chain.get("finding_ids", chain) if isinstance(chain, dict) else chain
                if isinstance(ids, list):
                    for j, fid in enumerate(ids):
                        ac.add_step(
                            vector_id="WEB-CHAIN",
                            finding_id=str(fid),
                            level=min(j + 1, 4),
                            description_en=f"Chain step {j + 1}",
                            description_ko=f"체인 단계 {j + 1}",
                        )
                tracker.attack_chains.append(ac)

        # Phase completion — single scan_loop phase
        from vxis.scoring.tracker import PhaseResult, PhaseStatus

        _loop_completed = getattr(ctx, "scan_loop_completed", True)
        tracker.phase_results["scan_loop"] = PhaseResult(
            phase_name="scan_loop",
            status=PhaseStatus.completed if _loop_completed is not False else PhaseStatus.failed,
            findings_count=len(ctx.findings),
            error=None
            if _loop_completed is not False
            else "ScanAgentLoop hit max_iters before finish_scan",
        )

        # Use the scan's actual kind so DESKTOP scans aren't silently scored
        # against the WEB vector pool (was producing "[SCORE] WEB" for desktop
        # scans pre-Q5).
        engine = ScoringEngine(_kind_value)
        vxis_score = engine.calculate(tracker, ctx.findings, scan_id=ctx.scan_id)

        # Print detailed score
        print(vxis_score.summary_text())

        # Expose full VXISScore on ctx so benchmark/comparison can access 5-dim breakdown.
        # ADR-007 regression gate reads this; ctx.vxis_score stays as _SimpleScore for CLI.
        try:
            setattr(ctx, "score_detail", vxis_score)
        except Exception:
            pass

        return vxis_score.total, vxis_score.grade

    except Exception:
        import logging

        logging.getLogger(__name__).exception("ScoringEngine failed, using fallback")
        # Fallback: simple severity sum
        sev_weights = {"critical": 200, "high": 100, "medium": 50, "low": 20, "informational": 5}
        score = 0.0
        for f in ctx.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            score += sev_weights.get(sev, 5)
        score = min(1000.0, score)
        grade = (
            "A"
            if score >= 700
            else "B"
            if score >= 400
            else "C"
            if score >= 200
            else "D"
            if score > 0
            else "F"
        )
        return score, grade


class _SimpleScore:
    """Minimal score object for ctx.vxis_score — matches cli/main.py's access pattern."""

    def __init__(self, total: float, grade: str) -> None:
        self.total = total
        self.grade = grade


class ScanPipeline:
    """Task 10 shim — constructor signature matches the legacy ScanPipeline
    so cli/main.py:590 keeps working unchanged.
    """

    def __init__(
        self,
        brain: Any,
        config: Any | None = None,
        enable_deferred_approval: bool = True,
        approval_callback: Callable[[list], Awaitable[list[bool]]] | None = None,
        event_callback: Callable[[str, dict], None] | None = None,
        injection_approval_callback: Callable[[dict], Awaitable[bool]] | None = None,
        auto_approve_injection: bool = False,
        report_output_path: Path | str | None = None,
        generate_report: bool = True,
    ) -> None:
        self.brain = brain
        self.config = config
        self.enable_deferred_approval = enable_deferred_approval
        self._approval_callback = approval_callback
        self._event_callback = event_callback
        self._injection_approval_callback = injection_approval_callback
        self._auto_approve_injection = auto_approve_injection
        self._report_output_path = report_output_path
        self._generate_report_enabled = generate_report

    def _emit(self, event_type: str, data: dict) -> None:
        if self._event_callback:
            try:
                self._event_callback(event_type, data)
            except Exception:
                logger.exception("event_callback raised — ignoring")

    def _resolve_and_attach_policy(self, ctx: ScanContext) -> None:
        """Component P: resolve + attach the scan policy, gated behind the v3
        flag. Fail-closed default when off/unknown; no chokepoint is wired in
        this increment — this only makes ctx.policy available."""
        from vxis.agent.policy.scan_policy import resolve_policy
        from vxis.agent.scan_loop_v3 import v3_enabled, v3_flag

        if v3_flag("VXIS_V3_POLICY") or v3_enabled():
            ctx.policy = resolve_policy(self.config)

    async def run(
        self,
        target: str,
        app_context_en: str = "",
        app_context_ko: str = "",
        resume_from: str | None = None,  # Phase A: ignored, kept for signature compat
        kind: TargetKind = TargetKind.WEB,
        target_hints: dict[str, str] | None = None,
    ) -> ScanContext:
        """Run a Strix-parity single-loop scan against the target."""
        started = time.monotonic()

        # 1. Prepare target runtime through the platform launcher layer.
        self._emit(
            "phase_start", {"phase": "runtime_prepare", "kind": kind.value, "target": target}
        )
        runtime = await prepare_target_runtime(target, kind, hints=target_hints)
        from vxis.scope.runtime_gate import ensure_active_scope, clear_active_scope

        _scope_owned = ensure_active_scope(runtime.resolved_target)
        try:
            self._emit(
                "phase_end",
                {
                    "phase": "runtime_prepare",
                    "kind": kind.value,
                    "target": runtime.resolved_target,
                    "launcher": runtime.launcher_name,
                    "runtime_mode": runtime.runtime_mode,
                },
            )

            # 2. Build context
            ctx = ScanContext(
                target=runtime.resolved_target,
                kind=kind,
                app_context_en=app_context_en,
                app_context_ko=app_context_ko,
                scan_id=f"VXIS-{time.strftime('%Y%m%d-%H%M%S')}",
            )
            self._resolve_and_attach_policy(ctx)
            ctx.runtime_profile = {  # type: ignore[attr-defined]
                "launcher_name": runtime.launcher_name,
                "runtime_mode": runtime.runtime_mode,
                "metadata": dict(runtime.metadata),
            }
            ctx.launcher_notes = list(runtime.shared_notes)  # type: ignore[attr-defined]
            ctx.target_hints = dict(target_hints or {})  # type: ignore[attr-defined]
            ghost_activated_here = False

            # Ghost activation — preserve behavior from legacy pipeline
            try:
                from vxis.ghost.layer import ghost_layer
                from vxis.ghost.trigger import parse_ghost_trigger

                _activated, target = parse_ghost_trigger(runtime.resolved_target, self.config)
                ctx.target = target
                if _activated:
                    proxy_pool = _ghost_proxy_pool_from_config(self.config)
                    ghost_layer.activate(proxy_pool=proxy_pool)
                    ghost_activated_here = True
                    ctx.runtime_profile["metadata"]["ghost_active"] = True  # type: ignore[index]
                    ctx.runtime_profile["metadata"]["ghost_proxy_count"] = len(proxy_pool)  # type: ignore[index]
                    self._emit(
                        "ghost",
                        {
                            "active": True,
                            "proxy_count": len(proxy_pool),
                            "target": ctx.target,
                        },
                    )
                    logger.info(
                        "[Ghost] activated for ScanPipelineV2 target=%s proxies=%d",
                        ctx.target,
                        len(proxy_pool),
                    )
            except Exception:
                logger.exception("Ghost activation failed — continuing without ghost transport")

            # 3. Reset per-scan state (findings + brain counters + playbook dedup)
            _reset_finding_store()
            _set_finding_event_callback(self._emit)
            reset_brain_decision_count()
            reset_llm_call_count()
            reset_llm_usage_stats()
            try:
                from vxis.agent.tools.playbook_tools import _loaded_playbooks

                _loaded_playbooks.clear()
            except Exception:
                pass

            # 4. Propagate surface kind into Brain so it selects the right system prompt.
            # Brain is constructed before run() — we patch _target_kind here because
            # kind is only known at scan time, not at construction time.
            # Brain이 올바른 시스템 프롬프트를 선택할 수 있도록 서피스 종류를 주입합니다.
            # Brain은 run() 이전에 생성되므로 스캔 시점에만 알 수 있는 kind를 여기서 패치합니다.
            if hasattr(self.brain, "_target_kind"):
                self.brain._target_kind = kind

            # 5. Build the tool registry
            registry = build_default_registry(
                brain=self.brain,
                sandbox_key=str(getattr(ctx, "scan_id", "") or ctx.target),
            )

            # 6. Emit a synthetic phase_start so the CLI Rich Live display has content
            self._emit("phase_start", {"phase": "scan_loop", "name": "ScanAgentLoop"})

            # 7. Create + run the ScanAgentLoop
            max_iters, hard_max_iters, extend_iters = _resolve_scan_loop_budget()
            logger.info(
                "scan loop budget: soft=%d hard=%d extend=%d",
                max_iters,
                hard_max_iters,
                extend_iters,
            )
            loop = ScanAgentLoop(
                target=ctx.target,
                registry=registry,
                max_iters=max_iters,
                hard_max_iters=hard_max_iters,
                adaptive_budget=True,
                extend_iters=extend_iters,
                brain=self.brain,
                target_kind=kind,
                event_callback=self._emit,
            )
            for note in runtime.shared_notes[:3]:
                loop.state.add_shared_note(note)

            # Cross-scan target memory: turn prior scans into concrete strategy
            # pressure, not just passive notes.
            try:
                target_memory = _load_target_memory_profile(ctx.target)
                ctx.target_memory = target_memory  # type: ignore[attr-defined]
                if target_memory.get("target_known"):
                    loop._target_memory_profile = target_memory  # type: ignore[attr-defined]
                    loop.state.add_shared_note(
                        f"memory: {target_memory['prior_scan_count']} prior scan(s) for this target."
                    )
                    loop.state.add_shared_note(
                        "memory strategy: first revalidate the strongest prior lead, then spend at least one branch on unexplored surface."
                    )
                    for prior in (target_memory.get("known_findings") or [])[:4]:
                        ft = str(prior.get("finding_type", ""))
                        component = str(prior.get("affected_component", ""))
                        title = str(prior.get("title", "") or ft or component)
                        seed = _memory_finding_to_vector_seed(ft, title, component)
                        if seed is None:
                            continue
                        vector_id, seed_title, priority = seed
                        branch_id = f"memory:{ft}:{component or seed_title}".lower().replace(
                            " ", "_"
                        )[:120]
                        evidence = (
                            f"Previously observed finding on this target: {ft} at {component or ctx.target}. "
                            "Revalidate quickly, then deepen or pivot beyond the previously known scope."
                        )
                        loop.state.ensure_vector_candidate(
                            branch_id,
                            vector_id,
                            f"Revalidate prior {seed_title}",
                            priority=priority,
                            evidence=evidence,
                        )
                    for tactic in (target_memory.get("successful_tactics") or [])[:3]:
                        loop.state.add_shared_note(
                            "memory tactic: "
                            + str(tactic.get("finding_type", ""))
                            + " -> "
                            + str(tactic.get("reasoning", "") or tactic.get("title", ""))[:120]
                        )
                    for refuted in (target_memory.get("refuted_patterns") or [])[:3]:
                        loop.state.add_shared_note(
                            "memory refuted: suppress weak "
                            + str(refuted.get("finding_type", ""))
                            + " on "
                            + str(refuted.get("affected_component", ""))[:80]
                        )
                    for lead in (target_memory.get("branch_leads") or [])[:3]:
                        lead_priority = _memory_branch_priority(lead)
                        loop.state.ensure_branch(
                            f"carry:{lead.get('id', 'branch')}",
                            str(lead.get("vector_id", "MEM-CARRY")),
                            str(lead.get("title", "Carry-over branch")),
                            priority=lead_priority,
                            role=str(lead.get("role", "post_exploit_worker")),
                            phase=str(lead.get("phase", "")),
                            owner="memory",
                            objective=str(lead.get("objective", "")),
                            next_step=str(lead.get("next_step", "")),
                            blocker="carry-over lead",
                            evidence="carry-over memory lead from previous scan; resume, verify current validity, then push deeper.",
                            watch_terms=[
                                str(lead.get("title", "")),
                                str(lead.get("vector_id", "")),
                            ],
                        )
                        loop.state.add_shared_note(
                            f"memory branch: reopen {lead.get('title', 'branch')} as p{lead_priority} {lead.get('role', 'worker')}/{lead.get('phase', '?')}"
                        )
            except Exception:
                logger.exception("Failed to seed scan loop from target memory profile")

            # Local retrospective feedback loop: seed the next run with the most
            # recent runtime weaknesses for this target. This is separate from the
            # GitHub Actions growth loop and is meant for unattended local scans.
            try:
                from vxis.growth.scan_retrospective import load_latest_target_retrospective

                prior_retro = load_latest_target_retrospective(ctx.target)
                if prior_retro:
                    for hint in (prior_retro.get("improvement_hints") or [])[:3]:
                        reason = str(hint.get("reason", "")).strip()
                        if reason:
                            loop.state.add_shared_note(f"retrospective: {reason}")
                    seen_carry_titles: set[tuple[str, str]] = set()
                    for item in (prior_retro.get("review_queue") or [])[:3]:
                        status = str(item.get("status", "open")).lower()
                        if status not in {"open", "escalated"}:
                            continue
                        raw_reason = str(item.get("reason", "") or "")
                        if "MagicMock" in raw_reason:
                            continue
                        raw_title = str(item.get("title", "") or "")
                        normalized_title = _normalize_carryover_title(raw_title)
                        if raw_title.lower().startswith("carryover:"):
                            continue
                        dedup_key = (
                            normalized_title,
                            str(item.get("affected_component", "")).strip().lower(),
                        )
                        if dedup_key in seen_carry_titles:
                            continue
                        seen_carry_titles.add(dedup_key)
                        loop.state.record_review_item(
                            f"carry:{item.get('id', 'retro')}",
                            stage="retrospective",
                            status="open",
                            title=f"carryover:{normalized_title or 'review item'}",
                            reason=raw_reason or "Carried from previous scan retrospective.",
                            action_hint=str(item.get("action_hint", ""))
                            or "Resolve this review gap early in the new run.",
                            affected_component=str(item.get("affected_component", "")),
                            source_finding_type=str(item.get("source_finding_type", "")),
                        )
            except Exception:
                logger.exception("Failed to seed scan loop from prior retrospective")

            loop_result: dict[str, Any] = {}
            try:
                loop_result = await loop.run()
            except Exception as exc:
                logger.exception("ScanAgentLoop failed")
                self._emit("error", {"stage": "scan_loop", "error": str(exc)})
                try:
                    await registry.cleanup()
                except Exception:
                    logger.exception("tool registry cleanup failed after scan_loop error")
                try:
                    from vxis.agent.tools.browser_tools import shutdown_browser

                    await shutdown_browser()
                except Exception:
                    pass
                try:
                    from vxis.agent.tools.proxy_runtime import shutdown_proxy_runtime

                    await shutdown_proxy_runtime()
                except Exception:
                    pass
                if ghost_activated_here:
                    try:
                        ghost_layer.deactivate()
                    except Exception:
                        logger.exception("Ghost deactivation failed after scan_loop error")
                _set_finding_event_callback(None)
                # Still attach a score so the CLI doesn't crash
                ctx.vxis_score = _SimpleScore(total=0.0, grade="F")
                return ctx

            try:
                await registry.cleanup()
            except Exception:
                logger.exception("tool registry cleanup failed after scan_loop")

            self._emit(
                "phase_end",
                {
                    "phase": "scan_loop",
                    "iterations": loop_result.get("iterations", 0),
                    "duration_s": time.monotonic() - started,
                },
            )

            # Phase B fix: surface peak_context_bytes from the loop state into ctx.
            # Task 11 reported peak_context_bytes=0 because the v2 shim had no wire-up;
            # now ScanAgentLoop samples it each iteration and exposes it on loop_result.
            peak_bytes_from_loop = int(loop_result.get("peak_context_bytes", 0))
            if peak_bytes_from_loop > getattr(ctx, "peak_context_bytes", 0):
                ctx.peak_context_bytes = peak_bytes_from_loop

            # Phase C belief state: surface verdict counts + confirmed/refuted lists.
            verdict_counts = loop_result.get("verdict_counts", {}) or {}
            ctx.scan_loop_completed = bool(loop_result.get("completed", False))  # type: ignore[attr-defined]
            ctx.verdict_counts = verdict_counts  # type: ignore[attr-defined]
            ctx.confirmed_findings = loop_result.get("confirmed_findings", []) or []  # type: ignore[attr-defined]
            ctx.refuted_findings = loop_result.get("refuted_findings", []) or []  # type: ignore[attr-defined]
            ctx.skills_completed = loop_result.get("skills_completed", []) or []  # type: ignore[attr-defined]
            ctx.vector_candidates = loop_result.get("vector_candidates", []) or []  # type: ignore[attr-defined]
            ctx.attempt_outcomes = loop_result.get("attempt_outcomes", []) or []  # type: ignore[attr-defined]
            ctx.scan_todos = loop_result.get("scan_todos", []) or []  # type: ignore[attr-defined]
            ctx.branches = loop_result.get("branches", []) or []  # type: ignore[attr-defined]
            ctx.shared_notes = loop_result.get("shared_notes", []) or []  # type: ignore[attr-defined]
            ctx.llm_usage = get_llm_usage_stats()  # type: ignore[attr-defined]
            ctx.runtime_profile = {  # type: ignore[attr-defined]
                "launcher_name": runtime.launcher_name,
                "runtime_mode": runtime.runtime_mode,
                "metadata": dict(runtime.metadata),
            }
            # Phase 4: surface sandbox invocations so _compute_vxis_score can
            # credit VC for shell_exec / python_exec usage (sandbox primacy).
            ctx.sandbox_invocations = loop_result.get("sandbox_invocations", []) or []  # type: ignore[attr-defined]
            ctx.final_report_sections = _extract_final_report_sections(  # type: ignore[attr-defined]
                list(getattr(loop.state, "messages", []))
            )
            if verdict_counts:
                print(
                    "VXIS_BELIEF verdicts={} confirmed={} refuted={}".format(
                        verdict_counts,
                        len(ctx.confirmed_findings),  # type: ignore[attr-defined]
                        len(ctx.refuted_findings),  # type: ignore[attr-defined]
                    )
                )

            # 6. Copy findings from the in-memory store into ctx.findings
            finding_dicts = _get_finding_dicts()
            for d in finding_dicts:
                try:
                    f = _build_finding_from_dict(
                        d, scan_id=ctx.scan_id, target=ctx.target, kind=ctx.kind
                    )
                    ctx.findings.append(f)
                except Exception:
                    logger.exception("Failed to convert finding dict: %s", d.get("id", "?"))

            # 7. Copy chains into ctx.attack_chains (stored as list[dict] per ScanContext typing)
            chain_dicts = _get_chain_dicts()
            try:
                ctx.attack_chains = [
                    {"finding_ids": list(c.get("finding_ids", [])), "raw": c} for c in chain_dicts
                ]
            except Exception:
                ctx.attack_chains = []

            # 7.5 Shutdown browser if Eyes was used during the scan
            try:
                from vxis.agent.tools.browser_tools import shutdown_browser

                await shutdown_browser()
            except Exception:
                pass
            try:
                from vxis.agent.tools.proxy_runtime import shutdown_proxy_runtime

                await shutdown_proxy_runtime()
            except Exception:
                pass

            # 8. Deferred actions gate (Phase A: usually empty, but plumbing preserved)
            if self.enable_deferred_approval and getattr(ctx, "deferred_actions", None):
                await self._run_deferred_gate(ctx)

            # 9. Generate the HTML report
            if self._generate_report_enabled:
                try:
                    await self._generate_report(ctx)
                except Exception:
                    logger.exception("Report generation failed — continuing")

            # 10. Compute VXIS score
            score_value, grade = _compute_vxis_score(ctx)
            ctx.vxis_score = _SimpleScore(total=score_value, grade=grade)
            self._emit("score", {"total": score_value, "grade": grade})

            # 10a. Dump full 5-dim breakdown next to the HTML report for benchmark comparison.
            detail = getattr(ctx, "score_detail", None)
            report_path = getattr(self, "_report_output_path", None) or getattr(
                self, "report_output_path", None
            )
            if detail is not None and report_path:
                try:
                    score_json_path = Path(str(report_path)).with_suffix(".score.json")
                    score_json_path.parent.mkdir(parents=True, exist_ok=True)
                    score_json_path.write_text(detail.to_json(), encoding="utf-8")
                    logger.info("VXIS_BENCHMARK score breakdown -> %s", score_json_path)
                except Exception:
                    logger.exception("Failed to dump score breakdown JSON — continuing")

            # 11. Populate phase logs (duration_seconds is a computed @property on ctx)
            try:
                ctx.phase_logs = [
                    {
                        "name": "scan_loop",
                        "status": "done",
                        "duration": time.monotonic() - started,
                    }
                ]
            except Exception:
                pass

            # Print instrumentation counters — Task 11/14 benchmark greps these
            brain_decisions = get_brain_decision_count()
            llm_calls = get_llm_call_count()
            peak_bytes = getattr(ctx, "peak_context_bytes", 0)
            findings_count = len(ctx.findings)
            logger.info(
                "VXIS_BENCHMARK peak_context_bytes=%d llm_call_count=%d brain_decision_count=%d findings_count=%d",
                peak_bytes,
                llm_calls,
                brain_decisions,
                findings_count,
            )
            print(
                f"VXIS_BENCHMARK peak_context_bytes={peak_bytes} "
                f"llm_call_count={llm_calls} brain_decision_count={brain_decisions} "
                f"findings_count={findings_count}"
            )

            # Phase C: MITRE ATT&CK coverage calculation. Builds technique and
            # tactic coverage from the current scan's findings and prints a
            # summary line for operators.
            try:
                from vxis.agent.tools.mitre_data import coverage_report

                mitre = coverage_report(_get_finding_dicts())
                logger.info(
                    "MITRE coverage: %d technique(s), %d tactic(s), %.1f%% of known",
                    len(mitre["techniques_covered"]),
                    len(mitre["tactics_covered"]),
                    mitre["coverage_pct"],
                )
                # Attach to ctx for the report generator
                ctx.mitre_coverage = mitre  # type: ignore[attr-defined]
                if mitre["per_technique"]:
                    print(
                        "MITRE_COVERAGE techniques={} tactics={} pct={}".format(
                            len(mitre["techniques_covered"]),
                            len(mitre["tactics_covered"]),
                            mitre["coverage_pct"],
                        )
                    )
                    for t in mitre["per_technique"][:10]:
                        print(f"  {t['id']} {t['name']} ({t['tactic']}) x{t['finding_count']}")
            except Exception:
                logger.exception("MITRE coverage calculation failed")

            # Phase B: persist scan results to cross-scan memory KB so the next
            # scan of this target can query prior findings via query_scan_memory.
            # Also extract the fingerprint_target result from the loop's message
            # history (if Brain called it) so cross-stack learning works.
            try:
                finding_dicts_raw = _get_finding_dicts()
                extracted_fingerprint: dict[str, Any] | None = None
                for msg in getattr(loop.state, "messages", []):
                    c = msg.get("content") if isinstance(msg, dict) else None
                    if isinstance(c, dict) and c.get("name") == "fingerprint_target":
                        data = (c.get("result") or {}).get("data") or {}
                        if "recommended_playbooks" in data:
                            extracted_fingerprint = {
                                "recommended_playbooks": data.get("recommended_playbooks"),
                                "is_spa": data.get("is_spa"),
                                "root_status": data.get("root_status"),
                                "root_size": data.get("root_size"),
                                "matches": [
                                    {"playbook": m.get("playbook"), "score": m.get("score")}
                                    for m in (data.get("matches") or [])[:5]
                                ],
                            }
                            break  # use first fingerprint in the scan
                _record_scan_memory(
                    target=ctx.target,
                    findings=finding_dicts_raw,
                    fingerprint=extracted_fingerprint,
                    scan_id=ctx.scan_id,
                    confirmed_findings=getattr(ctx, "confirmed_findings", []) or [],
                    refuted_findings=getattr(ctx, "refuted_findings", []) or [],
                    review_history=loop_result.get("review_history", []) or [],
                    branches=loop_result.get("branches", []) or [],
                )
                refreshed_memory = _load_target_memory_profile(ctx.target)
                ctx.target_memory = refreshed_memory  # type: ignore[attr-defined]
                ctx.aggregated_findings = list(refreshed_memory.get("aggregated_findings") or [])  # type: ignore[attr-defined]
            except Exception:
                logger.exception("Failed to record scan memory")

            # Local self-improvement loop: capture a per-scan retrospective with
            # review queue, open branches, verdict pressure, and suggested code
            # areas. This is runtime-local and intentionally separate from the
            # GitHub Actions growth loop.
            try:
                from vxis.growth.scan_retrospective import record_scan_retrospective

                retrospective_path = record_scan_retrospective(
                    scan_id=ctx.scan_id,
                    target=ctx.target,
                    findings=_get_finding_dicts(),
                    loop_result=loop_result,
                    messages=list(getattr(loop.state, "messages", [])),
                    attack_chains=list(getattr(ctx, "attack_chains", []) or []),
                    llm_usage=dict(getattr(ctx, "llm_usage", {}) or {}),
                    control_plane=dict(getattr(loop, "_latest_control_plane", {}) or {}),
                )
                ctx.scan_retrospective_path = str(retrospective_path)  # type: ignore[attr-defined]
            except Exception:
                logger.exception("Failed to record scan retrospective")

            if ghost_activated_here:
                try:
                    ghost_layer.deactivate()
                except Exception:
                    logger.exception("Ghost deactivation failed after scan")
            _set_finding_event_callback(None)
            return ctx
        finally:
            if _scope_owned:
                clear_active_scope()

    async def _run_deferred_gate(self, ctx: ScanContext) -> None:
        """Invoke the approval callback on ctx.deferred_actions. Phase A stub."""
        if not self._approval_callback or not getattr(ctx, "deferred_actions", None):
            return
        try:
            approvals = await self._approval_callback(ctx.deferred_actions)
            for action, approved in zip(ctx.deferred_actions, approvals):
                action.approved = approved
        except Exception:
            logger.exception("deferred approval callback failed")

    async def _generate_report(self, ctx: ScanContext) -> None:
        """Render the HTML report via ReportGenerator. Honor --output flag."""
        try:
            from vxis.report.generator import _DEFAULT_METHODOLOGY, ReportData, ReportGenerator
        except Exception as e:
            logger.warning("Report modules unavailable: %s", e)
            return

        # Phase C: render report even when findings=0 if we have belief state
        # (verdict counts, refutations, MITRE) — the verification summary is
        # itself valuable evidence of what was tried and ruled out.
        has_belief = bool(getattr(ctx, "verdict_counts", {})) or bool(
            getattr(ctx, "refuted_findings", [])
        )
        if not ctx.findings and not has_belief:
            logger.info("No findings and no belief state — skipping report generation")
            return
        if not ctx.findings:
            logger.info("No findings but belief state present — rendering verification-only report")

        if self._report_output_path:
            output_path = Path(self._report_output_path)
        else:
            from urllib.parse import urlparse

            safe = urlparse(ctx.target.replace("ghost://", "")).netloc.replace(
                ".", "_"
            ) or ctx.target.replace("/", "_")
            output_path = Path(f"reports/VXIS_Pipeline_{safe}.html")

        output_path.parent.mkdir(parents=True, exist_ok=True)

        # ReportData.attack_chains expects list[list[str]] per CLAUDE.md convention
        chain_id_lists = []
        try:
            for c in ctx.attack_chains:
                if isinstance(c, dict):
                    ids = c.get("finding_ids") or []
                    if ids:
                        chain_id_lists.append(list(ids))
                elif isinstance(c, list):
                    chain_id_lists.append(list(c))
        except Exception:
            chain_id_lists = []

        data = ReportData(
            scan_id=ctx.scan_id,
            client_name="VXIS Phase A Benchmark",
            target=ctx.target,
            scan_date=time.strftime("%Y-%m-%d"),
            findings=ctx.findings,
            company_name="VXIS Security",
            author="VXIS Autonomous Brain",
            executive_summary=(
                (getattr(ctx, "final_report_sections", {}) or {}).get("executive_summary")
                or f"Phase A scan completed: {len(ctx.findings)} finding(s)|||Phase A 스캔 완료: {len(ctx.findings)}건 발견"
            ),
            methodology=(
                (getattr(ctx, "final_report_sections", {}) or {}).get("methodology")
                or _DEFAULT_METHODOLOGY
            ),
            technical_analysis=(
                (getattr(ctx, "final_report_sections", {}) or {}).get("technical_analysis") or ""
            ),
            recommendations=(
                (getattr(ctx, "final_report_sections", {}) or {}).get("recommendations") or ""
            ),
            attack_chains=chain_id_lists,
            aggregated_findings=list(getattr(ctx, "aggregated_findings", []) or []),
            verdict_counts=getattr(ctx, "verdict_counts", {}) or {},
            confirmed_findings=getattr(ctx, "confirmed_findings", []) or [],
            refuted_findings=getattr(ctx, "refuted_findings", []) or [],
            mitre_coverage=getattr(ctx, "mitre_coverage", {}) or {},
        )
        gen = ReportGenerator()
        gen.generate_html_file(data, output_path)
        logger.info("Report written to: %s", output_path)
