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
    7. Feed findings into ctx.score_tracker (vector_id + exploitation level)
    8. Copy chains from finding_tools._get_chains() into ctx.attack_chains
    9. If deferred actions accumulated, run _execute_deferred_actions
    10. Generate the HTML report via ReportGenerator
    11. Compute VXIS score via ScoringEngine (fallback: severity heuristic)
    12. Return ctx

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
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

from vxis.agent.brain import (
    get_brain_decision_count,
    get_llm_call_count,
    reset_brain_decision_count,
    reset_llm_call_count,
)
from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tools import build_default_registry
from vxis.agent.tools.finding_tools import _get_chains as _get_chain_dicts
from vxis.agent.tools.finding_tools import _get_findings as _get_finding_dicts
from vxis.agent.tools.finding_tools import _reset_for_tests as _reset_finding_store
from vxis.agent.tools.memory_tools import record_scan_result as _record_scan_memory
from vxis.pipeline.context import ScanContext

logger = logging.getLogger(__name__)

# ── Vector ID inference: finding_type → VXIS vector ID ────────────────────────
# Used when the Brain doesn't supply an explicit vector_id.
# Keys are snake_case finding_type values commonly emitted by the Brain.

_WEB_TYPE_VECTOR: dict[str, str] = {
    "sql_injection": "WEB-SQLI-001",
    "sql_injection_union": "WEB-SQLI-001",
    "sql_injection_boolean_blind": "WEB-SQLI-002",
    "sql_injection_time_blind": "WEB-SQLI-003",
    "sql_injection_error_based": "WEB-SQLI-004",
    "sql_injection_second_order": "WEB-SQLI-006",
    "nosql_injection": "WEB-NOSQL-001",
    "command_injection": "WEB-CMDI-001",
    "os_command_injection": "WEB-CMDI-001",
    "rce": "WEB-CMDI-001",
    "remote_code_execution": "WEB-CMDI-001",
    "ldap_injection": "WEB-LDAP-001",
    "xpath_injection": "WEB-XPATH-001",
    "ssti": "WEB-SSTI-001",
    "server_side_template_injection": "WEB-SSTI-001",
    "xss": "WEB-XSS-001",
    "xss_reflected": "WEB-XSS-001",
    "cross_site_scripting": "WEB-XSS-001",
    "xss_stored": "WEB-XSS-002",
    "xss_dom": "WEB-XSS-003",
    "ssrf": "WEB-SSRF-001",
    "server_side_request_forgery": "WEB-SSRF-001",
    "auth_bypass": "WEB-AUTH-001",
    "authentication_bypass": "WEB-AUTH-001",
    "broken_authentication": "WEB-AUTH-001",
    "jwt_vulnerability": "WEB-AUTH-003",
    "jwt_weak_secret": "WEB-AUTH-003",
    "weak_password": "WEB-AUTH-005",
    "default_credentials": "WEB-AUTH-006",
    "idor": "WEB-AC-001",
    "insecure_direct_object_reference": "WEB-AC-001",
    "broken_access_control": "WEB-AC-001",
    "privilege_escalation": "WEB-AC-004",
    "misconfiguration": "WEB-MISCONF-001",
    "security_misconfiguration": "WEB-MISCONF-001",
    "directory_listing": "WEB-MISCONF-004",
    "exposed_debug_endpoint": "WEB-MISCONF-005",
    "weak_tls": "WEB-CRYPTO-001",
    "weak_cipher": "WEB-CRYPTO-001",
    "xxe": "WEB-XXE-001",
    "xml_external_entity": "WEB-XXE-001",
    "deserialization": "WEB-DESER-001",
    "insecure_deserialization": "WEB-DESER-001",
    "file_upload": "WEB-UPLOAD-001",
    "unrestricted_file_upload": "WEB-UPLOAD-001",
    "race_condition": "WEB-RACE-001",
    "csrf": "WEB-CSRF-001",
    "cross_site_request_forgery": "WEB-CSRF-001",
    "websocket_vulnerability": "WEB-WSS-001",
    "api_vulnerability": "WEB-API-001",
    "api_broken_auth": "WEB-API-003",
    "graphql_injection": "WEB-API-007",
    "business_logic": "WEB-BIZ-001",
    "business_logic_flaw": "WEB-BIZ-001",
    "supply_chain": "WEB-SUPPLY-001",
}

_GAME_TYPE_VECTOR: dict[str, str] = {
    "server_validation_bypass": "GAME-SV-001",
    "speed_hack": "GAME-SV-002",
    "memory_tampering": "GAME-CLIENT-001",
    "economy_manipulation": "GAME-ECON-001",
    "currency_duplication": "GAME-ECON-002",
    "protocol_vulnerability": "GAME-PROTO-001",
    "anti_cheat_bypass": "GAME-DRM-001",
    "drm_bypass": "GAME-DRM-001",
    "business_logic": "GAME-LOGIC-001",
}

_MOBILE_TYPE_VECTOR: dict[str, str] = {
    "hardcoded_secrets": "MOB-STATIC-001",
    "hardcoded_credentials": "MOB-STATIC-001",
    "insecure_data_storage": "MOB-STORE-001",
    "cleartext_storage": "MOB-STORE-001",
    "ssl_pinning_bypass": "MOB-NET-001",
    "insecure_communication": "MOB-NET-001",
    "certificate_pinning_bypass": "MOB-NET-002",
    "api_vulnerability": "MOB-API-001",
    "api_broken_auth": "MOB-API-002",
    "dynamic_analysis": "MOB-DYN-001",
    "runtime_manipulation": "MOB-DYN-001",
    "binary_vulnerability": "MOB-BINARY-001",
    "reverse_engineering": "MOB-BINARY-001",
    "privacy_violation": "MOB-PRIV-001",
    "excessive_permissions": "MOB-PRIV-002",
    "platform_vulnerability": "MOB-PLAT-001",
    "intent_injection": "MOB-PLAT-002",
}

_TYPE_VECTOR_BY_TARGET: dict[str, dict[str, str]] = {
    "web": _WEB_TYPE_VECTOR,
    "game": _GAME_TYPE_VECTOR,
    "mobile": _MOBILE_TYPE_VECTOR,
}

# Severity → exploitation level (0-4) for ScoreTracker.record_finding()
_SEVERITY_TO_LEVEL: dict[str, int] = {
    "informational": 0,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _infer_vector_id(finding_type: str, target_type: str) -> str:
    """Infer the VXIS attack vector ID from finding_type + target_type.

    Returns an empty string if no mapping is found.
    벡터 ID를 finding_type에서 추론한다. 매핑이 없으면 빈 문자열 반환.
    """
    mapping = _TYPE_VECTOR_BY_TARGET.get(target_type, {})
    return mapping.get(finding_type.lower().strip(), "")


def _populate_score_tracker(
    finding_dicts: list[dict[str, Any]],
    ctx: Any,
) -> None:
    """Feed scan findings into ctx.score_tracker for vector coverage scoring.

    Resolves vector_id from the finding dict (explicit > inferred from type).
    Records each vector attempt + finding at the appropriate exploitation level.

    스캔 결과를 score_tracker에 기록하여 벡터 커버리지 점수를 활성화한다.
    """
    tracker = getattr(ctx, "score_tracker", None)
    if tracker is None:
        return
    target_type = getattr(ctx, "target_type", "web")

    for d in finding_dicts:
        finding_id = str(d.get("id", ""))
        finding_type = str(d.get("finding_type", ""))
        severity = str(d.get("severity", "medium")).lower()

        # Resolve vector_id: explicit field takes priority, then infer from type
        vector_id = str(d.get("vector_id", "")).strip()
        if not vector_id:
            vector_id = _infer_vector_id(finding_type, target_type)

        if not vector_id:
            logger.debug(
                "[SCORE] No vector_id for finding %s (type=%s) — skipping tracker",
                finding_id, finding_type,
            )
            continue

        level = _SEVERITY_TO_LEVEL.get(severity, 2)

        try:
            tracker.record_vector_attempt(vector_id)
            if finding_id:
                tracker.record_finding(finding_id, vector_id, level)
        except Exception:
            logger.debug(
                "[SCORE] tracker record failed for %s / %s", finding_id, vector_id,
                exc_info=True,
            )


def _finding_dict_to_finding_object(d: dict[str, Any], scan_id: str, target: str) -> Any:
    """Convert a finding_tools dict into a Finding object for the report.

    Uses minimal valid field set; richer structure (MITRE, bilingual PoC) is
    filled with safe defaults because Phase A's ScanAgentLoop doesn't yet
    emit them. Phase B will enrich.
    """
    from vxis.evidence.schema import Severity
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
    remediation_body = str(d.get("remediation", ""))

    bilingual_title = f"{title}|||{title}"
    bilingual_desc = f"{desc_body}|||{desc_body}"
    bilingual_remediation = (
        f"{remediation_body}|||{remediation_body}" if remediation_body else "TBD|||TBD"
    )

    evidence_text = str(d.get("evidence", "")) or "No evidence captured."
    evidence_list = [
        Evidence(
            evidence_type="log",
            title="Brain-reported evidence",
            content=evidence_text,
        )
    ]

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
        severity=severity,
        finding_type=str(d.get("finding_type", "generic")),
        source_plugin="scan_agent_loop",
        affected_component=str(d.get("affected_component", "")),
        cvss=cvss,
        cwe_ids=cwe_ids,
        evidence=evidence_list,
        remediation=bilingual_remediation,
        references=[],
    )


def _compute_vxis_score(ctx: Any) -> tuple[float, str]:
    """Compute a VXIS score. Returns (score, grade).

    Tries the full ScoringEngine first (uses ctx.score_tracker data for
    5-dimensional scoring). Falls back to a severity-weighted heuristic when
    the tracker has no vector data (e.g. test stubs).

    ScoringEngine를 우선 시도하고, 벡터 데이터가 없을 때 heuristic으로 폴백한다.
    """
    tracker = getattr(ctx, "score_tracker", None)
    target_type = getattr(ctx, "target_type", "web")
    scan_id = getattr(ctx, "scan_id", "")

    # Attempt full ScoringEngine when the tracker has vector data
    if tracker is not None and (tracker.vectors_attempted or tracker.vectors_found):
        try:
            from vxis.scoring.engine import ScoringEngine

            engine = ScoringEngine(target_type=target_type)
            vxis_score = engine.calculate(tracker, ctx.findings, scan_id=scan_id)
            return vxis_score.total, vxis_score.grade
        except Exception:
            logger.debug("[SCORE] ScoringEngine failed — falling back to heuristic", exc_info=True)

    # Severity-weighted heuristic fallback
    sev_weights = {
        "critical": 200,
        "high": 100,
        "medium": 50,
        "low": 20,
        "info": 5,
        "informational": 5,
    }
    score = 0.0
    for f in ctx.findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        score += sev_weights.get(sev, 5)
    score = min(1000.0, score)
    if score >= 700:
        grade = "A"
    elif score >= 400:
        grade = "B"
    elif score >= 200:
        grade = "C"
    elif score > 0:
        grade = "D"
    else:
        grade = "F"
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
    ) -> None:
        self.brain = brain
        self.config = config
        self.enable_deferred_approval = enable_deferred_approval
        self._approval_callback = approval_callback
        self._event_callback = event_callback
        self._injection_approval_callback = injection_approval_callback
        self._auto_approve_injection = auto_approve_injection
        self._report_output_path = report_output_path

    def _emit(self, event_type: str, data: dict) -> None:
        if self._event_callback:
            try:
                self._event_callback(event_type, data)
            except Exception:
                logger.exception("event_callback raised — ignoring")

    async def run(
        self,
        target: str,
        app_context_en: str = "",
        app_context_ko: str = "",
        resume_from: str | None = None,  # Phase A: ignored, kept for signature compat
    ) -> ScanContext:
        """Run a Strix-parity single-loop scan against the target."""
        started = time.monotonic()

        # 1. Build context
        ctx = ScanContext(
            target=target,
            app_context_en=app_context_en,
            app_context_ko=app_context_ko,
            scan_id=f"VXIS-{time.strftime('%Y%m%d-%H%M%S')}",
        )

        # Ghost activation — preserve behavior from legacy pipeline
        try:
            from vxis.ghost.trigger import parse_ghost_trigger

            _activated, target = parse_ghost_trigger(target, self.config)
            ctx.target = target
        except Exception:
            pass  # Ghost optional; missing = no-op

        # 2. Reset per-scan state (findings + brain counters)
        _reset_finding_store()
        reset_brain_decision_count()
        reset_llm_call_count()

        # 3. Build the tool registry
        registry = build_default_registry()

        # 4. Emit a synthetic phase_start so the CLI Rich Live display has content
        self._emit("phase_start", {"phase": "scan_loop", "name": "ScanAgentLoop"})

        # 5. Create + run the ScanAgentLoop
        max_iters = 50  # Phase A cap; Phase B will tune
        loop = ScanAgentLoop(
            target=target,
            registry=registry,
            max_iters=max_iters,
            brain=self.brain,
        )

        loop_result: dict[str, Any] = {}
        try:
            loop_result = await loop.run()
        except Exception as exc:
            logger.exception("ScanAgentLoop failed")
            self._emit("error", {"stage": "scan_loop", "error": str(exc)})
            # Still attach a score so the CLI doesn't crash
            ctx.vxis_score = _SimpleScore(total=0.0, grade="F")
            return ctx

        self._emit(
            "phase_end",
            {"phase": "scan_loop", "iterations": loop_result.get("iterations", 0)},
        )

        # Phase B fix: surface peak_context_bytes from the loop state into ctx.
        # Task 11 reported peak_context_bytes=0 because the v2 shim had no wire-up;
        # now ScanAgentLoop samples it each iteration and exposes it on loop_result.
        peak_bytes_from_loop = int(loop_result.get("peak_context_bytes", 0))
        if peak_bytes_from_loop > getattr(ctx, "peak_context_bytes", 0):
            ctx.peak_context_bytes = peak_bytes_from_loop

        # 6. Copy findings from the in-memory store into ctx.findings
        finding_dicts = _get_finding_dicts()
        for d in finding_dicts:
            try:
                f = _finding_dict_to_finding_object(
                    d, scan_id=ctx.scan_id, target=ctx.target
                )
                ctx.findings.append(f)
                self._emit(
                    "hit",
                    {
                        "severity": d.get("severity", "medium"),
                        "title": d.get("title", ""),
                    },
                )
            except Exception:
                logger.exception("Failed to convert finding dict: %s", d.get("id", "?"))

        # 7. Feed findings into ctx.score_tracker for 5-dimensional VXIS scoring.
        # Must run after findings are collected so vector_ids are available.
        # score_tracker에 findings를 기록하여 벡터 커버리지 점수를 활성화한다.
        _populate_score_tracker(finding_dicts, ctx)

        # 8. Copy chains into ctx.attack_chains (stored as list[dict] per ScanContext typing)
        chain_dicts = _get_chain_dicts()
        try:
            ctx.attack_chains = [
                {"finding_ids": list(c.get("finding_ids", [])), "raw": c}
                for c in chain_dicts
            ]
        except Exception:
            ctx.attack_chains = []

        # 9. Deferred actions gate (Phase A: usually empty, but plumbing preserved)
        if self.enable_deferred_approval and getattr(ctx, "deferred_actions", None):
            await self._run_deferred_gate(ctx)

        # 10. Generate the HTML report
        try:
            await self._generate_report(ctx)
        except Exception:
            logger.exception("Report generation failed — continuing")

        # 11. Compute VXIS score (uses ScoringEngine when tracker has vector data)
        score_value, grade = _compute_vxis_score(ctx)
        ctx.vxis_score = _SimpleScore(total=score_value, grade=grade)

        # 12. Populate phase logs (duration_seconds is a computed @property on ctx)
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
            )
        except Exception:
            logger.exception("Failed to record scan memory")

        return ctx

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
            from vxis.report.generator import ReportData, ReportGenerator
        except Exception as e:
            logger.warning("Report modules unavailable: %s", e)
            return

        if not ctx.findings:
            logger.info("No findings — skipping report generation")
            return

        if self._report_output_path:
            output_path = Path(self._report_output_path)
        else:
            from urllib.parse import urlparse

            safe = (
                urlparse(ctx.target.replace("ghost://", "")).netloc.replace(".", "_")
                or ctx.target.replace("/", "_")
            )
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
                f"Phase A scan completed: {len(ctx.findings)} finding(s)"
                f"|||Phase A 스캔 완료: {len(ctx.findings)}건 발견"
            ),
            attack_chains=chain_id_lists,
        )
        gen = ReportGenerator()
        gen.generate_html_file(data, output_path)
        logger.info("Report written to: %s", output_path)
