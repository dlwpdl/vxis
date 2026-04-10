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
    10. Compute VXIS score via 5-dimension ScoringEngine (finding_type→vector mapping)
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


# Maps finding_type strings (set by Brain's report_finding tool) to their
# canonical vector IDs in the scoring registry. Used by _compute_vxis_score
# to populate ScoreTracker without requiring findings to carry an explicit
# vector_id field.
_FINDING_TYPE_TO_VECTOR: dict[str, str] = {
    # SQL Injection
    "sql_injection": "WEB-SQLI-001",
    "sqli": "WEB-SQLI-001",
    "blind_sql_injection": "WEB-SQLI-002",
    "blind_sqli": "WEB-SQLI-002",
    "error_based_sql": "WEB-SQLI-003",
    "union_based_sql": "WEB-SQLI-004",
    "time_based_blind_sqli": "WEB-SQLI-005",
    "second_order_sql": "WEB-SQLI-006",
    "second_order_sqli": "WEB-SQLI-006",
    # NoSQL Injection
    "nosql_injection": "WEB-NOSQL-001",
    "nosql": "WEB-NOSQL-001",
    "nosql_operator_injection": "WEB-NOSQL-002",
    # Command Injection
    "command_injection": "WEB-CMDI-001",
    "cmdi": "WEB-CMDI-001",
    "os_command_injection": "WEB-CMDI-001",
    "blind_command_injection": "WEB-CMDI-002",
    # LDAP / XPath
    "ldap_injection": "WEB-LDAP-001",
    "ldap": "WEB-LDAP-001",
    "xpath_injection": "WEB-XPATH-001",
    "xpath": "WEB-XPATH-001",
    # SSTI
    "ssti": "WEB-SSTI-001",
    "server_side_template_injection": "WEB-SSTI-001",
    "template_injection": "WEB-SSTI-001",
    # XSS
    "xss": "WEB-XSS-001",
    "xss_reflected": "WEB-XSS-001",
    "reflected_xss": "WEB-XSS-001",
    "xss_stored": "WEB-XSS-002",
    "stored_xss": "WEB-XSS-002",
    "persistent_xss": "WEB-XSS-002",
    "xss_dom": "WEB-XSS-003",
    "dom_xss": "WEB-XSS-003",
    "dom_based_xss": "WEB-XSS-003",
    "mutation_xss": "WEB-XSS-004",
    "mxss": "WEB-XSS-004",
    # SSRF
    "ssrf": "WEB-SSRF-001",
    "server_side_request_forgery": "WEB-SSRF-001",
    "blind_ssrf": "WEB-SSRF-002",
    "ssrf_via_redirect": "WEB-SSRF-003",
    # Authentication
    "weak_credentials": "WEB-AUTH-001",
    "weak_password": "WEB-AUTH-001",
    "brute_force": "WEB-AUTH-002",
    "authentication_bypass": "WEB-AUTH-003",
    "auth_bypass": "WEB-AUTH-003",
    "broken_authentication": "WEB-AUTH-003",
    "broken_auth": "WEB-AUTH-003",
    "session_fixation": "WEB-AUTH-004",
    "cookie_theft": "WEB-AUTH-005",
    "session_hijacking": "WEB-AUTH-005",
    "jwt_vulnerability": "WEB-AUTH-006",
    "jwt_vulnerabilities": "WEB-AUTH-006",
    "jwt": "WEB-AUTH-006",
    "jwt_misconfiguration": "WEB-AUTH-006",
    "oauth_misconfiguration": "WEB-AUTH-007",
    "oauth": "WEB-AUTH-007",
    "saml_bypass": "WEB-AUTH-008",
    "saml": "WEB-AUTH-008",
    # Access Control
    "idor": "WEB-AC-001",
    "insecure_direct_object_reference": "WEB-AC-001",
    "broken_object_level_authorization": "WEB-AC-001",
    "privilege_escalation": "WEB-AC-002",
    "vertical_privilege_escalation": "WEB-AC-002",
    "path_traversal": "WEB-AC-003",
    "directory_traversal": "WEB-AC-003",
    "forced_browsing": "WEB-AC-004",
    "broken_access_control": "WEB-AC-001",
    "access_control": "WEB-AC-001",
    "broken_function_level_authorization": "WEB-AC-005",
    # Misconfiguration
    "security_headers_missing": "WEB-MISCONF-001",
    "missing_security_headers": "WEB-MISCONF-001",
    "cors_misconfiguration": "WEB-MISCONF-002",
    "cors": "WEB-MISCONF-002",
    "open_redirect": "WEB-MISCONF-003",
    "ssl_tls_misconfiguration": "WEB-MISCONF-004",
    "tls_misconfiguration": "WEB-MISCONF-004",
    "ssl_misconfiguration": "WEB-MISCONF-004",
    "default_credentials": "WEB-MISCONF-005",
    "debug_mode": "WEB-MISCONF-006",
    "debug_mode_enabled": "WEB-MISCONF-006",
    "misconfiguration": "WEB-MISCONF-001",
    # Cryptographic Issues
    "weak_hash": "WEB-CRYPTO-001",
    "weak_hashing": "WEB-CRYPTO-001",
    "weak_encryption": "WEB-CRYPTO-002",
    "hardcoded_secrets": "WEB-CRYPTO-003",
    "hardcoded_secret": "WEB-CRYPTO-003",
    "weak_random": "WEB-CRYPTO-004",
    "insufficient_randomness": "WEB-CRYPTO-004",
    # Other injections
    "xxe": "WEB-XXE-001",
    "xml_external_entity": "WEB-XXE-001",
    "deserialization": "WEB-DESER-001",
    "insecure_deserialization": "WEB-DESER-001",
    "file_upload": "WEB-UPLOAD-001",
    "unrestricted_file_upload": "WEB-UPLOAD-001",
    "race_condition": "WEB-RACE-001",
    "csrf": "WEB-CSRF-001",
    "cross_site_request_forgery": "WEB-CSRF-001",
    "websocket": "WEB-WSS-001",
    "websocket_security": "WEB-WSS-001",
    # API Security
    "api_security": "WEB-API-001",
    "api_key_exposure": "WEB-API-003",
    "api_rate_limiting": "WEB-API-004",
    "graphql_injection": "WEB-API-007",
    "graphql": "WEB-API-007",
    # Supply Chain
    "supply_chain": "WEB-SUPPLY-001",
    "dependency_confusion": "WEB-SUPPLY-001",
    # Infrastructure / Info Disclosure
    "information_disclosure": "WEB-INFRA-001",
    "sensitive_data_exposure": "WEB-INFRA-001",
    "directory_listing": "WEB-INFRA-002",
    "backup_files": "WEB-INFRA-003",
    # Business Logic
    "business_logic": "WEB-BIZ-001",
    "price_manipulation": "WEB-BIZ-001",
    "workflow_bypass": "WEB-BIZ-002",
    "rate_limiting_bypass": "WEB-BIZ-003",
    "quantity_manipulation": "WEB-BIZ-004",
    "coupon_abuse": "WEB-BIZ-005",
}


def _compute_vxis_score(ctx: Any) -> tuple[float, str]:
    """Compute the 5-dimension VXIS score from the scan context.

    Populates a ScoreTracker by mapping each finding's finding_type to a
    canonical vector ID via _FINDING_TYPE_TO_VECTOR, then delegates to the
    real ScoringEngine for a deterministic 5-dimension score.  Falls back to
    a severity-weighted heuristic if the scoring module is unavailable.

    Returns (total_score, grade).
    """
    try:
        from vxis.scoring.engine import ScoringEngine
        from vxis.scoring.tracker import ScoreTracker

        target_type = getattr(ctx, "target_type", "web") or "web"
        tracker = ScoreTracker(target_type=target_type)

        findings_raw = getattr(ctx, "findings", []) or []
        for f in findings_raw:
            fid = str(getattr(f, "id", "") or "")
            ftype = str(getattr(f, "finding_type", "") or "").lower().strip()
            vid = _FINDING_TYPE_TO_VECTOR.get(ftype)
            if vid:
                try:
                    tracker.record_vector_attempt(vid)
                    # Derive exploitation level from severity (default 1)
                    sev = (
                        f.severity.value
                        if hasattr(f.severity, "value")
                        else str(f.severity)
                    ).lower()
                    level = {"critical": 3, "high": 2, "medium": 1, "low": 1}.get(sev, 1)
                    tracker.record_finding(fid, vid, level)
                except Exception:
                    logger.debug("Failed to record vector for finding %s", fid)

        # Record attack chains so chain_intelligence dimension is populated
        chains = getattr(ctx, "attack_chains", []) or []
        for chain_dict in chains:
            raw = chain_dict.get("raw", chain_dict) if isinstance(chain_dict, dict) else {}
            fids = list(raw.get("finding_ids", []))
            if len(fids) >= 2:
                try:
                    from vxis.scoring.tracker import AttackChain, ChainStep

                    steps = []
                    for i, finding_id in enumerate(fids):
                        ftype = ""
                        for f in findings_raw:
                            if str(getattr(f, "id", "")) == finding_id:
                                ftype = str(getattr(f, "finding_type", "") or "").lower()
                                break
                        vid = _FINDING_TYPE_TO_VECTOR.get(ftype, "WEB-AC-001")
                        steps.append(
                            ChainStep(
                                step_index=i,
                                vector_id=vid,
                                finding_id=finding_id,
                                level=1,
                                description=f"Chain step {i}|||체인 단계 {i}",
                            )
                        )
                    chain_obj = AttackChain(steps=steps)
                    tracker.record_chain(chain_obj)
                except Exception:
                    logger.debug("Failed to record attack chain")

        engine = ScoringEngine(target_type=target_type)
        score_obj = engine.calculate(tracker, findings_raw, scan_id=getattr(ctx, "scan_id", ""))
        return score_obj.total, score_obj.grade

    except Exception:
        logger.debug("ScoringEngine unavailable, falling back to heuristic", exc_info=True)

    # Fallback: severity-weighted heuristic
    sev_weights = {
        "critical": 200,
        "high": 100,
        "medium": 50,
        "low": 20,
        "info": 5,
        "informational": 5,
    }
    score = 0.0
    for f in getattr(ctx, "findings", []) or []:
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

        # 2. Reset per-scan state (findings + brain counters + playbook dedup)
        _reset_finding_store()
        reset_brain_decision_count()
        reset_llm_call_count()
        try:
            from vxis.agent.tools.playbook_tools import _loaded_playbooks
            _loaded_playbooks.clear()
        except Exception:
            pass

        # 3. Build the tool registry
        registry = build_default_registry(brain=self.brain)

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

        # Phase C belief state: surface verdict counts + confirmed/refuted lists.
        verdict_counts = loop_result.get("verdict_counts", {}) or {}
        ctx.verdict_counts = verdict_counts  # type: ignore[attr-defined]
        ctx.confirmed_findings = loop_result.get("confirmed_findings", []) or []  # type: ignore[attr-defined]
        ctx.refuted_findings = loop_result.get("refuted_findings", []) or []  # type: ignore[attr-defined]
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

        # 7. Copy chains into ctx.attack_chains (stored as list[dict] per ScanContext typing)
        chain_dicts = _get_chain_dicts()
        try:
            ctx.attack_chains = [
                {"finding_ids": list(c.get("finding_ids", [])), "raw": c}
                for c in chain_dicts
            ]
        except Exception:
            ctx.attack_chains = []

        # 7.5 Shutdown browser if Eyes was used during the scan
        try:
            from vxis.agent.tools.browser_tools import shutdown_browser
            await shutdown_browser()
        except Exception:
            pass

        # 8. Deferred actions gate (Phase A: usually empty, but plumbing preserved)
        if self.enable_deferred_approval and getattr(ctx, "deferred_actions", None):
            await self._run_deferred_gate(ctx)

        # 9. Generate the HTML report
        try:
            await self._generate_report(ctx)
        except Exception:
            logger.exception("Report generation failed — continuing")

        # 10. Compute VXIS score
        score_value, grade = _compute_vxis_score(ctx)
        ctx.vxis_score = _SimpleScore(total=score_value, grade=grade)

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
            mitre = coverage_report(finding_dicts_raw if False else _get_finding_dicts())
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

        # Phase C: render report even when findings=0 if we have belief state
        # (verdict counts, refutations, MITRE) — the verification summary is
        # itself valuable evidence of what was tried and ruled out.
        has_belief = bool(getattr(ctx, "verdict_counts", {})) or bool(getattr(ctx, "refuted_findings", []))
        if not ctx.findings and not has_belief:
            logger.info("No findings and no belief state — skipping report generation")
            return
        if not ctx.findings:
            logger.info("No findings but belief state present — rendering verification-only report")

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
            verdict_counts=getattr(ctx, "verdict_counts", {}) or {},
            confirmed_findings=getattr(ctx, "confirmed_findings", []) or [],
            refuted_findings=getattr(ctx, "refuted_findings", []) or [],
            mitre_coverage=getattr(ctx, "mitre_coverage", {}) or {},
        )
        gen = ReportGenerator()
        gen.generate_html_file(data, output_path)
        logger.info("Report written to: %s", output_path)
