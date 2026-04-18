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


def _compute_vxis_score(ctx: Any) -> tuple[float, str]:
    """Compute VXIS score using the full 5-dimension ScoringEngine.

    Populates a ScoreTracker from scan findings, then runs ScoringEngine.
    Falls back to simple severity sum if ScoringEngine fails.
    """
    try:
        from vxis.scoring.engine import ScoringEngine
        from vxis.scoring.tracker import ScoreTracker

        tracker = ScoreTracker(target_type="web")

        # Map finding types to registered vector IDs (must match vectors.py registry).
        # Each key is a finding_type string emitted by the Brain/ScanAgentLoop.
        _type_to_vector = {
            "sql_injection": "WEB-SQLI-001",
            "xss_reflected": "WEB-XSS-001", "xss_stored": "WEB-XSS-002",
            "xss": "WEB-XSS-001",
            "ssrf": "WEB-SSRF-001",
            "idor": "WEB-AC-001",                     # WEB-IDOR-001 is not registered
            "broken_access_control": "WEB-AC-002",    # WEB-BAC-001 is not registered
            "information_disclosure": "WEB-MISCONF-003",  # WEB-INFO-001 is not registered
            "path_traversal": "WEB-AC-004",           # WEB-TRAV-001 is not registered
            "auth_bypass": "WEB-AUTH-001", "weak_auth": "WEB-AUTH-001",
            "csrf": "WEB-CSRF-001",
            "xxe": "WEB-XXE-001",
            "rce": "WEB-CMDI-001",                    # WEB-RCE-001 is not registered
            "command_injection": "WEB-CMDI-001",
            "error_oracle": "WEB-MISCONF-003",        # WEB-INFO-002 is not registered
            "misconfiguration": "WEB-MISCONF-001",    # WEB-MISC-001 is not registered
            "open_redirect": "WEB-MISCONF-006",       # WEB-REDIR-001 is not registered
            "jwt_confusion": "WEB-AUTH-003",          # WEB-JWT-001 is not registered
            "weak_crypto": "WEB-CRYPTO-001",
            "business_logic": "WEB-BIZ-001",          # WEB-LOGIC-001 is not registered
        }

        # Severity → exploitation level
        _sev_to_level = {
            "critical": 3,  # exploit successful + post-exploit
            "high": 2,      # exploit successful
            "medium": 1,    # vulnerability confirmed
            "low": 0,       # recon only
            "informational": 0,
        }

        for f in ctx.findings:
            ftype = f.finding_type if hasattr(f, "finding_type") else str(getattr(f, "finding_type", ""))
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
                            description_en=f"Chain step {j+1}",
                            description_ko=f"체인 단계 {j+1}",
                        )
                tracker.attack_chains.append(ac)

        # Phase completion — single scan_loop phase
        from vxis.scoring.tracker import PhaseResult, PhaseStatus
        tracker.phase_results["scan_loop"] = PhaseResult(
            phase_name="scan_loop",
            status=PhaseStatus.completed,
            findings_count=len(ctx.findings),
        )

        engine = ScoringEngine("web")
        vxis_score = engine.calculate(tracker, ctx.findings, scan_id=ctx.scan_id)

        # Print detailed score
        print(vxis_score.summary_text())

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
        grade = "A" if score >= 700 else "B" if score >= 400 else "C" if score >= 200 else "D" if score > 0 else "F"
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
