"""Multi-target scan orchestrator.

Runs each non-skipped target from a ScanManifest sequentially, then
optionally runs Phase-G cross-target synthesis, and emits a single HTML report.

Design decisions:
  - Sequential execution to avoid races on shared Brain/LLM quota.
  - Each target gets a ScanPipeline with an independent Brain instance.
  - scan_id prefix is shared; per-target suffix is <base>-<target.name>.
  - CODE targets whose surface raises NotImplementedError are gracefully
    skipped with a WARN (no abort).
  - Phase-G (CrossProtocolSynthesizer) is called only when correlation=True
    and at least one target produced findings.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import date
from pathlib import Path
from typing import Any

from vxis.cli.manifest import ScanManifest, ManifestTarget
from vxis.evidence.schema import Evidence
from vxis.interaction.surface import TargetKind
from vxis.models.finding import Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_base_scan_id() -> str:
    return f"VXIS-MULTI-{time.strftime('%Y%m%d-%H%M%S')}"


def _resolve_output(template: str) -> Path:
    today = date.today().isoformat()
    resolved = template.replace("{date}", today)
    return Path(resolved).resolve()


def _build_brain() -> Any:
    """Construct a default AgentBrain. Import is deferred so tests can mock."""
    from vxis.agent.brain import AgentBrain  # type: ignore[import-untyped]
    from vxis.config.schema import VXISConfig  # type: ignore[import-untyped]

    config = VXISConfig()
    return AgentBrain(config=config)


def _build_pipeline(
    report_output_path: Path | None = None,
) -> Any:
    """Build a ScanPipeline with a fresh brain."""
    from vxis.pipeline.scan_pipeline_v2 import ScanPipeline  # type: ignore[import-untyped]

    brain = _build_brain()
    return ScanPipeline(
        brain=brain,
        report_output_path=report_output_path,
    )


async def _scan_target(
    target: ManifestTarget,
    scan_id: str,
    max_iters: int,
) -> list[Finding]:
    """Run a single target scan and return its findings.

    Returns an empty list when:
      - target.skip is True
      - target.kind == CODE and surface raises NotImplementedError
    """
    if target.skip:
        logger.info("Skipping target '%s' (skip=True)", target.name)
        return []

    if target.kind == TargetKind.CODE:
        # Attempt to import CodeSurface; fall back gracefully if not yet landed.
        try:
            from vxis.interaction.factory import SurfaceFactory  # type: ignore[import-untyped]
            SurfaceFactory.probe(TargetKind.CODE)
        except (ImportError, NotImplementedError, AttributeError):
            logger.warning(
                "CODE surface not yet available — skipping %s",
                target.name,
            )
            return []

    logger.info(
        "Starting scan for target '%s' (%s) → %s",
        target.name,
        target.kind.value,
        target.entry,
    )

    pipeline = _build_pipeline()

    ctx = await pipeline.run(
        target=target.entry,
        kind=target.kind,
        target_hints=dict(target.hints),
    )

    findings: list[Finding] = list(ctx.findings) if ctx.findings else []
    logger.info(
        "Completed scan for target '%s': %d finding(s), scan_id=%s",
        target.name,
        len(findings),
        scan_id,
    )
    return findings


async def _run_phase_g(all_findings: list[Finding]) -> list[Any]:
    """Run CrossProtocolSynthesizer across all target findings.

    Returns the list of SynthesizedChain objects (may be empty).
    """
    from vxis.synthesis.cross_protocol import CrossProtocolSynthesizer  # type: ignore[import-untyped]

    synth = CrossProtocolSynthesizer()

    # CrossProtocolSynthesizer.add_findings expects list[Evidence].
    # Finding inherits from Evidence (or is compatible); cast is safe.
    evidence_list: list[Evidence] = []
    for f in all_findings:
        if isinstance(f, Evidence):
            evidence_list.append(f)
        else:
            # Finding may wrap an Evidence; attempt attribute access.
            ev = getattr(f, "evidence", None) or getattr(f, "_evidence", None)
            if isinstance(ev, Evidence):
                evidence_list.append(ev)
            # If neither, skip — synthesizer needs Evidence objects.

    if evidence_list:
        synth.add_findings(evidence_list)

    chains = await synth.synthesize()
    logger.info("Phase-G synthesis: %d cross-target chain(s) produced", len(chains))
    return chains


def _emit_report(
    manifest: ScanManifest,
    base_scan_id: str,
    all_findings: list[Finding],
    chains: list[Any],
    output_path: Path,
) -> None:
    """Render a single merged HTML report."""
    from vxis.report.generator import ReportData, ReportGenerator  # type: ignore[import-untyped]

    attack_chains: list[list[str]] = []
    for chain in chains:
        chain_ids: list[str] = []
        for f in getattr(chain, "findings", []):
            fid = getattr(f, "id", None) or getattr(f, "finding_id", None)
            if fid:
                chain_ids.append(str(fid))
        if len(chain_ids) >= 2:
            attack_chains.append(chain_ids)

    report_data = ReportData(
        scan_id=base_scan_id,
        client_name=manifest.project,
        target=", ".join(
            t.entry for t in manifest.targets if not t.skip
        ),
        scan_date=date.today().isoformat(),
        findings=all_findings,
        attack_chains=attack_chains or None,
    )

    generator = ReportGenerator()
    generator.generate_html_file(report_data, output_path)
    logger.info("Report written → %s", output_path)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def multi_scan(manifest: ScanManifest) -> int:
    """Orchestrate a multi-target scan and return a POSIX exit code.

    Returns:
        0  — success (report generated, zero or more findings)
        1  — all targets were skipped or no output could be written
    """
    return asyncio.run(_async_multi_scan(manifest))


async def _async_multi_scan(manifest: ScanManifest) -> int:
    base_scan_id = _build_base_scan_id()
    output_path = _resolve_output(manifest.output)

    logger.info(
        "Multi-scan started: project='%s', targets=%d, scan_id=%s",
        manifest.project,
        len(manifest.targets),
        base_scan_id,
    )

    all_findings: list[Finding] = []
    scanned_count = 0

    for target in manifest.targets:
        per_target_scan_id = f"{base_scan_id}-{target.name}"
        findings = await _scan_target(
            target=target,
            scan_id=per_target_scan_id,
            max_iters=manifest.max_iters_per_target,
        )
        all_findings.extend(findings)
        if not target.skip and target.kind != TargetKind.CODE:
            scanned_count += 1

    if scanned_count == 0:
        logger.warning("All targets were skipped — no report generated.")
        return 1

    # Phase-G cross-target synthesis
    chains: list[Any] = []
    if manifest.correlation and all_findings:
        chains = await _run_phase_g(all_findings)

    _emit_report(
        manifest=manifest,
        base_scan_id=base_scan_id,
        all_findings=all_findings,
        chains=chains,
        output_path=output_path,
    )

    return 0
