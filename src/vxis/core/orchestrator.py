"""Scan orchestrator for VXIS security automation platform.

Ties together scope validation, plugin discovery, DAG execution, finding
normalization, deduplication, FP filtering, enrichment, and persistence
into a single coherent scan session.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vxis.config.schema import VXISConfig
from vxis.core.context import DAGContext, PluginOutput
from vxis.core.db import create_engine, get_session, init_db
from vxis.core.engine import DAGExecutor, TaskState
from vxis.core.events import (
    EventType,
    PipelineEvent,
    ScanEventBus,
    ScanLifecycleEvent,
    ToolFindingEvent,
    ToolOutputEvent,
)
from vxis.core.enricher import FindingEnricher
from vxis.core.rate_limiter import GlobalRateLimiter
from vxis.core.fp_pipeline import FPPipeline
from vxis.core.logger import AuditLogger
from vxis.core.normalizer import FindingDeduplicator, FindingFactory
from vxis.core.resilience import ResilientRunner, ToolExecutionError, classify_result
from vxis.core.scanner import run_tool
from vxis.core.scope import ScopeValidator, ScopeViolationError
from vxis.models.db_models import FindingRecord, ScanRecord, ToolRunRecord
from vxis.models.finding import Finding, Severity
from vxis.plugins.registry import build_dag_from_plugins, discover_plugins

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Value object returned after a completed scan session.

    Attributes:
        scan_id:       Unique identifier for this scan run.
        target:        Primary scan target (domain or IP).
        profile:       Scan profile name used (e.g. 'standard').
        findings:      Deduplicated, enriched Finding objects.
        tool_runs:     Summary dicts for each plugin execution.
        errors:        List of dicts with 'plugin', 'state', and 'error' keys
                       for every plugin that failed, timed out, or was skipped.
        started_at:    UTC wall-clock start time.
        finished_at:   UTC wall-clock end time.
    """

    scan_id: str
    target: str
    profile: str
    findings: list[Finding] = field(default_factory=list)
    tool_runs: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def duration_seconds(self) -> float:
        """Wall-clock duration of the entire scan in seconds."""
        delta = self.finished_at - self.started_at
        return delta.total_seconds()

    @property
    def severity_counts(self) -> dict[str, int]:
        """Count of findings grouped by severity level.

        Returns a dict with keys for every Severity value; missing severities
        default to 0 so callers can safely access any key.
        """
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.effective_severity.value] += 1
        return counts


# ---------------------------------------------------------------------------
# ScanOrchestrator
# ---------------------------------------------------------------------------


class ScanOrchestrator:
    """Orchestrates a complete VXIS scan session end-to-end.

    Responsibilities (in order):
    1. Scope validation
    2. Plugin discovery and filtering
    3. DAG construction and execution
    4. Raw output collection into DAGContext
    5. Finding normalization (FindingFactory)
    6. Deduplication (FindingDeduplicator)
    7. False-positive filtering (FPPipeline)
    8. Enrichment (FindingEnricher)
    9. Persistence to the configured database
    10. Return a ScanResult

    Args:
        config: Root VXIS configuration object.
    """

    def __init__(
        self,
        config: VXISConfig,
        event_bus: ScanEventBus | None = None,
    ) -> None:
        self.config = config
        self.event_bus = event_bus or ScanEventBus()
        self.audit_logger = AuditLogger(config.data_dir / "audit.jsonl")
        self.rate_limiter = GlobalRateLimiter()
        self.resilient_runner = ResilientRunner()

        # Reusable DB engine — created once, shared across scans.
        db_url = config.db_url
        if ":///" in db_url:
            prefix, path = db_url.split("///", 1)
            db_url = f"{prefix}///{Path(path).expanduser()}"
        self._db_engine = create_engine(db_url)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_scan(
        self,
        target: str,
        profile: str = "standard",
        selected_plugins: list[str] | None = None,
        client_config_path: Path | None = None,
        tier: int = 1,
    ) -> ScanResult:
        """Execute a full scan against *target*.

        Args:
            target:             Primary scan target (domain, IP, or CIDR range).
            profile:            Named scan profile; must exist in config.profiles.
            selected_plugins:   If provided, only these plugin names are run.
                                All discovered plugins are used when None.
            client_config_path: Optional path to a client-specific config file
                                (reserved for future use in Phase 1+).

        Returns:
            A populated ScanResult with findings, tool run summaries, and
            timing information.

        Raises:
            ScopeViolationError: When the target is outside the authorized scope.
            ValueError:          When the requested profile is not found in config.
        """
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)

        # --- 1. Validate profile ---
        scan_profile = self.config.profiles.get(profile)
        if scan_profile is None:
            available = ", ".join(self.config.profiles.keys())
            raise ValueError(f"Profile '{profile}' not found. Available profiles: {available}")

        # --- 2. Scope validation ---
        # When no client config is supplied, the target itself is the only
        # authorized scope entry so the check is always in-scope. Real
        # deployments attach a ClientConfig with explicit target lists.
        scope_validator = ScopeValidator(
            targets=[target],
            exclude_targets=[],
            exclude_ports=[],
        )
        in_scope = scope_validator.is_in_scope(target)
        self.audit_logger.log_scope_check(scan_id, target, in_scope)

        if not in_scope:
            raise ScopeViolationError(target, [target])

        # --- 3. Audit: scan start ---
        self.audit_logger.log_scan_start(
            scan_id=scan_id,
            target=target,
            profile=profile,
            config_snapshot={"profile": profile, "target": target},
        )

        # --- 4. Plugin discovery and filtering ---
        registry = discover_plugins()

        # Filter by tier: only run Tier 1 (recon) plugins for zero-touch scans.
        # Tier 2 (breach) plugins require --tier breach flag (future).
        # tier comes from the parameter above
        registry = {k: v for k, v in registry.items() if getattr(v.meta, "tier", 1) <= tier}

        # Filter out plugins whose binary is not installed
        registry = {k: v for k, v in registry.items() if v.validate_environment()}

        # Apply profile-level skip list
        for skip_name in scan_profile.skip_plugins:
            registry.pop(skip_name, None)

        # Apply caller-supplied plugin allowlist
        if selected_plugins is not None:
            allowed = set(selected_plugins)
            registry = {k: v for k, v in registry.items() if k in allowed}

        logger.info(
            "Scan %s: %d plugins selected for target '%s' with profile '%s'.",
            scan_id,
            len(registry),
            target,
            profile,
        )

        # --- 5. Build DAG ---
        dag_nodes = build_dag_from_plugins(registry)
        dag_context = DAGContext(target=target, scan_profile=profile)

        # --- Emit scan started ---
        await self.event_bus.emit(
            ScanLifecycleEvent(
                event_type=EventType.SCAN_STARTED,
                scan_id=scan_id,
                target=target,
                profile=profile,
                plugin_count=len(registry),
            )
        )

        # --- 6. Configure rate limiter for this target ---
        if scan_profile.rate_limit > 0:
            self.rate_limiter.set_rate(target, scan_profile.rate_limit)
        else:
            # rate_limit=0 means unlimited; set rate to 0 so acquire() is a no-op
            self.rate_limiter.set_rate(target, 0)

        # --- 7. Execute DAG ---
        executor = DAGExecutor(
            dag_nodes,
            max_concurrency=scan_profile.max_concurrency,
            event_bus=self.event_bus,
        )
        completed_nodes = await executor.execute(
            self._make_run_func(
                registry=registry,
                dag_context=dag_context,
                target=target,
                profile=profile,
                scan_id=scan_id,
            )
        )

        # --- 7. Collect tool run summaries ---
        tool_runs: list[dict[str, Any]] = []
        for node_name, node in completed_nodes.items():
            tool_runs.append(
                {
                    "plugin": node_name,
                    "state": node.state.value,
                    "duration_seconds": node.duration_seconds,
                    "error": node.error,
                }
            )

        # --- 7b. Collect errors from failed / skipped / timed-out nodes ---
        plugin_errors: list[dict[str, str]] = []
        for node_name, node in completed_nodes.items():
            if node.state in (TaskState.FAILED, TaskState.TIMED_OUT, TaskState.SKIPPED):
                plugin_errors.append(
                    {
                        "plugin": node_name,
                        "state": node.state.value,
                        "error": node.error or "unknown error",
                    }
                )
                logger.warning(
                    "Scan %s: plugin '%s' ended in state '%s': %s",
                    scan_id,
                    node_name,
                    node.state.value,
                    node.error or "unknown error",
                )

        # --- 8. Normalize findings from all completed nodes ---
        all_raw_findings: list[Finding] = []
        for node_name, node in completed_nodes.items():
            if node.state != TaskState.COMPLETED or node.result is None:
                continue
            plugin_output = node.result
            normalized = self._normalize_output(plugin_output, scan_id, target)
            all_raw_findings.extend(normalized)

        # --- 9. Deduplicate ---
        await self.event_bus.emit(
            PipelineEvent(
                event_type=EventType.PIPELINE_STAGE,
                scan_id=scan_id,
                stage="deduplicate",
                finding_count=len(all_raw_findings),
                detail=f"{len(all_raw_findings)} raw findings",
            )
        )
        deduplicator = FindingDeduplicator()
        deduped = deduplicator.deduplicate(all_raw_findings)

        # --- 10. False-positive pipeline ---
        await self.event_bus.emit(
            PipelineEvent(
                event_type=EventType.PIPELINE_STAGE,
                scan_id=scan_id,
                stage="fp_filter",
                finding_count=len(deduped),
                detail=f"{len(deduped)} after dedup",
            )
        )
        tech_stack = self._detect_tech_stack(dag_context)
        fp_pipeline = FPPipeline(tech_stack=tech_stack)
        filtered = await fp_pipeline.process(deduped)

        # --- 11. Enrich ---
        await self.event_bus.emit(
            PipelineEvent(
                event_type=EventType.PIPELINE_STAGE,
                scan_id=scan_id,
                stage="enrich",
                finding_count=len(filtered),
                detail=f"{len(filtered)} after FP filter",
            )
        )
        enricher = FindingEnricher()
        enriched = enricher.enrich(filtered)

        # --- 12. Persist to database ---
        finished_at = datetime.now(timezone.utc)
        await self._persist(
            scan_id=scan_id,
            target=target,
            profile=profile,
            findings=enriched,
            tool_runs=tool_runs,
            started_at=started_at,
            finished_at=finished_at,
        )

        # --- 13. Audit: scan end ---
        self.audit_logger.log_scan_end(
            scan_id=scan_id,
            finding_count=len(enriched),
            status="completed",
        )

        await self.event_bus.emit(
            ScanLifecycleEvent(
                event_type=EventType.SCAN_COMPLETED,
                scan_id=scan_id,
                target=target,
                profile=profile,
                finding_count=len(enriched),
                duration_seconds=(finished_at - started_at).total_seconds(),
            )
        )

        logger.info(
            "Scan %s completed: %d findings in %.1fs.",
            scan_id,
            len(enriched),
            (finished_at - started_at).total_seconds(),
        )

        # --- 14. Auto-learn: 스캔 결과를 메모리에 저장 ---
        self._auto_learn(target, enriched, tool_runs, plugin_errors, dag_context)

        return ScanResult(
            scan_id=scan_id,
            target=target,
            profile=profile,
            findings=enriched,
            tool_runs=tool_runs,
            errors=plugin_errors,
            started_at=started_at,
            finished_at=finished_at,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_run_func(
        self,
        registry: dict,
        dag_context: DAGContext,
        target: str,
        profile: str,
        scan_id: str,
    ):
        """Build the async run_func closure passed to DAGExecutor.

        The closure captures the registry, context, and scan metadata.  For
        each plugin it:
        1. Retrieves the plugin instance from the registry.
        2. Builds the CLI command via plugin.build_command().
        3. Executes via run_tool() with profile-adjusted timeout.
        4. Classifies the result via classify_result().
        5. Parses output via plugin.parse_output().
        6. Stores the PluginOutput in dag_context.
        7. Logs the run via AuditLogger.

        Returns:
            An async callable that accepts a plugin name and returns PluginOutput.
        """

        async def _run(plugin_name: str) -> PluginOutput:
            plugin = registry.get(plugin_name)
            if plugin is None:
                raise ValueError(f"Plugin '{plugin_name}' not found in registry.")

            tool_config: dict[str, Any] = {}
            profile_obj = self.config.profiles.get(profile)
            if profile_obj is not None:
                override = profile_obj.tool_overrides.get(plugin_name)
                if override is not None:
                    tool_config = {"extra_args": override.extra_args}

            command_str = plugin.build_command(
                target=target,
                scan_profile=profile,
                ctx=dag_context,
                tool_config=tool_config,
            )
            timeout = plugin.get_timeout(profile)

            logger.debug(
                "Running plugin '%s': command=%r, timeout=%ds.",
                plugin_name,
                command_str,
                timeout,
            )

            # Streaming callback for real-time tool output
            _event_bus = self.event_bus
            _scan_id = scan_id

            async def _on_line(line: str, is_stderr: bool) -> None:
                await _event_bus.emit(
                    ToolOutputEvent(
                        event_type=EventType.TOOL_OUTPUT_LINE,
                        scan_id=_scan_id,
                        plugin_name=plugin_name,
                        line=line,
                        is_stderr=is_stderr,
                    )
                )
                # Detect findings in real-time from JSON Lines tools
                if not is_stderr and line.startswith("{"):
                    _try_emit_finding(line, plugin_name)

            def _try_emit_finding(line: str, pname: str) -> None:
                """Best-effort real-time finding detection from JSON output."""
                import json as _json

                try:
                    data = _json.loads(line)
                    # Nuclei format
                    if "info" in data and "severity" in data.get("info", {}):
                        asyncio.create_task(
                            _event_bus.emit(
                                ToolFindingEvent(
                                    event_type=EventType.TOOL_FINDING,
                                    scan_id=_scan_id,
                                    plugin_name=pname,
                                    severity=data["info"]["severity"],
                                    title=data["info"].get("name", data.get("template-id", "")),
                                    target=data.get("host", data.get("matched-at", "")),
                                )
                            )
                        )
                    # Trufflehog format
                    elif "DetectorName" in data:
                        asyncio.create_task(
                            _event_bus.emit(
                                ToolFindingEvent(
                                    event_type=EventType.TOOL_FINDING,
                                    scan_id=_scan_id,
                                    plugin_name=pname,
                                    severity="high",
                                    title=f"Secret: {data.get('DetectorName', '')}",
                                    target=data.get("SourceMetadata", {})
                                    .get("Data", {})
                                    .get("Github", {})
                                    .get("repository", ""),
                                )
                            )
                        )
                except (_json.JSONDecodeError, KeyError, TypeError):
                    pass

            # Acquire a rate-limit token before executing the tool.
            # This ensures all plugins targeting the same host respect
            # the profile's configured requests-per-second limit.
            await self.rate_limiter.get_limiter(target).acquire()

            async def _exec_tool() -> PluginOutput:
                """Execute the tool, raising ToolExecutionError on failure for retry."""
                try:
                    r = await run_tool(
                        command=command_str,
                        timeout=timeout,
                        shell=True,
                        on_line=_on_line,
                    )
                except TimeoutError:
                    self.audit_logger.log_tool_run(
                        scan_id=scan_id,
                        plugin_name=plugin_name,
                        target=target,
                        command=command_str,
                        exit_code=None,
                        elapsed_seconds=None,
                    )
                    raise

                _level = classify_result(r.return_code, r.stdout)
                self.audit_logger.log_tool_run(
                    scan_id=scan_id,
                    plugin_name=plugin_name,
                    target=target,
                    command=r.command,
                    exit_code=r.return_code,
                    elapsed_seconds=r.elapsed_seconds,
                )

                # If the tool failed without output, raise for retry
                if r.return_code != 0 and not r.stdout.strip():
                    raise ToolExecutionError(
                        f"Plugin '{plugin_name}' exited with code {r.return_code}",
                        exit_code=r.return_code,
                        stderr=r.stderr,
                    )

                logger.debug(
                    "Plugin '%s' finished: exit_code=%d, level=%s, elapsed=%.1fs.",
                    plugin_name,
                    r.return_code,
                    _level.value,
                    r.elapsed_seconds,
                )

                po = plugin.parse_output(r.stdout, r.stderr)
                dag_context.set(plugin_name, po)
                return po

            try:
                return await self.resilient_runner.run_with_retry(_exec_tool)
            except ToolExecutionError:
                # All retries exhausted — parse whatever output we have
                plugin_output = plugin.parse_output("", "")
                dag_context.set(plugin_name, plugin_output)
                raise

        return _run

    # Factory methods that require extra keyword arguments beyond (data, scan_id).
    _FACTORY_EXTRA_KWARGS: dict[str, list[str]] = {
        "checkdmarc": ["domain"],
        "crtsh": ["domain"],
        "subfinder": ["domain"],
        "swaks": ["target"],
    }

    def _normalize_output(
        self,
        plugin_output: PluginOutput,
        scan_id: str,
        target: str,
    ) -> list[Finding]:
        """Convert a PluginOutput into Finding objects using FindingFactory.

        Uses dynamic dispatch via ``getattr`` so that every ``from_<name>``
        method on :class:`FindingFactory` is automatically available without
        an explicit if-elif chain.  Plugin names containing hyphens are
        normalised to underscores (e.g. ``trivy-k8s`` → ``from_trivy_k8s``).

        Args:
            plugin_output: Raw parsed output from a plugin execution.
            scan_id:       Identifier of the parent scan.
            target:        Primary scan target (passed as ``domain=`` or
                           ``target=`` to factories that require it).

        Returns:
            List of Finding objects extracted from this plugin's output.
        """
        name = plugin_output.plugin_name
        data = plugin_output.parsed_data
        method_name = f"from_{name.replace('-', '_')}"

        factory_method = getattr(FindingFactory, method_name, None)
        if factory_method is None:
            raw_findings: list[dict[str, Any]] = plugin_output.findings
            logger.debug(
                "Plugin '%s' has no factory method '%s'; %d raw finding(s) skipped.",
                name,
                method_name,
                len(raw_findings),
            )
            return []

        try:
            extra_params = self._FACTORY_EXTRA_KWARGS.get(name, [])
            kwargs: dict[str, Any] = {}
            for param in extra_params:
                if param == "domain":
                    kwargs["domain"] = target
                elif param == "target":
                    kwargs["target"] = target
            return factory_method(data, scan_id, **kwargs)
        except Exception:
            logger.exception("Failed to normalize output for plugin '%s'. Skipping.", name)
            return []

    @staticmethod
    def _detect_tech_stack(dag_context: DAGContext) -> list[str]:
        """Extract technology stack identifiers from completed plugin outputs.

        Inspects httpx, nmap, and wafw00f results for technology indicators
        (web server, OS, WAF) and returns a list of lowercase tech strings
        suitable for :class:`FPPipeline`.
        """
        tech: set[str] = set()

        # --- httpx: tech detection from response headers / body ---
        httpx_out = dag_context.get("httpx")
        if httpx_out and httpx_out.parsed_data:
            results = httpx_out.parsed_data.get("results", [])
            if isinstance(results, list):
                for entry in results:
                    # httpx "tech" field
                    for t in entry.get("tech", []) or []:
                        tech.add(t.lower())
                    # httpx webserver field
                    ws = entry.get("webserver", "") or ""
                    if ws:
                        tech.add(ws.split("/")[0].lower())

        # --- nmap: OS and service detection ---
        nmap_out = dag_context.get("nmap")
        if nmap_out and nmap_out.parsed_data:
            for host in nmap_out.parsed_data.get("hosts", []) or []:
                # OS matches
                for os_match in host.get("os_matches", []) or []:
                    os_name = (os_match.get("name", "") or "").lower()
                    if "linux" in os_name:
                        tech.add("linux")
                    elif "windows" in os_name:
                        tech.add("windows")
                # Service banners
                for port_info in host.get("ports", []) or []:
                    product = (port_info.get("product", "") or "").lower()
                    if product:
                        tech.add(product.split("/")[0])

        # --- wafw00f: WAF detection ---
        waf_out = dag_context.get("wafw00f")
        if waf_out and waf_out.parsed_data:
            for entry in waf_out.parsed_data.get("results", []) or []:
                waf_name = (entry.get("firewall", "") or "").lower()
                if waf_name:
                    tech.add(waf_name)

        return list(tech)

    def _auto_learn(
        self,
        target: str,
        findings: list[Finding],
        tool_runs: list[dict[str, Any]],
        errors: list[dict[str, str]],
        dag_context: DAGContext,
    ) -> None:
        """스캔 완료 후 결과를 메모리에 자동 저장.

        뭐가 됐고, 뭐가 안 됐고, 뭘 찾았는지 기록하여
        다음 스캔에서 더 효과적인 전략을 선택할 수 있게 한다.
        """
        try:
            from vxis.agent.memory import AgentMemory, ScanMemory

            # 효과적/비효과적 도구 분류
            effective = []
            ineffective = []
            failed = []

            for run in tool_runs:
                plugin = run.get("plugin", "")
                state = run.get("state", "")
                if state == "completed":
                    # 이 도구가 실제로 finding을 냈는지 확인
                    plugin_findings = [f for f in findings if f.source_plugin == plugin]
                    if plugin_findings:
                        effective.append(plugin)
                    else:
                        ineffective.append(plugin)
                elif state in ("failed", "timed_out"):
                    failed.append(plugin)
                # skipped는 무시

            # 기술 스택
            tech_stack = self._detect_tech_stack(dag_context)

            # findings 요약
            findings_summary = [
                {
                    "severity": f.severity.value,
                    "type": f.finding_type,
                    "title": f.title[:100],
                }
                for f in findings[:50]
            ]

            memory = AgentMemory()
            scan_mem = ScanMemory(
                target=target,
                tech_stack=tech_stack,
                findings_summary=findings_summary,
                effective_tools=effective,
                ineffective_tools=ineffective + failed,
                total_findings=len(findings),
            )
            memory.remember_scan(scan_mem)

            # 로그에 학습 결과 표시
            logger.info(
                "학습 저장: %s — %d건 발견, 효과적: %s, 비효과적: %s, 실패: %s",
                target,
                len(findings),
                ", ".join(effective) or "없음",
                ", ".join(ineffective) or "없음",
                ", ".join(failed) or "없음",
            )

        except Exception as exc:
            logger.debug("메모리 자동 저장 실패 (무시): %s", exc)

    async def _persist(
        self,
        scan_id: str,
        target: str,
        profile: str,
        findings: list[Finding],
        tool_runs: list[dict[str, Any]],
        started_at: datetime,
        finished_at: datetime,
    ) -> None:
        """Write scan results to the configured database.

        Creates a ScanRecord, FindingRecord rows, and ToolRunRecord rows
        inside a single async session with automatic commit/rollback.

        Args:
            scan_id:     Logical scan identifier (UUID string).
            target:      Primary scan target.
            profile:     Scan profile name.
            findings:    Enriched, deduplicated findings to persist.
            tool_runs:   Tool execution summaries.
            started_at:  Scan start timestamp (UTC).
            finished_at: Scan end timestamp (UTC).
        """
        engine = self._db_engine

        try:
            await init_db(engine)

            async with get_session(engine) as session:
                # Scan record
                scan_record = ScanRecord(
                    target=target,
                    profile=profile,
                    status="completed",
                    started_at=started_at,
                    finished_at=finished_at,
                    config_snapshot={"scan_id": scan_id, "profile": profile},
                )
                session.add(scan_record)
                # Flush to get the auto-generated integer PK
                await session.flush()

                # Finding records
                for finding in findings:
                    finding_record = FindingRecord(
                        scan_id=scan_record.id,
                        dedup_hash=finding.dedup_hash,
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity.value,
                        effective_severity=finding.effective_severity.value,
                        status=finding.status.value,
                        finding_type=finding.finding_type,
                        target=finding.target,
                        port=finding.port,
                        protocol=finding.protocol,
                        affected_component=finding.affected_component,
                        cvss_score=finding.cvss.base_score if finding.cvss else None,
                        cvss_vector=(finding.cvss.vector_string if finding.cvss else None),
                        cve_ids=finding.cve_ids or None,
                        cwe_ids=finding.cwe_ids or None,
                        source_plugin=finding.source_plugin,
                        source_plugins=finding.source_plugins or None,
                        confidence=finding.confidence,
                        remediation=finding.remediation,
                        evidence=(
                            [e.model_dump() for e in finding.evidence] if finding.evidence else None
                        ),
                        references=(
                            [r.model_dump() for r in finding.references]
                            if finding.references
                            else None
                        ),
                        mitre_attack=(
                            finding.mitre_attack.model_dump() if finding.mitre_attack else None
                        ),
                        analyst_severity=(
                            finding.analyst_severity.value if finding.analyst_severity else None
                        ),
                        analyst_notes=finding.analyst_notes,
                        discovered_at=finding.discovered_at,
                        updated_at=finding.updated_at,
                    )
                    session.add(finding_record)

                # Tool run records
                for run in tool_runs:
                    tool_run_record = ToolRunRecord(
                        scan_id=scan_record.id,
                        plugin_name=run["plugin"],
                        command=run.get("command", ""),
                        return_code=run.get("exit_code"),
                        elapsed_seconds=run.get("duration_seconds"),
                        state=run["state"],
                    )
                    session.add(tool_run_record)

        except Exception:
            logger.exception(
                "Failed to persist scan '%s' to database. Results are still returned.",
                scan_id,
            )
