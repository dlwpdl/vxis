"""VXIS Agent Executor — Phase 3 자율 펜테스팅 엔진.

Phase 3 Architecture:
    ┌──────────────────────────────────────────────────────┐
    │  VXIS Master Agent (Brain + Phase 3 Modules)         │
    │                                                      │
    │  Knowledge Store  ← 지식 축적 (쓸수록 강해짐)          │
    │  Token Router     ← 비용 최적화 (원가 관리)            │
    │  Context Compressor ← 90%+ 토큰 절약                 │
    │  Chain Reasoner   ← 공격 체인 추론                    │
    │  LLM Fallback     ← 정책 거부 시 자동 전환            │
    │                                                      │
    │  Perceive → Recall → Reason → Chain → Reflect → Act  │
    └──────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from vxis.agent.brain import AgentBrain, AgentAction, AgentObservation
from vxis.agent.sandbox import DockerSandbox, SandboxManager, get_sandbox_manager
from vxis.config.schema import VXISConfig
from vxis.core.context import DAGContext, PluginOutput
from vxis.core.events import ScanEventBus
from vxis.core.orchestrator import ScanOrchestrator, ScanResult
from vxis.core.scanner import ToolResult, run_tool
from vxis.models.finding import Finding

logger = logging.getLogger(__name__)


@dataclass
class AgentScanResult:
    """Result from the autonomous agent scan."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    execution_log: str = ""
    steps_taken: int = 0
    duration_seconds: float = 0.0
    scan_result: ScanResult | None = None  # underlying orchestrator result


class AgentExecutor:
    """Master Agent that orchestrates autonomous pentesting.

    Phases:
        Phase 1 — Reconnaissance: Discover attack surface (subdomains, ports, tech stack)
        Phase 2 — Vulnerability Assessment: Run targeted scans based on recon
        Phase 3 — Deep Dive: AI decides what to probe further based on findings
        Phase 4 — Report: Synthesize everything into a final report

    Usage:
        executor = AgentExecutor(config)
        result = await executor.run(target="example.com")
    """

    def __init__(
        self,
        config: VXISConfig | None = None,
        event_bus: ScanEventBus | None = None,
        max_steps: int = 15,
    ) -> None:
        self._config = config or VXISConfig()
        self._event_bus = event_bus or ScanEventBus()
        self._orchestrator = ScanOrchestrator(self._config, event_bus=self._event_bus)
        self._observation = AgentObservation(target="")
        self._all_findings: list[Finding] = []

        # ── Phase 3 모듈 초기화 ────────────────────────────────
        self._knowledge_store = None
        self._compressor = None
        self._token_router = None
        self._chain_reasoner = None

        try:
            from vxis.knowledge.store import KnowledgeStore
            self._knowledge_store = KnowledgeStore()
        except Exception as exc:
            logger.debug("KnowledgeStore 초기화 실패 (무시): %s", exc)

        try:
            from vxis.knowledge.compressor import ContextCompressor
            self._compressor = ContextCompressor()
        except Exception as exc:
            logger.debug("ContextCompressor 초기화 실패 (무시): %s", exc)

        try:
            from vxis.llm.router import TokenRouter
            self._token_router = TokenRouter()
        except Exception as exc:
            logger.debug("TokenRouter 초기화 실패 (무시): %s", exc)

        try:
            from vxis.graph.chain_reasoner import ChainReasoner
            self._chain_reasoner = ChainReasoner()
        except Exception as exc:
            logger.debug("ChainReasoner 초기화 실패 (무시): %s", exc)

        # Brain에 Phase 3 모듈 주입
        self._brain = AgentBrain(
            max_steps=max_steps,
            knowledge_store=self._knowledge_store,
            compressor=self._compressor,
            token_router=self._token_router,
            chain_reasoner=self._chain_reasoner,
        )

        # ── Sandbox 초기화 ──────────────────────────────────────
        self._sandbox_available: bool = DockerSandbox.is_available()
        self._sandbox_manager: SandboxManager | None = (
            get_sandbox_manager() if self._sandbox_available else None
        )
        if self._sandbox_available:
            logger.info("Docker sandbox 활성화 — 도구를 컨테이너 안에서 실행합니다.")
        else:
            logger.info("Docker 미사용 — 도구를 호스트에서 직접 실행합니다 (폴백 모드).")

    async def run(
        self,
        target: str,
        profile: str = "standard",
    ) -> AgentScanResult:
        """Execute a full autonomous pentest against the target."""
        started_at = datetime.now(timezone.utc)
        self._observation.target = target

        logger.info("VXIS Agent starting autonomous scan: %s", target)

        # ── Phase 1: Initial Recon (parallel) ──
        logger.info("[Phase 1] 정찰 시작 — 공격 표면 수집")
        await self._run_recon_phase(target, profile)

        # ── Phase 2+: AI-driven iterative scanning ──
        logger.info("[Phase 2+] AI 에이전트 루프 시작")
        while not self._brain.is_done:
            actions = self._brain.think(self._observation)

            if not actions:
                break

            # Execute actions in parallel
            tasks = [
                self._execute_action(action, target, profile)
                for action in actions
                if action.tool != "DONE"
            ]

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for action, result in zip(
                    [a for a in actions if a.tool != "DONE"],
                    results,
                ):
                    if isinstance(result, Exception):
                        self._brain.record_result(action, {
                            "success": False,
                            "summary": str(result),
                            "findings_count": 0,
                        })
                    else:
                        self._brain.record_result(action, result)

        # ── Final: Compile results ──
        finished_at = datetime.now(timezone.utc)
        duration = (finished_at - started_at).total_seconds()

        execution_log = self._brain.get_execution_log()

        # Phase 3: 토큰 사용량 리포트 첨부
        if self._token_router is not None:
            execution_log += "\n\n" + self._token_router.format_usage_report()

        # Phase 3: 공격 체인 리포트 첨부
        if self._chain_reasoner is not None:
            chain_report = self._chain_reasoner.format_chains_for_brain()
            if chain_report:
                execution_log += "\n\n" + chain_report

        # Phase 3: Knowledge Store 통계 첨부
        if self._knowledge_store is not None:
            try:
                stats = self._knowledge_store.get_stats()
                execution_log += (
                    f"\n\n## Knowledge Store Stats\n"
                    f"- 축적된 기록: {stats['total_records']}\n"
                    f"- 컴파일된 패턴: {stats['compiled_patterns']}\n"
                    f"- 상관관계 규칙: {stats['correlation_rules']}\n"
                )
            except Exception:
                pass

        logger.info(
            "VXIS Agent 완료: %d단계, %d건 발견, %.0f초",
            self._brain._step_count,
            len(self._all_findings),
            duration,
        )

        # sandbox 컨테이너 정리 (스캔 완료 후)
        if self._sandbox_manager is not None:
            try:
                await self._sandbox_manager.cleanup_all()
            except Exception as exc:
                logger.warning("sandbox 정리 중 오류 (무시): %s", exc)

        return AgentScanResult(
            target=target,
            findings=self._all_findings,
            execution_log=execution_log,
            steps_taken=self._brain._step_count,
            duration_seconds=duration,
        )

    # ── Phase 1: Parallel Recon ─────────────────────────────────

    async def _run_recon_phase(self, target: str, profile: str) -> None:
        """Run initial recon tools in parallel to build attack surface picture."""
        recon_plugins = ["subfinder", "crtsh", "dnstwist", "checkdmarc", "httpx"]

        try:
            result = await self._orchestrator.run_scan(
                target=target,
                profile=profile,
                selected_plugins=recon_plugins,
            )
            self._update_observation_from_result(result)
        except Exception as exc:
            logger.warning("Recon phase partial failure: %s", exc)

    # ── Action execution ────────────────────────────────────────

    async def _execute_action(
        self,
        action: AgentAction,
        target: str,
        profile: str,
    ) -> dict[str, Any]:
        """Execute a single agent action using the orchestrator or direct tool."""

        tool = action.tool
        args = action.args

        logger.info("  → 실행: %s (%s)", tool, action.reasoning[:60])

        # Map agent actions to orchestrator plugin runs
        plugin_tools = {
            "nmap", "nuclei", "httpx", "testssl", "sslyze",
            "subfinder", "checkdmarc", "wafw00f", "trufflehog",
            "gitleaks", "crtsh", "dnstwist",
        }

        if tool in plugin_tools:
            return await self._run_plugin(tool, target, profile)
        elif tool == "ffuf":
            return await self._run_ffuf(target, args)
        elif tool == "sqlmap":
            return await self._run_sqlmap(target, args)
        else:
            return {"success": False, "summary": f"Unknown tool: {tool}", "findings_count": 0}

    async def _run_plugin(
        self, plugin_name: str, target: str, profile: str,
    ) -> dict[str, Any]:
        """Run a VXIS plugin via the orchestrator."""
        try:
            result = await self._orchestrator.run_scan(
                target=target,
                profile=profile,
                selected_plugins=[plugin_name],
            )
            new_findings = result.findings
            self._all_findings.extend(new_findings)
            self._update_observation_from_result(result)

            # Record in executed tools
            self._observation.executed_tools.append({
                "tool": plugin_name,
                "state": "completed",
                "findings": str(len(new_findings)),
            })

            return {
                "success": True,
                "summary": f"{plugin_name}: {len(new_findings)} findings",
                "findings_count": len(new_findings),
            }
        except Exception as exc:
            self._observation.executed_tools.append({
                "tool": plugin_name,
                "state": "failed",
                "findings": "0",
            })
            return {
                "success": False,
                "summary": f"{plugin_name} failed: {exc}",
                "findings_count": 0,
            }

    # ── Sandbox-aware tool runner ────────────────────────────────

    async def _run_command(
        self,
        command: str,
        target: str,
        timeout: int = 300,
    ) -> ToolResult:
        """Docker sandbox가 가용하면 컨테이너 안에서, 아니면 호스트에서 직접 실행.

        Args:
            command: 실행할 셸 명령어 문자열.
            target: 컨테이너 선택에 사용할 타겟 식별자.
            timeout: 최대 실행 시간(초).

        Returns:
            ToolResult (sandbox 실행과 직접 실행 모두 동일한 형식).
        """
        if self._sandbox_available and self._sandbox_manager is not None:
            sandbox = await self._sandbox_manager.get_or_create(target)
            return await sandbox.run_tool(command, timeout=timeout)
        # 폴백: 기존 직접 실행
        return await run_tool(command, timeout=timeout, shell=True)

    async def _run_ffuf(self, target: str, args: dict) -> dict[str, Any]:
        """Run ffuf directory brute-force."""
        url = args.get("url", f"https://{target}/FUZZ")
        wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")

        # sandbox 미사용 시에만 호스트 설치 여부 체크 (sandbox 안에는 이미 설치됨)
        if not self._sandbox_available:
            import shutil as _shutil
            if not _shutil.which("ffuf"):
                return {"success": False, "summary": "ffuf not installed", "findings_count": 0}

        cmd = f"ffuf -u {url} -w {wordlist} -mc 200,301,302,403 -o - -of json -s"

        try:
            result = await self._run_command(cmd, target=target, timeout=120)
            lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
            self._observation.executed_tools.append({
                "tool": "ffuf",
                "state": "completed",
                "findings": str(len(lines)),
            })
            return {
                "success": True,
                "summary": f"ffuf: {len(lines)} paths discovered",
                "findings_count": len(lines),
            }
        except Exception as exc:
            return {"success": False, "summary": f"ffuf failed: {exc}", "findings_count": 0}

    async def _run_sqlmap(self, target: str, args: dict) -> dict[str, Any]:
        """Run sqlmap for SQL injection testing."""
        url = args.get("url", f"https://{target}/")

        if not self._sandbox_available:
            import shutil as _shutil
            if not _shutil.which("sqlmap"):
                return {"success": False, "summary": "sqlmap not installed", "findings_count": 0}

        cmd = (
            f"sqlmap -u '{url}' --batch --random-agent"
            f" --level=3 --risk=2 --output-dir=/tmp/vxis_sqlmap"
            f" --forms --crawl=2 2>&1 | tail -20"
        )

        try:
            result = await self._run_command(cmd, target=target, timeout=300)
            injectable = "injectable" in result.stdout.lower()
            findings = 1 if injectable else 0

            self._observation.executed_tools.append({
                "tool": "sqlmap",
                "state": "completed",
                "findings": str(findings),
            })

            if injectable:
                self._observation.findings.append({
                    "severity": "critical",
                    "title": f"SQL Injection detected at {url}",
                    "source": "sqlmap",
                })

            return {
                "success": True,
                "summary": f"sqlmap: {'INJECTABLE!' if injectable else 'no injection found'}",
                "findings_count": findings,
            }
        except Exception as exc:
            return {"success": False, "summary": f"sqlmap failed: {exc}", "findings_count": 0}

    # ── Observation updates ─────────────────────────────────────

    def _update_observation_from_result(self, result: ScanResult) -> None:
        """Extract useful info from scan result into observation."""
        for finding in result.findings:
            self._observation.findings.append({
                "severity": finding.severity.value,
                "title": finding.title,
                "source": finding.source_plugin,
                "target": finding.target,
            })

        # Extract tech stack, ports, subdomains from tool runs
        for run in result.tool_runs:
            plugin = run.get("plugin", "")
            state = run.get("state", "")
            if state != "completed":
                continue

            existing_tools = {t["tool"] for t in self._observation.executed_tools}
            if plugin not in existing_tools:
                self._observation.executed_tools.append({
                    "tool": plugin,
                    "state": state,
                    "findings": str(len([
                        f for f in result.findings
                        if f.source_plugin == plugin
                    ])),
                })
