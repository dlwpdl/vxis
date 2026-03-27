"""GameMemoryAgent — 게임 메모리 조작 및 런타임 분석 에이전트.

Frida를 사용하여 게임 프로세스 메모리를 분석하고
치트 가능한 게임 상태 값을 식별 + 조작.

주요 기능:
    1. 게임 프로세스 자동 식별 + Frida 어태치
    2. 통화/체력/점수 등 크리티컬 값 메모리 스캔
    3. 안티디버그 함수 탐지 및 우회 가능성 평가
    4. 게임 엔진별 특화 분석 (Unity MonoBehaviour, Unreal GWorld)
    5. Brain으로 자동 Frida 스크립트 생성
"""

from __future__ import annotations

import logging
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis

logger = logging.getLogger(__name__)


@register
class GameMemoryAgent(BaseAgent):
    agent_id = "game_memory"
    description = (
        "Game memory analysis: Frida-based runtime hooking, game state value scanning, "
        "anti-debug detection, Unity/Unreal engine-specific analysis"
    )

    async def run(self, context: AgentContext) -> AgentResult:
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Frida 사용 가능 여부 확인
        from vxis.interaction.frida_bridge import FridaBridge, _FRIDA_AVAILABLE

        if not _FRIDA_AVAILABLE:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title="Frida not installed — memory analysis unavailable",
                severity=Severity.INFO,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    "frida Python package not installed. "
                    "Memory analysis capabilities disabled. "
                    "Install: pip install frida frida-tools"
                ),
                tags=["game", "memory", "frida", "setup"],
            ))
            return AgentResult(
                agent_id=self.agent_id,
                findings=findings,
                hypotheses=hypotheses,
                status="partial",
                error="frida not installed",
                metadata={"frida_available": False},
            )

        bridge = FridaBridge()

        # Phase 1: 게임 프로세스 탐색
        processes = await bridge.enumerate_processes()
        game_keywords = ["unity", "unreal", "game", "client", "launcher"]
        game_processes = [
            p for p in processes
            if any(kw in p.name.lower() for kw in game_keywords)
        ]

        if not game_processes:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title="No game process found for memory analysis",
                severity=Severity.INFO,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    f"No game process detected in running processes. "
                    f"Start the game client before running memory analysis. "
                    f"Total processes enumerated: {len(processes)}"
                ),
                tags=["game", "memory", "process"],
            ))
        else:
            # 가장 유망한 프로세스 선택
            target_proc = game_processes[0]

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Game process identified: {target_proc.name} (PID: {target_proc.pid})",
                severity=Severity.INFO,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=(
                    f"Game process found: {target_proc.name} (PID: {target_proc.pid}). "
                    f"Memory analysis will target this process."
                ),
                tags=["game", "memory", "process"],
            ))

            # Phase 2: 프로세스 어태치 + 분석
            attached = await bridge.attach(target_proc.pid)
            if attached:
                try:
                    # 모듈 열거
                    modules = await bridge.enumerate_modules()
                    module_analysis = self._analyze_modules(modules)

                    if module_analysis.get("game_engine"):
                        findings.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"Game engine identified: {module_analysis['game_engine']}",
                            severity=Severity.INFO,
                            evidence_type=EvidenceType.HTTP_EXCHANGE,
                            description=(
                                f"Engine: {module_analysis['game_engine']}. "
                                f"Modules: {module_analysis['module_count']}. "
                                f"Notable modules: {module_analysis.get('notable_modules', [])[:3]}"
                            ),
                            tags=["game", "memory", "engine"],
                        ))

                    # 안티디버그 함수 탐지
                    antidebug_findings = await self._detect_antidebug_in_modules(bridge, modules)
                    for adf in antidebug_findings:
                        findings.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"Anti-debug function: {adf['function']} in {adf['module']}",
                            severity=Severity.MEDIUM,
                            evidence_type=EvidenceType.HTTP_EXCHANGE,
                            description=(
                                f"Anti-debug/anti-cheat function detected: {adf['function']} "
                                f"in module {adf['module']} at {adf.get('address', 'unknown')}. "
                                f"Category: {adf.get('category', 'unknown')}"
                            ),
                            tags=["game", "memory", "antidebug", adf.get("category", "")],
                        ))

                    if not antidebug_findings:
                        findings.append(Evidence(
                            agent_id=self.agent_id,
                            title="No anti-debug functions detected — memory editing unrestricted",
                            severity=Severity.HIGH,
                            evidence_type=EvidenceType.MISCONFIGURATION,
                            description=(
                                "No anti-debug or anti-cheat memory protection functions found. "
                                "Game state values can be freely edited with Cheat Engine or Frida."
                            ),
                            tags=["game", "memory", "anticheat", "missing-protection"],
                        ))
                        hypotheses.append(Hypothesis(
                            title=f"Memory editing attack on game process {target_proc.name}",
                            rationale=(
                                "No memory protection detected — "
                                "all in-memory game state values (currency, HP, score) are editable"
                            ),
                            probability=0.9, impact=0.85,
                            suggested_agent="game_memory",
                        ))

                    # 메모리 스캔 — 일반적인 게임 값 패턴
                    memory_scan_results = await self._scan_common_game_values(bridge)
                    for scan_result in memory_scan_results:
                        findings.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"Game value location found: {scan_result['value_name']}",
                            severity=Severity.HIGH,
                            evidence_type=EvidenceType.HTTP_EXCHANGE,
                            description=(
                                f"Game state value '{scan_result['value_name']}' found at "
                                f"{len(scan_result.get('addresses', []))} memory locations. "
                                f"Value: {scan_result.get('value')}. "
                                f"Addresses: {scan_result.get('addresses', [])[:3]}"
                            ),
                            tags=["game", "memory", "cheat", scan_result["value_name"]],
                        ))
                        hypotheses.append(Hypothesis(
                            title=f"In-memory {scan_result['value_name']} manipulation possible",
                            rationale=(
                                f"Memory address of {scan_result['value_name']} identified. "
                                f"Direct memory write can change this value instantly."
                            ),
                            probability=0.85, impact=0.8,
                            suggested_agent="game_memory",
                        ))

                finally:
                    await bridge.detach()

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "frida_available": True,
                "game_processes_found": len(game_processes),
                "total_findings": len(findings),
            },
        )

    def _analyze_modules(self, modules: list[Any]) -> dict[str, Any]:
        """로드된 모듈에서 게임 엔진 및 주목할 모듈 식별."""
        module_names = [m.name.lower() for m in modules]

        game_engine = "unknown"
        notable: list[str] = []

        if any("mono" in n or "unity" in n for n in module_names):
            game_engine = "unity"
        elif any("ue4" in n or "ue5" in n or "unrealcrt" in n for n in module_names):
            game_engine = "unreal"
        elif any("godot" in n for n in module_names):
            game_engine = "godot"

        # 주목할 모듈
        interesting = ["anticheat", "protection", "guard", "security", "easyanti", "battleye"]
        for name in module_names:
            if any(kw in name for kw in interesting):
                notable.append(name)

        return {
            "game_engine": game_engine,
            "module_count": len(modules),
            "notable_modules": notable,
        }

    async def _detect_antidebug_in_modules(
        self,
        bridge: Any,
        modules: list[Any],
    ) -> list[dict[str, Any]]:
        """모든 모듈에서 안티디버그 함수 탐지."""
        antidebug_sigs = [
            ("IsDebuggerPresent", "anti_debug"),
            ("CheckRemoteDebuggerPresent", "anti_debug"),
            ("NtQueryInformationProcess", "anti_debug"),
            ("OutputDebugString", "anti_debug"),
            ("ZwSetInformationThread", "anti_debug"),
            ("EasyAntiCheat", "anti_cheat"),
            ("BattlEye", "anti_cheat"),
            ("vanguard", "anti_cheat"),
            ("GetTickCount", "timing"),
            ("QueryPerformanceCounter", "timing"),
        ]

        found: list[dict[str, Any]] = []
        # 처음 10개 모듈만 확인 (성능 제한)
        for module in modules[:10]:
            exports = await bridge.get_exports(module.name)
            for export in exports:
                export_name = export.get("name", "")
                for sig, category in antidebug_sigs:
                    if sig.lower() in export_name.lower():
                        found.append({
                            "function": export_name,
                            "module": module.name,
                            "address": export.get("address", ""),
                            "category": category,
                        })
                        break

        return found

    async def _scan_common_game_values(
        self,
        bridge: Any,
    ) -> list[dict[str, Any]]:
        """일반적인 게임 값 패턴 메모리 스캔.

        일반적인 초기 게임 값 (체력 100, 골드 1000 등)을 스캔.
        """
        import struct

        common_values = [
            ("player_hp", 100),
            ("player_mana", 100),
            ("gold", 1000),
            ("level", 1),
            ("experience", 0),
        ]

        results: list[dict[str, Any]] = []

        for value_name, default_value in common_values:
            # int32 패턴 생성
            pattern_bytes = struct.pack("<I", default_value)
            hex_pattern = " ".join(f"{b:02X}" for b in pattern_bytes)

            try:
                matches = await bridge.scan_memory_pattern(hex_pattern)
                if matches:
                    results.append({
                        "value_name": value_name,
                        "value": default_value,
                        "addresses": [m["address"] for m in matches[:5]],
                        "match_count": len(matches),
                    })
            except Exception as exc:
                logger.debug("Memory scan failed for %s: %s", value_name, exc)

        return results
