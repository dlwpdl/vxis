"""MemoryScannerPlugin — FridaBridge를 사용한 프로세스 메모리 스캔.

게임 프로세스 메모리에서 변경 가능한 게임 상태 값을 탐색.
통화, 체력, 점수 등 게임 크리티컬 값의 메모리 위치 식별.

주요 기능:
    1. 프로세스 열거 + 자동 게임 프로세스 식별
    2. 정수/실수 값 패턴 스캔 (체력, 골드, 점수)
    3. 안티디버그 함수 탐지
    4. 메모리 보호 강도 평가
"""

from __future__ import annotations

import logging
import struct
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

logger = logging.getLogger(__name__)


class MemoryScannerPlugin(BasePlugin):
    """FridaBridge 기반 게임 프로세스 메모리 스캐너.

    frida가 없으면 정적 분석 모드로 동작.
    """

    _meta = PluginMeta(
        name="memory_scanner",
        version="1.0.0",
        tool_binary="frida",  # frida-tools frida CLI
        category="game",
        tier=2,  # Tier 2 — 프로세스 어태치 필요
        produces=("memory_regions", "cheat_vectors", "antidebug_functions"),
        timeout_seconds=300,
    )

    @property
    def meta(self) -> PluginMeta:
        return self._meta

    def build_command(
        self,
        target: str,
        scan_profile: str,
        ctx: DAGContext,
        tool_config: dict[str, Any],
    ) -> str:
        """frida CLI 명령어 (프로세스 목록 열거)."""
        return "frida-ps -a"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """frida-ps 출력 파싱 (PID, 프로세스명 추출)."""
        processes: list[dict[str, Any]] = []
        for line in raw_stdout.splitlines()[1:]:  # 헤더 스킵
            parts = line.split(None, 1)
            if len(parts) == 2:
                try:
                    processes.append({"pid": int(parts[0]), "name": parts[1].strip()})
                except ValueError:
                    pass

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={"processes": processes, "count": len(processes)},
        )

    # ── 핵심 분석 메서드 ────────────────────────────────────────────

    async def scan_game_process(
        self,
        process_name_or_pid: str | int,
        known_values: dict[str, int | float] | None = None,
        game_engine: str = "unknown",
    ) -> dict[str, Any]:
        """게임 프로세스 메모리 스캔.

        Args:
            process_name_or_pid: 프로세스 이름 또는 PID.
            known_values: 알려진 게임 상태 값 (스캔 타깃 힌트). 예: {"gold": 1000, "hp": 100}.
            game_engine: 게임 엔진 (Unity/Unreal 특화 오프셋 사용).

        Returns:
            스캔 결과 딕셔너리.
        """
        from vxis.interaction.frida_bridge import FridaBridge

        bridge = FridaBridge()
        if not bridge.is_available:
            return {
                "error": "frida not available",
                "install": "pip install frida frida-tools",
                "static_analysis_only": True,
            }

        result: dict[str, Any] = {
            "process": str(process_name_or_pid),
            "modules": [],
            "value_locations": {},
            "anticheat_functions": [],
            "security_assessment": {},
        }

        attached = await bridge.attach(process_name_or_pid)
        if not attached:
            result["error"] = f"Failed to attach to {process_name_or_pid}"
            return result

        try:
            # 모듈 열거
            modules = await bridge.enumerate_modules()
            result["modules"] = [
                {"name": m.name, "base": m.base_address, "size": m.size}
                for m in modules
            ]

            # 알려진 값으로 메모리 위치 탐색
            if known_values:
                for value_name, value in known_values.items():
                    locations = await self._scan_for_value(bridge, value)
                    if locations:
                        result["value_locations"][value_name] = locations[:5]
                        logger.info(
                            "  Found '%s' value at %d locations",
                            value_name, len(locations),
                        )

            # 안티디버그 함수 탐지
            antidebug_funcs = await self._detect_antidebug(bridge, modules)
            result["anticheat_functions"] = antidebug_funcs

            # 엔진 특화 스캔
            if game_engine == "unity":
                unity_data = await self._scan_unity_specifics(bridge)
                result["unity_analysis"] = unity_data
            elif game_engine == "unreal":
                unreal_data = await self._scan_unreal_specifics(bridge)
                result["unreal_analysis"] = unreal_data

            # 보안 평가
            result["security_assessment"] = self._assess_memory_security(
                modules=modules,
                antidebug_count=len(antidebug_funcs),
                has_value_locations=bool(result["value_locations"]),
            )

        finally:
            await bridge.detach()

        return result

    async def _scan_for_value(
        self,
        bridge: Any,
        value: int | float,
    ) -> list[str]:
        """메모리에서 특정 값의 주소 탐색.

        4바이트 int32 및 float32 패턴으로 스캔.
        """
        locations: list[str] = []

        # int32 패턴
        try:
            int_val = int(value)
            int_bytes = struct.pack("<I", int_val & 0xFFFFFFFF)
            pattern_str = " ".join(f"{b:02X}" for b in int_bytes)
            matches = await bridge.scan_memory_pattern(pattern_str)
            locations.extend([m["address"] for m in matches[:3]])
        except (struct.error, OverflowError):
            pass

        # float32 패턴
        try:
            float_bytes = struct.pack("<f", float(value))
            pattern_str = " ".join(f"{b:02X}" for b in float_bytes)
            matches = await bridge.scan_memory_pattern(pattern_str)
            locations.extend([m["address"] for m in matches[:3]])
        except Exception:
            pass

        return locations

    async def _detect_antidebug(
        self,
        bridge: Any,
        modules: list[Any],
    ) -> list[dict[str, Any]]:
        """안티디버그/안티치트 함수 탐지."""
        antidebug_signatures = [
            # Windows API
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugString",
            "DebugBreak",
            "ZwSetInformationThread",
            # 안티치트 시스템
            "EasyAntiCheat",
            "BEService",
            "BattleEye",
            "vanguard",
            # 타이밍 기반 탐지
            "GetTickCount",
            "QueryPerformanceCounter",
            # 가상화 탐지
            "cpuid",
            "rdtsc",
        ]

        found: list[dict[str, Any]] = []
        for module in modules[:20]:  # 최대 20개 모듈
            exports = await bridge.get_exports(module.name)
            for export in exports:
                export_name = export.get("name", "")
                for sig in antidebug_signatures:
                    if sig.lower() in export_name.lower():
                        found.append({
                            "function": export_name,
                            "module": module.name,
                            "address": export.get("address"),
                            "category": self._categorize_antidebug(export_name),
                        })
                        break

        return found

    async def _scan_unity_specifics(self, bridge: Any) -> dict[str, Any]:
        """Unity 엔진 특화 스캔 (MonoBehaviour, Mono JIT 힙)."""
        js_code = """
        try {
            var mono_modules = Process.enumerateModules().filter(function(m) {
                return m.name.toLowerCase().includes('mono') ||
                       m.name.toLowerCase().includes('unity');
            });
            send({
                type: 'unity_modules',
                count: mono_modules.length,
                names: mono_modules.map(function(m) { return m.name; })
            });

            // Unity MonoBehaviour 탐지
            if (mono_modules.length > 0) {
                send({type: 'unity_detected', has_mono: true});
            }
        } catch(e) {
            send({type: 'error', message: e.message});
        }
        """
        from vxis.interaction.frida_bridge import HookScript
        hook = HookScript(name="unity_scan", js_code=js_code)
        result = await bridge.inject_script(hook, collect_duration=2.0)

        unity_data: dict[str, Any] = {"detected": False}
        for val in result.captured_values:
            if isinstance(val, dict):
                if val.get("type") == "unity_modules":
                    unity_data["module_count"] = val.get("count", 0)
                    unity_data["modules"] = val.get("names", [])
                elif val.get("type") == "unity_detected":
                    unity_data["detected"] = True

        return unity_data

    async def _scan_unreal_specifics(self, bridge: Any) -> dict[str, Any]:
        """Unreal Engine 특화 스캔 (UObject, GWorld)."""
        js_code = """
        try {
            var ue_modules = Process.enumerateModules().filter(function(m) {
                return m.name.toLowerCase().includes('ue4') ||
                       m.name.toLowerCase().includes('ue5') ||
                       m.name.toLowerCase().includes('unreal');
            });
            send({
                type: 'unreal_modules',
                count: ue_modules.length,
                names: ue_modules.map(function(m) { return m.name; })
            });
        } catch(e) {
            send({type: 'error', message: e.message});
        }
        """
        from vxis.interaction.frida_bridge import HookScript
        hook = HookScript(name="unreal_scan", js_code=js_code)
        result = await bridge.inject_script(hook, collect_duration=2.0)

        unreal_data: dict[str, Any] = {"detected": False}
        for val in result.captured_values:
            if isinstance(val, dict) and val.get("type") == "unreal_modules":
                unreal_data["detected"] = val.get("count", 0) > 0
                unreal_data["modules"] = val.get("names", [])

        return unreal_data

    def _assess_memory_security(
        self,
        modules: list[Any],
        antidebug_count: int,
        has_value_locations: bool,
    ) -> dict[str, Any]:
        """메모리 보안 강도 평가."""
        issues: list[str] = []
        score = 10  # 10점 만점 (낮을수록 취약)

        if has_value_locations:
            issues.append("Game state values found in scannable memory — cheat memory editing possible")
            score -= 4

        if antidebug_count == 0:
            issues.append("No anti-debug functions detected — debugger attachment unrestricted")
            score -= 3
        elif antidebug_count < 3:
            issues.append("Minimal anti-debug protection — partial bypass feasible")
            score -= 1

        # 모듈 수가 적으면 보호 계층 부족 가능성
        if len(modules) < 5:
            issues.append("Few loaded modules — possible minimal security layer")
            score -= 1

        security_level = "high" if score >= 8 else "medium" if score >= 5 else "low"
        return {
            "score": max(0, score),
            "level": security_level,
            "issues": issues,
            "antidebug_count": antidebug_count,
            "memory_editable": has_value_locations,
        }

    @staticmethod
    def _categorize_antidebug(func_name: str) -> str:
        """안티디버그 함수 카테고리 분류."""
        name_lower = func_name.lower()
        if any(k in name_lower for k in ["debugger", "debug"]):
            return "anti_debug"
        if any(k in name_lower for k in ["anticheat", "easyanti", "battleye", "vanguard"]):
            return "anti_cheat"
        if any(k in name_lower for k in ["rdtsc", "tickcount", "performance"]):
            return "timing_check"
        if any(k in name_lower for k in ["cpuid", "vmware", "vbox"]):
            return "vm_detection"
        return "security_check"
