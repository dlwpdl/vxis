"""VXIS FridaBridge — Frida 런타임 후킹 브릿지.

게임/모바일 보안 분석을 위한 Frida Python API 래퍼.
Brain이 LLM으로 Frida JS 훅 스크립트를 생성하여 런타임 계측 수행.

핵심 기능:
    1. 프로세스 어태치/스폰 — 실행 중인 프로세스 또는 새 프로세스 계측
    2. 스크립트 인젝션 — Frida JS를 타깃 프로세스에 주입
    3. 모듈 열거 — 로드된 라이브러리 목록 및 익스포트 함수 탐색
    4. 메모리 R/W — 프로세스 메모리 읽기/쓰기
    5. 함수 후킹 — 특정 함수 진입/이탈 시 콜백 등록
    6. Brain 통합 — LLM이 타깃 설명에 맞는 Frida JS 자동 생성

Architecture:
    FridaBridge
        ├── ProcessInfo (프로세스 메타데이터)
        ├── HookScript (후킹 스크립트 컨테이너)
        ├── HookResult (후킹 결과 + 수집 데이터)
        └── Brain integration (LLM 기반 자동 스크립트 생성)

Note:
    frida 패키지가 없으면 우아하게 비활성화.
    install: pip install frida frida-tools
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Frida import — optional dependency
try:
    import frida  # type: ignore[import-untyped]
    import frida.core  # type: ignore[import-untyped]
    _FRIDA_AVAILABLE = True
except ImportError:
    frida = None  # type: ignore[assignment]
    _FRIDA_AVAILABLE = False
    logger.debug("frida not installed — FridaBridge will operate in stub mode")


# ── Data Types ────────────────────────────────────────────────────


@dataclass
class ProcessInfo:
    """프로세스 메타데이터."""

    pid: int
    name: str
    identifier: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_frida(cls, proc: Any) -> "ProcessInfo":
        """frida.Process 객체에서 변환."""
        return cls(
            pid=proc.pid,
            name=proc.name,
            identifier=getattr(proc, "identifier", ""),
            parameters=getattr(proc, "parameters", {}),
        )


@dataclass
class ModuleInfo:
    """로드된 모듈(라이브러리) 정보."""

    name: str
    base_address: str
    size: int
    path: str
    exports: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class HookScript:
    """Frida JS 후킹 스크립트 컨테이너."""

    name: str
    js_code: str
    description: str = ""
    target_module: str = ""
    target_export: str = ""
    generated_by_brain: bool = False


@dataclass
class HookResult:
    """후킹 실행 결과 및 수집 데이터."""

    script_name: str
    success: bool
    messages: list[dict[str, Any]] = field(default_factory=list)
    captured_values: list[Any] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    raw_output: str = ""

    @property
    def message_count(self) -> int:
        return len(self.messages)

    def to_summary(self) -> dict[str, Any]:
        return {
            "script": self.script_name,
            "success": self.success,
            "messages": self.message_count,
            "captured": len(self.captured_values),
            "errors": self.errors,
            "duration": self.duration_seconds,
        }


# ── Core Frida Bridge ─────────────────────────────────────────────


class FridaBridge:
    """Frida Python API 래퍼 — 런타임 계측 인터페이스.

    Usage:
        bridge = FridaBridge()
        if not bridge.is_available:
            logger.warning("frida not installed")
            return

        await bridge.attach("com.example.game")
        modules = await bridge.enumerate_modules()
        result = await bridge.inject_script(HookScript(
            name="find_gold",
            js_code='''
                Interceptor.attach(Module.getExportByName(null, "getPlayerGold"), {
                    onLeave: function(retval) {
                        send({type: "gold", value: retval.toInt32()});
                    }
                });
            '''
        ))
        await bridge.detach()
    """

    def __init__(self, device_id: str | None = None) -> None:
        """
        Args:
            device_id: Frida 장치 ID. None이면 로컬 장치 사용.
                       원격/USB 연결: "usb" 또는 특정 장치 ID.
        """
        self.device_id = device_id
        self._device: Any = None
        self._session: Any = None
        self._scripts: list[Any] = []
        self._attached_pid: int | None = None
        self._attached_name: str = ""
        self._message_queue: list[dict[str, Any]] = []

    @property
    def is_available(self) -> bool:
        """Frida가 설치되어 있고 사용 가능한지 확인."""
        return _FRIDA_AVAILABLE

    @property
    def is_attached(self) -> bool:
        """현재 프로세스에 어태치된 상태인지 확인."""
        return self._session is not None

    def _get_device(self) -> Any:
        """Frida 장치 인스턴스 획득."""
        if not _FRIDA_AVAILABLE:
            raise RuntimeError("frida not installed. Run: pip install frida frida-tools")

        if self._device is None:
            if self.device_id is None or self.device_id == "local":
                self._device = frida.get_local_device()
            elif self.device_id == "usb":
                self._device = frida.get_usb_device(timeout=10)
            else:
                self._device = frida.get_device(self.device_id)

        return self._device

    async def enumerate_processes(self) -> list[ProcessInfo]:
        """실행 중인 프로세스 목록 열거."""
        if not _FRIDA_AVAILABLE:
            logger.warning("frida not available — cannot enumerate processes")
            return []

        try:
            device = self._get_device()
            loop = asyncio.get_event_loop()
            processes = await loop.run_in_executor(None, device.enumerate_processes)
            return [ProcessInfo.from_frida(p) for p in processes]
        except Exception as exc:
            logger.error("Failed to enumerate processes: %s", exc)
            return []

    async def attach(self, pid_or_name: int | str) -> bool:
        """실행 중인 프로세스에 어태치.

        Args:
            pid_or_name: 프로세스 PID(int) 또는 프로세스 이름/번들 ID(str).

        Returns:
            True if successfully attached.
        """
        if not _FRIDA_AVAILABLE:
            logger.warning("frida not available — attach is a no-op")
            return False

        try:
            device = self._get_device()
            loop = asyncio.get_event_loop()
            self._session = await loop.run_in_executor(
                None, device.attach, pid_or_name
            )
            if isinstance(pid_or_name, int):
                self._attached_pid = pid_or_name
                self._attached_name = str(pid_or_name)
            else:
                self._attached_name = str(pid_or_name)
                self._attached_pid = self._session.pid

            logger.info("Attached to process: %s (PID: %s)", self._attached_name, self._attached_pid)
            return True
        except Exception as exc:
            logger.error("Failed to attach to %s: %s", pid_or_name, exc)
            self._session = None
            return False

    async def spawn(self, binary: str, argv: list[str] | None = None) -> int | None:
        """새 프로세스를 스폰하고 어태치.

        Args:
            binary: 실행 파일 경로 또는 앱 번들 ID.
            argv: 커맨드라인 인수 목록.

        Returns:
            스폰된 프로세스의 PID, 실패 시 None.
        """
        if not _FRIDA_AVAILABLE:
            logger.warning("frida not available — spawn is a no-op")
            return None

        try:
            device = self._get_device()
            loop = asyncio.get_event_loop()

            pid = await loop.run_in_executor(
                None,
                lambda: device.spawn([binary] + (argv or [])),
            )
            self._session = await loop.run_in_executor(None, device.attach, pid)
            self._attached_pid = pid
            self._attached_name = binary

            logger.info("Spawned and attached to: %s (PID: %d)", binary, pid)
            return pid
        except Exception as exc:
            logger.error("Failed to spawn %s: %s", binary, exc)
            return None

    async def resume(self, pid: int | None = None) -> None:
        """스폰된 프로세스를 재개(resume). spawn() 후 호출 필요."""
        if not _FRIDA_AVAILABLE:
            return
        target_pid = pid or self._attached_pid
        if target_pid is None:
            return
        try:
            device = self._get_device()
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, device.resume, target_pid)
            logger.debug("Resumed PID %d", target_pid)
        except Exception as exc:
            logger.warning("Failed to resume PID %d: %s", target_pid, exc)

    async def inject_script(
        self,
        script: HookScript,
        collect_duration: float = 5.0,
        on_message: Callable[[dict[str, Any], bytes | None], None] | None = None,
    ) -> HookResult:
        """Frida JS 스크립트를 타깃 프로세스에 주입 + 실행.

        Args:
            script: 실행할 HookScript 인스턴스.
            collect_duration: 메시지 수집 대기 시간(초).
            on_message: 메시지 수신 시 커스텀 콜백.

        Returns:
            HookResult with collected messages and any errors.
        """
        if not _FRIDA_AVAILABLE or self._session is None:
            return HookResult(
                script_name=script.name,
                success=False,
                errors=["frida not available or not attached"],
            )

        result = HookResult(script_name=script.name, success=False)
        t0 = time.monotonic()

        try:
            loop = asyncio.get_event_loop()
            frida_script = await loop.run_in_executor(
                None, self._session.create_script, script.js_code
            )

            collected_messages: list[dict[str, Any]] = []

            def _on_message(message: dict[str, Any], data: bytes | None) -> None:
                collected_messages.append({"message": message, "data": data})
                if on_message:
                    on_message(message, data)
                if message.get("type") == "send":
                    payload = message.get("payload")
                    result.captured_values.append(payload)
                elif message.get("type") == "error":
                    result.errors.append(str(message.get("description", "")))

            frida_script.on("message", _on_message)

            await loop.run_in_executor(None, frida_script.load)
            self._scripts.append(frida_script)

            logger.info("Script '%s' loaded — collecting for %.1fs", script.name, collect_duration)
            await asyncio.sleep(collect_duration)

            result.messages = collected_messages
            result.success = True
            result.duration_seconds = time.monotonic() - t0

            logger.info(
                "Script '%s' done: %d messages, %d values captured",
                script.name, len(collected_messages), len(result.captured_values)
            )
            return result

        except Exception as exc:
            result.errors.append(str(exc))
            result.duration_seconds = time.monotonic() - t0
            logger.error("Script '%s' failed: %s", script.name, exc)
            return result

    async def enumerate_modules(self) -> list[ModuleInfo]:
        """현재 어태치된 프로세스의 로드된 모듈 목록.

        Returns:
            ModuleInfo 리스트 (라이브러리 이름, 베이스 주소, 크기 등).
        """
        if not _FRIDA_AVAILABLE or self._session is None:
            return []

        # JavaScript를 실행하여 모듈 목록 수집
        js_code = """
        var modules = Process.enumerateModules();
        var result = modules.map(function(m) {
            return {
                name: m.name,
                base: m.base.toString(),
                size: m.size,
                path: m.path
            };
        });
        send(result);
        """
        hook = HookScript(name="_enum_modules", js_code=js_code)
        hook_result = await self.inject_script(hook, collect_duration=2.0)

        modules: list[ModuleInfo] = []
        for val in hook_result.captured_values:
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        modules.append(ModuleInfo(
                            name=item.get("name", ""),
                            base_address=item.get("base", "0x0"),
                            size=item.get("size", 0),
                            path=item.get("path", ""),
                        ))

        logger.info("Enumerated %d modules", len(modules))
        return modules

    async def get_exports(self, module_name: str) -> list[dict[str, Any]]:
        """특정 모듈의 익스포트 함수 목록 반환.

        Args:
            module_name: 모듈 이름 (e.g., "libgame.so", "UnityEngine.dll").

        Returns:
            익스포트 함수 정보 딕셔너리 리스트.
        """
        if not _FRIDA_AVAILABLE or self._session is None:
            return []

        # module_name에서 따옴표 이스케이프
        safe_name = module_name.replace('"', '\\"')
        js_code = f"""
        try {{
            var exports = Module.enumerateExports("{safe_name}");
            send(exports.map(function(e) {{
                return {{
                    name: e.name,
                    type: e.type,
                    address: e.address.toString()
                }};
            }}));
        }} catch(e) {{
            send({{error: e.message}});
        }}
        """
        hook = HookScript(name=f"_enum_exports_{module_name}", js_code=js_code)
        result = await self.inject_script(hook, collect_duration=2.0)

        exports: list[dict[str, Any]] = []
        for val in result.captured_values:
            if isinstance(val, list):
                exports.extend(val)
            elif isinstance(val, dict) and "error" not in val:
                exports.append(val)

        return exports

    async def read_memory(self, address: str | int, size: int) -> bytes:
        """프로세스 메모리 읽기.

        Args:
            address: 메모리 주소 (16진수 문자열 "0x..." 또는 정수).
            size: 읽을 바이트 수.

        Returns:
            읽은 바이트 배열.
        """
        if not _FRIDA_AVAILABLE or self._session is None:
            return b""

        addr_str = hex(address) if isinstance(address, int) else address
        js_code = f"""
        try {{
            var buf = Memory.readByteArray(ptr("{addr_str}"), {size});
            send({{type: "memory_read", address: "{addr_str}", size: {size}}}, buf);
        }} catch(e) {{
            send({{error: e.message}});
        }}
        """
        collected_data: list[bytes] = []

        def _collect(message: dict[str, Any], data: bytes | None) -> None:
            if data is not None:
                collected_data.append(data)

        hook = HookScript(name=f"_read_mem_{addr_str}", js_code=js_code)
        await self.inject_script(hook, collect_duration=1.0, on_message=_collect)

        return collected_data[0] if collected_data else b""

    async def write_memory(self, address: str | int, data: bytes) -> bool:
        """프로세스 메모리 쓰기.

        Args:
            address: 쓸 메모리 주소.
            data: 쓸 바이트 데이터.

        Returns:
            True if successful.
        """
        if not _FRIDA_AVAILABLE or self._session is None:
            return False

        addr_str = hex(address) if isinstance(address, int) else address
        # 바이트 배열을 JS 배열 리터럴로 변환
        byte_array = "[" + ", ".join(str(b) for b in data) + "]"

        js_code = f"""
        try {{
            var addr = ptr("{addr_str}");
            Memory.protect(addr, {len(data)}, 'rwx');
            Memory.writeByteArray(addr, {byte_array});
            send({{success: true, address: "{addr_str}", bytes_written: {len(data)}}});
        }} catch(e) {{
            send({{success: false, error: e.message}});
        }}
        """
        hook = HookScript(name=f"_write_mem_{addr_str}", js_code=js_code)
        result = await self.inject_script(hook, collect_duration=1.0)

        for val in result.captured_values:
            if isinstance(val, dict) and val.get("success"):
                logger.info("Wrote %d bytes to %s", len(data), addr_str)
                return True

        logger.warning("Memory write failed at %s", addr_str)
        return False

    async def hook_function(
        self,
        module: str | None,
        export: str,
        on_enter_code: str = "",
        on_leave_code: str = "",
        collect_duration: float = 10.0,
    ) -> HookResult:
        """특정 함수 진입/이탈 시 후킹.

        Args:
            module: 모듈 이름. None이면 전체 프로세스에서 검색.
            export: 함수 익스포트 이름.
            on_enter_code: onEnter 콜백 JS 코드 본문.
            on_leave_code: onLeave 콜백 JS 코드 본문.
            collect_duration: 데이터 수집 대기 시간.

        Returns:
            HookResult with all captured data.
        """
        module_arg = f'"{module}"' if module else "null"
        safe_export = export.replace('"', '\\"')

        enter_body = on_enter_code or "send({type: 'enter', func: '" + safe_export + "', args: this.context});"
        leave_body = on_leave_code or "send({type: 'leave', func: '" + safe_export + "', retval: retval.toString()});"

        js_code = f"""
        try {{
            var targetFunc = Module.getExportByName({module_arg}, "{safe_export}");
            Interceptor.attach(targetFunc, {{
                onEnter: function(args) {{
                    {enter_body}
                }},
                onLeave: function(retval) {{
                    {leave_body}
                }}
            }});
            send({{type: "hook_installed", func: "{safe_export}", module: {module_arg}}});
        }} catch(e) {{
            send({{error: e.message, func: "{safe_export}"}});
        }}
        """
        hook = HookScript(
            name=f"hook_{export}",
            js_code=js_code,
            target_module=module or "",
            target_export=export,
        )
        return await self.inject_script(hook, collect_duration=collect_duration)

    async def scan_memory_pattern(
        self,
        pattern: str,
        protection: str = "r--",
    ) -> list[dict[str, Any]]:
        """메모리 패턴 스캔 (게임 치트 메모리 값 탐색용).

        Args:
            pattern: 16진수 패턴 문자열 (e.g., "FF ?? FF 00").
            protection: 메모리 보호 플래그 (r--, rw-, rwx).

        Returns:
            매치된 메모리 주소 리스트.
        """
        if not _FRIDA_AVAILABLE or self._session is None:
            return []

        safe_pattern = pattern.replace('"', '\\"')
        js_code = f"""
        var results = [];
        Process.enumerateRangesSync("{protection}").forEach(function(range) {{
            try {{
                var matches = Memory.scanSync(range.base, range.size, "{safe_pattern}");
                matches.forEach(function(m) {{
                    results.push({{
                        address: m.address.toString(),
                        size: m.size,
                        range_base: range.base.toString(),
                    }});
                }});
            }} catch(e) {{}}
        }});
        send(results);
        """
        hook = HookScript(name=f"_scan_{pattern[:16]}", js_code=js_code)
        result = await self.inject_script(hook, collect_duration=5.0)

        matches: list[dict[str, Any]] = []
        for val in result.captured_values:
            if isinstance(val, list):
                matches.extend(val)

        logger.info("Memory pattern '%s' found at %d locations", pattern, len(matches))
        return matches

    async def detach(self) -> None:
        """모든 스크립트 언로드 후 프로세스에서 분리."""
        if not _FRIDA_AVAILABLE:
            return

        # 모든 스크립트 언로드
        loop = asyncio.get_event_loop()
        for script in self._scripts:
            try:
                await loop.run_in_executor(None, script.unload)
            except Exception:
                pass
        self._scripts.clear()

        # 세션 분리
        if self._session is not None:
            try:
                await loop.run_in_executor(None, self._session.detach)
                logger.info("Detached from %s (PID: %s)", self._attached_name, self._attached_pid)
            except Exception as exc:
                logger.warning("Detach error: %s", exc)
            self._session = None
            self._attached_pid = None
            self._attached_name = ""

    async def generate_hook_script(
        self,
        brain: Any,
        target_description: str,
        module_name: str = "",
        function_name: str = "",
    ) -> HookScript:
        """Brain(LLM)을 사용하여 타깃 설명에 맞는 Frida JS 스크립트 자동 생성.

        Args:
            brain: VXIS Brain 인스턴스 (LLM 인터페이스).
            target_description: 후킹하고 싶은 것에 대한 자연어 설명.
            module_name: 타깃 모듈 이름 힌트 (선택).
            function_name: 타깃 함수 이름 힌트 (선택).

        Returns:
            Brain이 생성한 HookScript.
        """
        module_hint = f"\nTarget module: {module_name}" if module_name else ""
        function_hint = f"\nTarget function: {function_name}" if function_name else ""

        prompt = f"""You are a Frida instrumentation expert. Generate a Frida JavaScript script for the following task:

Task: {target_description}{module_hint}{function_hint}

Requirements:
1. Use Interceptor.attach() for hooking existing functions
2. Use send() to report findings back to Python
3. Handle exceptions with try/catch
4. Include onEnter and onLeave where appropriate
5. The script must be self-contained (no imports needed)
6. Focus on security-relevant data: return values, arguments, memory addresses
7. For game security: look for currency values, player stats, anti-cheat checks

Return ONLY the JavaScript code, no explanation, no markdown code blocks."""

        try:
            if hasattr(brain, "query"):
                js_code = await brain.query(prompt)
            elif hasattr(brain, "chat"):
                js_code = await brain.chat(prompt)
            else:
                js_code = _DEFAULT_HOOK_TEMPLATE.format(
                    description=target_description,
                    module=module_name or "null",
                    func=function_name or "unknown",
                )

            # 마크다운 코드 블록 제거
            js_code = js_code.strip()
            if js_code.startswith("```"):
                lines = js_code.split("\n")
                js_code = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

            script_name = f"brain_generated_{function_name or 'hook'}".replace(" ", "_")[:50]
            return HookScript(
                name=script_name,
                js_code=js_code,
                description=target_description,
                target_module=module_name,
                target_export=function_name,
                generated_by_brain=True,
            )

        except Exception as exc:
            logger.warning("Brain script generation failed: %s — using fallback template", exc)
            fallback_js = _DEFAULT_HOOK_TEMPLATE.format(
                description=target_description,
                module=f'"{module_name}"' if module_name else "null",
                func=function_name or "target_func",
            )
            return HookScript(
                name="fallback_hook",
                js_code=fallback_js,
                description=target_description,
                target_module=module_name,
                target_export=function_name,
                generated_by_brain=False,
            )


# ── Fallback Hook Template ────────────────────────────────────────


_DEFAULT_HOOK_TEMPLATE = """\
// Auto-generated Frida hook
// Task: {description}
try {{
    var targetModule = {module};
    var funcName = "{func}";

    if (funcName !== "target_func" && funcName !== "unknown") {{
        var funcAddr = Module.getExportByName(targetModule, funcName);
        Interceptor.attach(funcAddr, {{
            onEnter: function(args) {{
                send({{
                    type: "enter",
                    func: funcName,
                    arg0: args[0] ? args[0].toString() : null,
                    arg1: args[1] ? args[1].toString() : null,
                    arg2: args[2] ? args[2].toString() : null,
                }});
            }},
            onLeave: function(retval) {{
                send({{
                    type: "leave",
                    func: funcName,
                    retval: retval.toString()
                }});
            }}
        }});
        send({{type: "hook_installed", func: funcName}});
    }} else {{
        // Enumerate all modules and report
        var modules = Process.enumerateModules();
        send({{type: "modules", count: modules.length, names: modules.slice(0, 10).map(m => m.name)}});
    }}
}} catch(e) {{
    send({{type: "error", message: e.message}});
}}
"""
