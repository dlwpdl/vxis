"""Platform runtime launcher abstraction for ScanPipelineV2.

The scan core should not need to know whether a target is a web URL, a local
desktop app bundle, or a code repository. This module normalizes supported
target entries and returns runtime metadata. Unsupported future surfaces fail
closed here instead of pretending placeholder runtimes are available.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vxis.interaction.surface import TargetKind


@dataclass
class RuntimeLaunch:
    """Prepared runtime envelope for a target before the scan loop starts."""

    kind: TargetKind
    original_target: str
    resolved_target: str
    launcher_name: str
    runtime_mode: str
    metadata: dict[str, Any] = field(default_factory=dict)
    shared_notes: list[str] = field(default_factory=list)


class BaseTargetLauncher:
    """Launcher contract. Current implementations are mostly normalizers."""

    launcher_name = "base"
    runtime_mode = "direct"

    async def prepare(self, target: str, kind: TargetKind, hints: dict[str, str] | None = None) -> RuntimeLaunch:
        return RuntimeLaunch(
            kind=kind,
            original_target=target,
            resolved_target=target,
            launcher_name=self.launcher_name,
            runtime_mode=self.runtime_mode,
            metadata={"hints": dict(hints or {})},
        )


class WebTargetLauncher(BaseTargetLauncher):
    launcher_name = "web_direct"
    runtime_mode = "http_target"

    async def prepare(self, target: str, kind: TargetKind, hints: dict[str, str] | None = None) -> RuntimeLaunch:
        resolved = target.strip()
        hint_map = dict(hints or {})
        notes: list[str] = []
        metadata: dict[str, Any] = {
            "transport": "http",
            "hints": hint_map,
            "docker_cli_available": shutil.which("docker") is not None,
        }
        parsed = urlparse(resolved)
        host = (parsed.hostname or "").lower()
        is_local = host in {"localhost", "127.0.0.1", "0.0.0.0"} or resolved.startswith("http://localhost")
        if is_local:
            metadata["local_target"] = True
        runtime_mode = self.runtime_mode
        launcher_name = self.launcher_name
        if hint_map.get("launcher") in {"docker", "compose"} or hint_map.get("compose_file") or is_local:
            runtime_mode = "docker_local_target"
            launcher_name = "web_docker_aware"
            notes.append("launcher:web target looks local/containerized; docker-aware runtime metadata enabled.")
            if hint_map.get("compose_file"):
                metadata["compose_file"] = hint_map["compose_file"]
            if hint_map.get("service"):
                metadata["service"] = hint_map["service"]
        if resolved.startswith(("http://", "https://")):
            metadata["entrypoint"] = resolved
        else:
            metadata["entrypoint"] = resolved
            notes.append("launcher:web target has no explicit scheme; scan loop will use the provided target verbatim.")
        return RuntimeLaunch(
            kind=kind,
            original_target=target,
            resolved_target=resolved,
            launcher_name=launcher_name,
            runtime_mode=runtime_mode,
            metadata=metadata,
            shared_notes=notes,
        )


class DesktopTargetLauncher(BaseTargetLauncher):
    launcher_name = "desktop_local"
    runtime_mode = "local_process"

    async def prepare(self, target: str, kind: TargetKind, hints: dict[str, str] | None = None) -> RuntimeLaunch:
        resolved_path = str(Path(target).expanduser().resolve())
        metadata = {
            "entrypoint": resolved_path,
            "path_exists": Path(resolved_path).exists(),
            "hints": dict(hints or {}),
        }
        notes = [
            "launcher:desktop target prepared as a local app/binary path; browser-first web probes should stay disabled."
        ]
        return RuntimeLaunch(
            kind=kind,
            original_target=target,
            resolved_target=resolved_path,
            launcher_name=self.launcher_name,
            runtime_mode=self.runtime_mode,
            metadata=metadata,
            shared_notes=notes,
        )


class CodeTargetLauncher(BaseTargetLauncher):
    launcher_name = "code_workspace"
    runtime_mode = "repo_workspace"

    async def prepare(self, target: str, kind: TargetKind, hints: dict[str, str] | None = None) -> RuntimeLaunch:
        resolved_path = str(Path(target).expanduser().resolve())
        metadata = {
            "entrypoint": resolved_path,
            "path_exists": Path(resolved_path).exists(),
            "hypothesis_only": True,
            "hints": dict(hints or {}),
        }
        notes = [
            "launcher:code target is read-only hypothesis input until a dynamic surface confirms any issue."
        ]
        return RuntimeLaunch(
            kind=kind,
            original_target=target,
            resolved_target=resolved_path,
            launcher_name=self.launcher_name,
            runtime_mode=self.runtime_mode,
            metadata=metadata,
            shared_notes=notes,
        )


_LAUNCHERS: dict[TargetKind, BaseTargetLauncher] = {
    TargetKind.WEB: WebTargetLauncher(),
    TargetKind.DESKTOP: DesktopTargetLauncher(),
    TargetKind.CODE: CodeTargetLauncher(),
}


async def prepare_target_runtime(
    target: str,
    kind: TargetKind,
    hints: dict[str, str] | None = None,
) -> RuntimeLaunch:
    launcher = _LAUNCHERS.get(kind)
    if launcher is None:
        raise NotImplementedError(
            f"{kind.value} target runtime is not production-wired; keep it under incubator/ "
            "until a real launcher and execution tests exist."
        )
    return await launcher.prepare(target, kind, hints=hints)
