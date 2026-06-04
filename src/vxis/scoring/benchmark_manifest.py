"""Executable benchmark manifest loading for Benchmark League v2."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class BenchmarkManifestTarget:
    target_id: str
    target_type: str
    name: str
    default_url: str = ""
    url_env: str = ""
    required: bool = False
    enabled: bool = True

    def resolve_url(self, environ: dict[str, str] | None = None) -> str:
        env = environ if environ is not None else os.environ
        if self.url_env:
            value = env.get(self.url_env, "").strip()
            if value:
                return value
        return self.default_url.strip()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "target_type": self.target_type,
            "name": self.name,
            "default_url": self.default_url,
            "url_env": self.url_env,
            "required": self.required,
            "enabled": self.enabled,
        }


@dataclass(frozen=True, slots=True)
class BenchmarkManifest:
    league_id: str
    profile: str
    description: str
    targets: tuple[BenchmarkManifestTarget, ...]

    def select(
        self,
        *,
        target_type: str | None = None,
        target_id: str | None = None,
    ) -> tuple[BenchmarkManifestTarget, ...]:
        selected = [target for target in self.targets if target.enabled]
        if target_type:
            selected = [target for target in selected if target.target_type == target_type]
        if target_id:
            selected = [target for target in selected if target.target_id == target_id]
        return tuple(selected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "league_id": self.league_id,
            "profile": self.profile,
            "description": self.description,
            "targets": [target.to_dict() for target in self.targets],
        }


def load_benchmark_manifest(path: str | Path) -> BenchmarkManifest:
    manifest_path = Path(path)
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("benchmark manifest must be a JSON object")

    targets_raw = raw.get("targets")
    if not isinstance(targets_raw, list) or not targets_raw:
        raise ValueError("benchmark manifest must include at least one target")

    targets: list[BenchmarkManifestTarget] = []
    for index, item in enumerate(targets_raw):
        if not isinstance(item, dict):
            raise ValueError(f"targets[{index}] must be a JSON object")

        target_id = str(item.get("target_id", "")).strip()
        target_type = str(item.get("target_type", "")).strip()
        name = str(item.get("name", target_id)).strip()
        if not target_id:
            raise ValueError(f"targets[{index}].target_id is required")
        if not target_type:
            raise ValueError(f"targets[{index}].target_type is required")

        targets.append(
            BenchmarkManifestTarget(
                target_id=target_id,
                target_type=target_type,
                name=name or target_id,
                default_url=str(item.get("default_url", "")).strip(),
                url_env=str(item.get("url_env", "")).strip(),
                required=bool(item.get("required", False)),
                enabled=bool(item.get("enabled", True)),
            )
        )

    return BenchmarkManifest(
        league_id=str(raw.get("league_id", "")).strip() or manifest_path.stem,
        profile=str(raw.get("profile", "")).strip() or "crown",
        description=str(raw.get("description", "")).strip(),
        targets=tuple(targets),
    )


__all__ = [
    "BenchmarkManifest",
    "BenchmarkManifestTarget",
    "load_benchmark_manifest",
]
