"""JSON-backed payload provider for skills.

Replaces hardcoded PAYLOADS constants per ADR-007. Each skill has a
corresponding JSON file under ``vxis.data.payloads`` with this shape::

    {
      "schema_version": 1,
      "skill": "<name>",
      "rounds": {"1": [...], "2": [...], "3": [...]}
    }

Loading is cached at the module level — the scan lifetime caches enough.
Missing files fail loud so callers never silently degrade to an empty
payload set.
"""
from __future__ import annotations

import json
from functools import cache
from importlib import resources
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

SUPPORTED_SCHEMA_VERSIONS: set[int] = {1}


class PayloadDataMissingError(FileNotFoundError):
    """Raised when a skill's payload JSON file is missing or unloadable."""


class _PayloadFile(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: int
    skill: str
    # Rotation-aware payloads (test_injection, test_xss). Key is round number as str.
    rounds: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    # Non-rotation named datasets (creds, path lists, header checks, regex patterns, etc.).
    # ADR-007 Phase 3+: skills without round rotation use this instead of ``rounds``.
    datasets: dict[str, list[Any]] = Field(default_factory=dict)


class PayloadDatasetMissingError(KeyError):
    """Raised when a skill's JSON is present but the requested dataset key is not."""


@cache
def _load_file(skill_name: str) -> _PayloadFile:
    try:
        raw = resources.files("vxis.data.payloads").joinpath(f"{skill_name}.json").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError) as exc:
        raise PayloadDataMissingError(
            f"Payload JSON missing for skill={skill_name!r} — expected src/vxis/data/payloads/{skill_name}.json"
        ) from exc

    parsed = _PayloadFile.model_validate(json.loads(raw))
    if parsed.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(
            f"Unsupported schema_version={parsed.schema_version} in {skill_name}.json; "
            f"supported={sorted(SUPPORTED_SCHEMA_VERSIONS)}"
        )
    return parsed


def load_skill_payloads(skill_name: str, round_num: int) -> list[dict[str, Any]]:
    """Return the payload list for ``(skill_name, round_num)``.

    Round convention mirrors the legacy in-file ``_payloads_for_round``:

    * ``round_num`` in ``{1, 2, 3}`` → that round's payloads
    * ``round_num >= 4`` or ``<= 0`` → union of all rounds (exhaustive)
    """
    parsed = _load_file(skill_name)
    if round_num in (1, 2, 3):
        return list(parsed.rounds.get(str(round_num), []))
    merged: list[dict[str, Any]] = []
    for key in sorted(parsed.rounds.keys(), key=lambda s: int(s)):
        merged.extend(parsed.rounds[key])
    return merged


def load_skill_dataset(skill_name: str, dataset_key: str) -> list[Any]:
    """Return the non-rotation dataset list for ``(skill_name, dataset_key)``.

    Used by skills without round rotation (ADR-007 Phase 3+). Raises
    ``PayloadDatasetMissingError`` if the key is not present — fail-loud so
    callers never silently degrade to an empty list.
    """
    parsed = _load_file(skill_name)
    if dataset_key not in parsed.datasets:
        raise PayloadDatasetMissingError(
            f"Dataset key {dataset_key!r} missing in {skill_name}.json; "
            f"present keys: {sorted(parsed.datasets)}"
        )
    return list(parsed.datasets[dataset_key])


def clear_cache() -> None:
    """Invalidate the module-level cache. Tests fixing payload files use this."""
    _load_file.cache_clear()
