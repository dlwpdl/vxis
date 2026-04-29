"""Scan manifest schema — multi-target scan definition.

A ScanManifest describes one or more targets to scan in sequence,
sharing a common scan_id prefix, producing a single merged report.

Invariants enforced by Pydantic:
  - targets must be non-empty
  - target names must be unique within a manifest
  - version must be 1 (forward-compat gate)
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from vxis.interaction.surface import TargetKind


class ManifestTarget(BaseModel):
    """A single target entry inside a ScanManifest."""

    name: str = Field(
        ...,
        description="Human label used in report sections and scan_id suffix.",
    )
    kind: TargetKind = Field(
        ...,
        description="Surface stack: web | desktop | mobile | game | code",
    )
    entry: str = Field(
        ...,
        description=(
            "Entry point shape depends on kind: "
            "web → URL, desktop → /path/to/App.app, "
            "mobile → /path/to/app.ipa, code → /path/to/dir"
        ),
    )
    os: Literal["linux", "windows", "macos", "ios", "android", "any"] = "any"
    hints: dict[str, str] = Field(
        default_factory=dict,
        description="Arbitrary key-value hints forwarded to Brain (e.g. tech: clojure-ring-reitit).",
    )
    skip: bool = Field(
        default=False,
        description="Skip this target during scan (staged rollout / surface not yet landed).",
    )

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ManifestTarget.name must not be empty")
        return v

    @field_validator("entry")
    @classmethod
    def entry_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ManifestTarget.entry must not be empty")
        return v


class ScanManifest(BaseModel):
    """Top-level multi-target scan manifest."""

    version: Literal[1] = 1
    project: str = Field(
        ...,
        description="Human label for the overall project (used in report title).",
    )
    targets: list[ManifestTarget] = Field(
        ...,
        min_length=1,
        description="Ordered list of targets. Must contain at least one entry.",
    )
    correlation: bool = Field(
        default=True,
        description=(
            "If True, run Phase-G CrossProtocolSynthesizer across all target "
            "findings after individual scans complete."
        ),
    )
    output: str = Field(
        default="reports/multi-{date}.html",
        description=(
            "Output path template. {date} is replaced with YYYY-MM-DD. "
            "Relative paths are resolved from cwd."
        ),
    )
    max_iters_per_target: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum Brain loop iterations per target.",
    )

    @field_validator("project")
    @classmethod
    def project_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ScanManifest.project must not be empty")
        return v

    @model_validator(mode="after")
    def unique_target_names(self) -> "ScanManifest":
        names = [t.name for t in self.targets]
        seen: set[str] = set()
        duplicates: list[str] = []
        for n in names:
            if n in seen:
                duplicates.append(n)
            seen.add(n)
        if duplicates:
            raise ValueError(
                f"Duplicate target names in manifest: {duplicates}. "
                "Each target.name must be unique."
            )
        return self
