"""Unit tests for ScanManifest Pydantic schema.

Tests:
  - Valid manifest parses correctly with all required fields
  - Required field absence raises ValidationError
  - TargetKind enum is enforced
  - skip defaults to False
  - Empty targets list raises ValidationError
  - Duplicate target names raise ValidationError
  - version must be 1
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vxis.cli.manifest import ManifestTarget, ScanManifest
from vxis.interaction.surface import TargetKind


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _web_target(**overrides: object) -> dict:
    base: dict = {
        "name": "cloud-api",
        "kind": "web",
        "entry": "http://localhost:3333",
    }
    base.update(overrides)
    return base


def _desktop_target(**overrides: object) -> dict:
    base: dict = {
        "name": "studio",
        "kind": "desktop",
        "entry": "/Applications/ProtoPie Studio.app",
        "os": "macos",
    }
    base.update(overrides)
    return base


def _minimal_manifest(**overrides: object) -> dict:
    base: dict = {
        "version": 1,
        "project": "Test Suite",
        "targets": [_web_target()],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# ManifestTarget tests
# ---------------------------------------------------------------------------

class TestManifestTarget:
    def test_valid_web_target(self) -> None:
        t = ManifestTarget(**_web_target())
        assert t.name == "cloud-api"
        assert t.kind == TargetKind.WEB
        assert t.entry == "http://localhost:3333"
        assert t.os == "any"
        assert t.hints == {}
        assert t.skip is False

    def test_valid_desktop_target_with_os(self) -> None:
        t = ManifestTarget(**_desktop_target())
        assert t.kind == TargetKind.DESKTOP
        assert t.os == "macos"

    def test_skip_defaults_to_false(self) -> None:
        t = ManifestTarget(**_web_target())
        assert t.skip is False

    def test_skip_can_be_set_true(self) -> None:
        t = ManifestTarget(**_web_target(skip=True))
        assert t.skip is True

    def test_hints_default_empty_dict(self) -> None:
        t = ManifestTarget(**_web_target())
        assert isinstance(t.hints, dict)
        assert len(t.hints) == 0

    def test_hints_preserved(self) -> None:
        t = ManifestTarget(**_web_target(hints={"tech": "clojure-ring-reitit"}))
        assert t.hints["tech"] == "clojure-ring-reitit"

    def test_kind_enum_web(self) -> None:
        t = ManifestTarget(**_web_target(kind="web"))
        assert t.kind is TargetKind.WEB

    def test_kind_enum_code(self) -> None:
        t = ManifestTarget(**_web_target(kind="code", entry="/path/to/repo"))
        assert t.kind is TargetKind.CODE

    def test_invalid_kind_raises(self) -> None:
        with pytest.raises(ValidationError):
            ManifestTarget(**_web_target(kind="ftp"))

    def test_missing_name_raises(self) -> None:
        data = _web_target()
        del data["name"]
        with pytest.raises(ValidationError):
            ManifestTarget(**data)

    def test_missing_kind_raises(self) -> None:
        data = _web_target()
        del data["kind"]
        with pytest.raises(ValidationError):
            ManifestTarget(**data)

    def test_missing_entry_raises(self) -> None:
        data = _web_target()
        del data["entry"]
        with pytest.raises(ValidationError):
            ManifestTarget(**data)

    def test_empty_name_raises(self) -> None:
        with pytest.raises(ValidationError, match="name must not be empty"):
            ManifestTarget(**_web_target(name="   "))

    def test_empty_entry_raises(self) -> None:
        with pytest.raises(ValidationError, match="entry must not be empty"):
            ManifestTarget(**_web_target(entry="  "))

    def test_all_target_kinds_accepted(self) -> None:
        for kind in TargetKind:
            t = ManifestTarget(**_web_target(kind=kind.value, entry="/any"))
            assert t.kind == kind


# ---------------------------------------------------------------------------
# ScanManifest tests
# ---------------------------------------------------------------------------

class TestScanManifest:
    def test_valid_minimal_manifest(self) -> None:
        m = ScanManifest(**_minimal_manifest())
        assert m.project == "Test Suite"
        assert m.version == 1
        assert len(m.targets) == 1
        assert m.correlation is True
        assert "{date}" in m.output
        assert m.max_iters_per_target == 50

    def test_multiple_valid_targets(self) -> None:
        m = ScanManifest(**_minimal_manifest(targets=[
            _web_target(name="cloud-api"),
            _desktop_target(name="studio"),
            _web_target(name="mcp-proxy", entry="http://localhost:8000"),
        ]))
        assert len(m.targets) == 3

    def test_empty_targets_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanManifest(**_minimal_manifest(targets=[]))

    def test_duplicate_target_names_raise(self) -> None:
        with pytest.raises(ValidationError, match="Duplicate target names"):
            ScanManifest(**_minimal_manifest(targets=[
                _web_target(name="api"),
                _web_target(name="api", entry="http://localhost:4444"),
            ]))

    def test_version_must_be_1(self) -> None:
        with pytest.raises(ValidationError):
            ScanManifest(**_minimal_manifest(version=2))  # type: ignore[arg-type]

    def test_missing_project_raises(self) -> None:
        data = _minimal_manifest()
        del data["project"]
        with pytest.raises(ValidationError):
            ScanManifest(**data)

    def test_empty_project_raises(self) -> None:
        with pytest.raises(ValidationError, match="project must not be empty"):
            ScanManifest(**_minimal_manifest(project="  "))

    def test_correlation_default_true(self) -> None:
        m = ScanManifest(**_minimal_manifest())
        assert m.correlation is True

    def test_correlation_can_be_false(self) -> None:
        m = ScanManifest(**_minimal_manifest(correlation=False))
        assert m.correlation is False

    def test_max_iters_default(self) -> None:
        m = ScanManifest(**_minimal_manifest())
        assert m.max_iters_per_target == 50

    def test_max_iters_custom(self) -> None:
        m = ScanManifest(**_minimal_manifest(max_iters_per_target=30))
        assert m.max_iters_per_target == 30

    def test_max_iters_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanManifest(**_minimal_manifest(max_iters_per_target=0))

    def test_max_iters_over_500_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanManifest(**_minimal_manifest(max_iters_per_target=501))

    def test_output_template_default_contains_date(self) -> None:
        m = ScanManifest(**_minimal_manifest())
        assert "{date}" in m.output

    def test_skip_target_in_list(self) -> None:
        m = ScanManifest(**_minimal_manifest(targets=[
            _web_target(name="active"),
            _web_target(name="skipped", skip=True),
        ]))
        assert m.targets[1].skip is True

    def test_three_targets_unique_names_ok(self) -> None:
        """Regression: three distinct names must not raise."""
        m = ScanManifest(**_minimal_manifest(targets=[
            _web_target(name="a"),
            _web_target(name="b", entry="http://localhost:4000"),
            _web_target(name="c", entry="http://localhost:5000"),
        ]))
        assert len(m.targets) == 3
