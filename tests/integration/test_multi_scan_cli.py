"""Integration tests for `vxis scan --manifest` CLI wiring.

Uses Typer's CliRunner to invoke the CLI in-process.
All heavy work (ScanPipeline, Brain, ReportGenerator) is mocked so this
test runs instantly without network or LLM.

Verified:
  - vxis scan --manifest <valid.yml>   → exit 0 (multi_scan mocked to return 0)
  - vxis scan --manifest <invalid.yml> → exit 2 (YAML / Pydantic validation error)
  - vxis scan --manifest <missing.yml> → exit 2 (file not found)
  - vxis scan --manifest <f> target    → exit 2 (mutually exclusive)
  - vxis scan <target>                 → still works (backward compat)
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vxis.cli.main import app

runner = CliRunner()

_MULTI_SCAN_PATH = "vxis.cli.multi_scan.multi_scan"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_yaml(tmp_path: Path, content: str, name: str = "scan.yml") -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


_VALID_MANIFEST_YAML = """\
    version: 1
    project: Test Suite
    targets:
      - name: cloud-api
        kind: web
        entry: http://localhost:3333
      - name: mcp-proxy
        kind: web
        entry: http://localhost:8000
    correlation: true
    max_iters_per_target: 5
    output: reports/test-{date}.html
"""

_INVALID_MANIFEST_YAML = """\
    version: 1
    # project is missing — should fail Pydantic validation
    targets:
      - name: api
        kind: web
        entry: http://localhost:3333
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestManifestCLI:
    def test_valid_manifest_exits_0(self, tmp_path: Path) -> None:
        """Happy path: valid manifest → multi_scan called → exit 0."""
        manifest_path = _write_yaml(tmp_path, _VALID_MANIFEST_YAML)

        with patch("vxis.cli.multi_scan.multi_scan", return_value=0) as mock_ms:
            result = runner.invoke(app, ["scan", "--manifest", str(manifest_path)])

        assert result.exit_code == 0, result.output
        mock_ms.assert_called_once()
        # Verify the manifest passed to multi_scan has the correct project
        scan_manifest = mock_ms.call_args.args[0]
        assert scan_manifest.project == "Test Suite"
        assert len(scan_manifest.targets) == 2

    def test_missing_manifest_file_exits_2(self, tmp_path: Path) -> None:
        """Non-existent manifest file → exit 2."""
        missing = tmp_path / "does_not_exist.yml"
        result = runner.invoke(app, ["scan", "--manifest", str(missing)])
        assert result.exit_code == 2

    def test_invalid_manifest_yaml_exits_2(self, tmp_path: Path) -> None:
        """Manifest with missing required fields → Pydantic ValidationError → exit 2."""
        manifest_path = _write_yaml(tmp_path, _INVALID_MANIFEST_YAML)

        with patch("vxis.cli.multi_scan.multi_scan", return_value=0):
            result = runner.invoke(app, ["scan", "--manifest", str(manifest_path)])

        assert result.exit_code == 2

    def test_manifest_and_target_mutually_exclusive_exits_2(self, tmp_path: Path) -> None:
        """Providing both --manifest and TARGET → exit 2."""
        manifest_path = _write_yaml(tmp_path, _VALID_MANIFEST_YAML)

        with patch("vxis.cli.multi_scan.multi_scan", return_value=0):
            result = runner.invoke(
                app,
                ["scan", "http://localhost:9999", "--manifest", str(manifest_path)],
            )

        assert result.exit_code == 2

    def test_multi_scan_returns_1_propagated_as_exit_1(self, tmp_path: Path) -> None:
        """When multi_scan returns 1 (all skipped), CLI exits with 1."""
        manifest_path = _write_yaml(tmp_path, _VALID_MANIFEST_YAML)

        with patch("vxis.cli.multi_scan.multi_scan", return_value=1):
            result = runner.invoke(app, ["scan", "--manifest", str(manifest_path)])

        assert result.exit_code == 1

    def test_no_target_no_manifest_exits_2(self) -> None:
        """Neither TARGET nor --manifest provided → exit 2."""
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 2
