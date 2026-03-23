"""Unit tests for Alembic migration configuration.

Verifies that:
  - The Alembic config can be loaded from alembic.ini.
  - All migration scripts in the versions directory are importable and
    structurally valid (have ``upgrade`` and ``downgrade`` callables).
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Root of the VXIS repository (three levels up from this test file).
REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"
VERSIONS_DIR = REPO_ROOT / "alembic" / "versions"


class TestAlembicConfig:
    """Ensure the Alembic configuration is loadable and well-formed."""

    def test_alembic_ini_exists(self) -> None:
        assert ALEMBIC_INI.is_file(), f"alembic.ini not found at {ALEMBIC_INI}"

    def test_config_loads(self) -> None:
        from alembic.config import Config

        cfg = Config(str(ALEMBIC_INI))
        script_location = cfg.get_main_option("script_location")
        assert script_location == "alembic"

    def test_script_directory_resolves(self) -> None:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        cfg = Config(str(ALEMBIC_INI))
        # ScriptDirectory needs the script_location relative to alembic.ini
        scripts = ScriptDirectory.from_config(cfg)
        # Should find at least the initial migration
        revisions = list(scripts.walk_revisions())
        assert len(revisions) >= 1, "Expected at least one migration revision"


class TestMigrationScripts:
    """Verify that individual migration scripts are importable and valid."""

    def test_initial_migration_importable(self) -> None:
        """The 001 initial schema migration must be importable."""
        import importlib.util

        script_path = VERSIONS_DIR / "001_initial_schema.py"
        assert script_path.is_file(), f"Initial migration not found: {script_path}"

        spec = importlib.util.spec_from_file_location("migration_001", script_path)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]

        # Every migration must expose upgrade() and downgrade().
        assert callable(getattr(module, "upgrade", None)), "upgrade() missing"
        assert callable(getattr(module, "downgrade", None)), "downgrade() missing"

        # Must have the standard revision identifiers.
        assert hasattr(module, "revision")
        assert hasattr(module, "down_revision")

    def test_all_versions_have_upgrade_downgrade(self) -> None:
        """Every .py file under alembic/versions/ must define upgrade/downgrade."""
        import importlib.util

        py_files = sorted(VERSIONS_DIR.glob("*.py"))
        assert py_files, "No migration scripts found in versions directory"

        for py_file in py_files:
            spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
            assert spec is not None, f"Cannot create import spec for {py_file}"
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore[union-attr]

            assert callable(getattr(module, "upgrade", None)), (
                f"{py_file.name}: upgrade() not found"
            )
            assert callable(getattr(module, "downgrade", None)), (
                f"{py_file.name}: downgrade() not found"
            )
