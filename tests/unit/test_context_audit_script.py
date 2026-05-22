from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_context_audit_script():
    script = Path(__file__).resolve().parents[2] / "scripts" / "context_audit.py"
    spec = importlib.util.spec_from_file_location("context_audit_script", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_context_audit_script_reports_warnings_without_failing(tmp_path: Path, capsys) -> None:
    module = _load_context_audit_script()
    target = tmp_path / "oversized.py"
    target.write_text(("print('x')\n" * 50), encoding="utf-8")

    exit_code = module.main([
        str(tmp_path),
        "--max-file-lines",
        "10",
        "--max-file-tokens",
        "20",
        "--limit",
        "3",
    ])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Context audit" in out
    assert "oversized.py" in out
    assert "warnings=" in out


def test_context_audit_script_fail_on_warning_returns_nonzero(tmp_path: Path, capsys) -> None:
    module = _load_context_audit_script()
    target = tmp_path / "oversized.py"
    target.write_text(("print('x')\n" * 50), encoding="utf-8")

    exit_code = module.main([
        str(tmp_path),
        "--max-file-lines",
        "10",
        "--max-file-tokens",
        "20",
        "--fail-on-warning",
    ])

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "Top offenders" in out
    assert "lines>10" in out
