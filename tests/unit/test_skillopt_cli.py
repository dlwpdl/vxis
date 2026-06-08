from __future__ import annotations

import json

from typer.testing import CliRunner

from vxis.cli.main import app

runner = CliRunner()


def test_skillopt_export_cli(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_SKILLOPT_HOME", str(tmp_path / "home"))
    cases = tmp_path / "cases.json"
    cases.write_text(
        json.dumps(
            [
                {"id": "one", "evidence": "login found", "expected_action": "run_skill attempt_auth"},
                {"id": "two", "evidence": "ids found", "expected_action": "run_skill test_idor"},
                {"id": "three", "evidence": "ssrf hint", "expected_action": "run_skill test_ssrf"},
            ]
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["skillopt", "export", str(cases), "--out", str(tmp_path / "split")])

    assert result.exit_code == 0, result.output
    assert "exported 3 case" in result.output
    assert (tmp_path / "split" / "train" / "items.json").exists()


def test_skillopt_import_and_list_cli(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_SKILLOPT_HOME", str(tmp_path / "home"))
    best = tmp_path / "best_skill.md"
    best.write_text("# Best\n\nUse object ownership maps.", encoding="utf-8")

    imported = runner.invoke(
        app,
        [
            "skillopt",
            "import",
            str(best),
            "--name",
            "axis2",
            "--families",
            "access_control,chain",
            "--roles",
            "director,post_exploit_worker",
        ],
    )
    assert imported.exit_code == 0, imported.output
    assert "imported optimized skill axis2" in imported.output

    listed = runner.invoke(app, ["skillopt", "list"])
    assert listed.exit_code == 0
    assert "axis2" in listed.output
    assert "active" in listed.output
