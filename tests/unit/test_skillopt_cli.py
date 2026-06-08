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


def test_skillopt_help_documents_manual_flow():
    result = runner.invoke(app, ["skillopt", "--help"], env={"COLUMNS": "140"})

    assert result.exit_code == 0
    assert "prepare axis2" in result.output
    assert "train axis2" in result.output
    assert "apply axis2" in result.output
    assert "not a background daemon" in result.output


def test_skillopt_prepare_cli_prints_next_steps(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_SKILLOPT_HOME", str(tmp_path / "home"))
    cases = tmp_path / "cases.json"
    cases.write_text(
        json.dumps(
            [
                {"id": "one", "evidence": "login found", "expected_action": "run_skill attempt_auth"},
                {"id": "two", "evidence": "ids found", "expected_action": "run_skill test_idor"},
            ]
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["skillopt", "prepare", "axis2", "--cases", str(cases)])

    assert result.exit_code == 0, result.output
    assert "next: vxis skillopt train axis2 --dry-run" in result.output
    assert (tmp_path / "home" / "splits" / "axis2" / "train" / "items.json").exists()


def test_skillopt_train_dry_run_cli(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_SKILLOPT_HOME", str(tmp_path / "home"))

    result = runner.invoke(app, ["skillopt", "train", "axis2", "--epochs", "2", "--workers", "4"])

    assert result.exit_code == 0, result.output
    assert "command: python scripts/train.py --config" in result.output
    assert "train.num_epochs=2" in result.output
    assert "env.workers=4" in result.output
    assert "dry-run only" in result.output


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

    disabled = runner.invoke(app, ["skillopt", "disable", "axis2"])
    assert disabled.exit_code == 0
    assert "disabled axis2" in disabled.output

    listed_disabled = runner.invoke(app, ["skillopt", "list"])
    assert "inactive" in listed_disabled.output

    enabled = runner.invoke(app, ["skillopt", "enable", "axis2"])
    assert enabled.exit_code == 0
    assert "enabled axis2" in enabled.output
