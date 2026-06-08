from typer.testing import CliRunner

from vxis.cli.main import app

runner = CliRunner()


def test_eng_create_list_and_dry_run_emulate(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_P1_HOME", str(tmp_path))
    create = runner.invoke(
        app,
        [
            "eng",
            "create",
            "ACME-2026Q2",
            "--operator",
            "BAC",
            "--scope",
            "127.0.0.1",
            "--expiry",
            "2099-01-01",
            "--technique",
            "recon",
            "--attest",
        ],
    )
    assert create.exit_code == 0, create.output
    engagement_id = create.output.strip().split()[-1]

    listing = runner.invoke(app, ["eng", "list"])
    assert listing.exit_code == 0
    assert engagement_id in listing.output
    assert "BAC" in listing.output

    emulate = runner.invoke(
        app,
        ["emulate", "--eng", engagement_id, "--technique", "recon", "--target", "127.0.0.1"],
    )
    assert emulate.exit_code == 0, emulate.output
    assert "ALLOWED dry-run" in emulate.output


def test_p1_scan_profile_requires_engagement():
    result = runner.invoke(app, ["scan", "127.0.0.1", "--profile", "p1"])
    assert result.exit_code == 2
    assert "requires --engagement" in result.output
