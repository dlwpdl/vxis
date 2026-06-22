"""infer_target_kind — branch Agent Mode on the raw target string.

Regression: Agent Mode treated every target as a web URL (kind defaulted to
WEB / was hardcoded), so a repo path like ~/Desktop/Git/cloud-api failed
preflight's URL-reachability check with a confusing error. A path must be
recognized as a CODE target (Strix accepts `--target ./dir` as a normal flow);
a .app/binary as DESKTOP; a github/gitlab repo URL as CODE; everything else
(bare domain / IP / CIDR / other URL) stays WEB.
"""

from __future__ import annotations

from vxis.interaction.surface import TargetKind
from vxis.pipeline.launcher import infer_target_kind


def test_http_url_is_web():
    assert infer_target_kind("http://localhost:3000") == TargetKind.WEB
    assert infer_target_kind("https://app.example.com/login") == TargetKind.WEB


def test_bare_domain_ip_cidr_is_web():
    assert infer_target_kind("example.com") == TargetKind.WEB
    assert infer_target_kind("10.0.0.5") == TargetKind.WEB
    assert infer_target_kind("10.0.0.0/24") == TargetKind.WEB
    assert infer_target_kind("localhost:3333") == TargetKind.WEB


def test_github_gitlab_repo_url_is_code():
    assert infer_target_kind("https://github.com/owner/repo") == TargetKind.CODE
    assert infer_target_kind("https://gitlab.com/owner/repo") == TargetKind.CODE


def test_existing_directory_is_code(tmp_path):
    assert infer_target_kind(str(tmp_path)) == TargetKind.CODE


def test_pathlike_nonexistent_is_code():
    assert infer_target_kind("/no/such/repo/here") == TargetKind.CODE
    assert infer_target_kind("~/no_such_vxis_dir_xyz") == TargetKind.CODE
    assert infer_target_kind("./relative/repo") == TargetKind.CODE
    assert infer_target_kind("../sibling/repo") == TargetKind.CODE


def test_macos_app_bundle_is_desktop(tmp_path):
    app = tmp_path / "MyApp.app"
    app.mkdir()
    assert infer_target_kind(str(app)) == TargetKind.DESKTOP


def test_executable_file_is_desktop(tmp_path):
    binf = tmp_path / "tool"
    binf.write_text("#!/bin/sh\necho hi\n")
    binf.chmod(0o755)
    assert infer_target_kind(str(binf)) == TargetKind.DESKTOP


def test_blank_target_defaults_web():
    assert infer_target_kind("") == TargetKind.WEB
    assert infer_target_kind("   ") == TargetKind.WEB
