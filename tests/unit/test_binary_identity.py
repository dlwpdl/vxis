"""Identity-gated plugin binary resolution.

A same-named binary on PATH that isn't the real tool (the Python `httpx` CLI
shadowing ProjectDiscovery httpx) must be rejected so the plugin is skipped
cleanly instead of dying on a cryptic non-zero exit mid-scan.
"""

from types import SimpleNamespace

import vxis.plugins.base as base
from vxis.plugins.recon.httpx_plugin import HttpxPlugin


def _fake_run(marker_paths: set[str]):
    """subprocess.run stub: only `marker_paths` emit the PD identity banner."""

    def run(cmd, **_kw):
        out = "projectdiscovery.io" if cmd[0] in marker_paths else "Usage: httpx [OPTIONS] URL"
        return SimpleNamespace(stdout=out, stderr="", returncode=0)

    return run


def test_rejects_wrong_httpx(monkeypatch):
    monkeypatch.setattr(base.shutil, "which", lambda n: "/usr/bin/httpx" if n == "httpx" else None)
    monkeypatch.setattr(base.subprocess, "run", _fake_run(marker_paths=set()))
    assert HttpxPlugin().resolve_binary() is None
    assert HttpxPlugin().validate_environment() is False


def test_accepts_pd_httpx_via_alias(monkeypatch):
    paths = {"httpx": "/opt/anaconda3/bin/httpx", "httpx-pd": "/root/go/bin/httpx-pd"}
    monkeypatch.setattr(base.shutil, "which", lambda n: paths.get(n))
    monkeypatch.setattr(base.subprocess, "run", _fake_run(marker_paths={"/root/go/bin/httpx-pd"}))
    assert HttpxPlugin().resolve_binary() == "/root/go/bin/httpx-pd"
    assert HttpxPlugin().validate_environment() is True


if __name__ == "__main__":
    import sys

    import pytest

    sys.exit(pytest.main([__file__, "-q"]))
