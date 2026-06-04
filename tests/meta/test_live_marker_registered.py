from __future__ import annotations

import pathlib
import tomllib


def test_live_marker_registered() -> None:
    data = tomllib.loads(pathlib.Path("pyproject.toml").read_text(encoding="utf-8"))
    markers = data["tool"]["pytest"]["ini_options"]["markers"]

    assert any(marker.startswith("live") for marker in markers)
