from __future__ import annotations

import json
from pathlib import Path

from vxis.scoring.benchmark_cli import has_llm_api_key
from vxis.scoring.benchmark_manifest import load_benchmark_manifest


def test_load_benchmark_manifest_resolves_env_url(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "league_id": "test-league",
                "profile": "crown",
                "targets": [
                    {
                        "target_id": "juice-shop",
                        "target_type": "web",
                        "name": "Juice Shop",
                        "default_url": "http://localhost:3000",
                        "url_env": "VXIS_TEST_TARGET",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    manifest = load_benchmark_manifest(path)
    target = manifest.select(target_type="web")[0]

    assert manifest.league_id == "test-league"
    assert manifest.profile == "crown"
    assert target.resolve_url({"VXIS_TEST_TARGET": "http://127.0.0.1:3001"}) == (
        "http://127.0.0.1:3001"
    )
    assert target.resolve_url({}) == "http://localhost:3000"


def test_load_benchmark_manifest_filters_disabled_targets(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "targets": [
                    {"target_id": "enabled", "target_type": "web", "enabled": True},
                    {"target_id": "disabled", "target_type": "web", "enabled": False},
                ]
            }
        ),
        encoding="utf-8",
    )

    manifest = load_benchmark_manifest(path)

    assert [target.target_id for target in manifest.select(target_type="web")] == ["enabled"]


def test_has_llm_api_key_checks_supported_providers() -> None:
    assert has_llm_api_key({}) is False
    assert has_llm_api_key({"ANTHROPIC_API_KEY": "secret"}) is True
    assert has_llm_api_key({"GEMINI_API_KEY": "secret"}) is True
