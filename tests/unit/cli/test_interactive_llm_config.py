from __future__ import annotations

import os
from unittest.mock import patch

from vxis.cli import interactive


class _FakeResponse:
    status = 200

    def __init__(self, body: bytes = b'{"data": []}') -> None:
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self._body


def test_configure_llamacpp_environment(monkeypatch) -> None:
    keys = [
        "UPSTREAM_LLM_PROVIDER",
        "UPSTREAM_LLM_MODEL",
        "VXIS_LLAMACPP_BASE_URL",
        "VXIS_LLAMACPP_MODEL",
    ]
    for key in keys:
        monkeypatch.delenv(key, raising=False)

    try:
        base_url = interactive._configure_llm_environment(
            "llamacpp",
            "local-model",
            "http://127.0.0.1:8080/",
        )

        assert base_url == "http://127.0.0.1:8080"
        assert os.environ["UPSTREAM_LLM_PROVIDER"] == "llamacpp"
        assert os.environ["UPSTREAM_LLM_MODEL"] == "local-model"
        assert os.environ["VXIS_LLAMACPP_BASE_URL"] == "http://127.0.0.1:8080"
        assert os.environ["VXIS_LLAMACPP_MODEL"] == "local-model"
    finally:
        for key in keys:
            os.environ.pop(key, None)


def test_fetch_llamacpp_models_from_openai_compatible_endpoint() -> None:
    body = b'{"data": [{"id": "model-a"}, {"id": "model-b"}]}'

    with patch("urllib.request.urlopen", return_value=_FakeResponse(body)) as urlopen:
        models = interactive._fetch_llamacpp_models("http://localhost:8080")

    assert models == ["model-a", "model-b"]
    assert urlopen.call_args.args[0].full_url == "http://localhost:8080/v1/models"


def test_default_llamacpp_base_url_prefers_compact_proxy(monkeypatch) -> None:
    monkeypatch.delenv("VXIS_LLAMACPP_BASE_URL", raising=False)

    with patch.object(interactive, "_fetch_json_url", return_value={"data": []}) as fetch:
        assert interactive._default_llamacpp_base_url() == "http://127.0.0.1:8090"

    fetch.assert_called_once_with("http://127.0.0.1:8090/v1/models", timeout=0.4)


def test_default_llamacpp_context_uses_health_ctx_size(monkeypatch) -> None:
    monkeypatch.delenv("VXIS_LLAMACPP_CONTEXT", raising=False)

    assert interactive._default_llamacpp_context({"ctx_size": 8192}) == 8192


def test_default_llamacpp_context_falls_back_to_8192(monkeypatch) -> None:
    monkeypatch.delenv("VXIS_LLAMACPP_CONTEXT", raising=False)

    assert interactive._default_llamacpp_context({}) == 8192


def test_default_llamacpp_context_env_wins(monkeypatch) -> None:
    monkeypatch.setenv("VXIS_LLAMACPP_CONTEXT", "16384")

    assert interactive._default_llamacpp_context({"ctx_size": 8192}) == 16384


def test_check_local_llm_ready_uses_llamacpp_models_endpoint() -> None:
    with patch("urllib.request.urlopen", return_value=_FakeResponse()) as urlopen:
        ready, message = interactive._check_local_llm_ready(
            "llamacpp",
            "http://localhost:8080",
        )

    assert ready is True
    assert "llamacpp reachable" in message
    assert urlopen.call_args.args[0].full_url == "http://localhost:8080/v1/models"
