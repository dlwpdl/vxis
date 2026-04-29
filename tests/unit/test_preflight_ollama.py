from __future__ import annotations

from unittest.mock import patch

from vxis.cli.preflight import check_brain


class _FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_check_brain_accepts_local_ollama_provider() -> None:
    with (
        patch.dict(
            "os.environ",
            {
                "UPSTREAM_LLM_PROVIDER": "ollama",
                "UPSTREAM_LLM_MODEL": "qwen2.5-coder:14b",
                "VXIS_OLLAMA_BASE_URL": "http://localhost:11434",
            },
            clear=False,
        ),
        patch("urllib.request.urlopen", return_value=_FakeResponse()),
    ):
        label, ready = check_brain(interactive=False)

    assert ready is True
    assert label == "local:ollama/qwen2.5-coder:14b"


def test_check_brain_uses_default_ollama_model_when_not_set() -> None:
    with (
        patch.dict(
            "os.environ",
            {
                "UPSTREAM_LLM_PROVIDER": "ollama",
                "VXIS_OLLAMA_BASE_URL": "http://localhost:11434",
            },
            clear=False,
        ),
        patch("urllib.request.urlopen", return_value=_FakeResponse()),
    ):
        label, ready = check_brain(interactive=False)

    assert ready is True
    assert label == "local:ollama/qwen2.5-coder:14b"
