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
            clear=True,
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
            clear=True,
        ),
        patch("urllib.request.urlopen", return_value=_FakeResponse()),
    ):
        label, ready = check_brain(interactive=False)

    assert ready is True
    assert label == "local:ollama/qwen2.5-coder:14b"


def test_check_brain_accepts_local_llamacpp_provider() -> None:
    with (
        patch.dict(
            "os.environ",
            {
                "UPSTREAM_LLM_PROVIDER": "llamacpp",
                "UPSTREAM_LLM_MODEL": "huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-q4_k_m",
                "VXIS_LLAMACPP_BASE_URL": "http://localhost:8080",
            },
            clear=True,
        ),
        patch("urllib.request.urlopen", return_value=_FakeResponse()),
    ):
        label, ready = check_brain(interactive=False)

    assert ready is True
    assert label == "local:llamacpp/huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-q4_k_m"


def test_check_brain_normalizes_google_to_gemini() -> None:
    with patch.dict(
        "os.environ",
        {
            "UPSTREAM_LLM_PROVIDER": "google",
            "UPSTREAM_LLM_MODEL": "gemini-2.5-flash",
            "GOOGLE_API_KEY": "test-key",
        },
        clear=True,
    ):
        label, ready = check_brain(interactive=False)

    assert ready is True
    assert label == "api:gemini/gemini-2.5-flash"


def test_check_brain_promotes_frontier_director_when_local_worker_has_key() -> None:
    with patch.dict(
        "os.environ",
        {
            "UPSTREAM_LLM_PROVIDER": "llamacpp",
            "UPSTREAM_LLM_MODEL": "local-35b",
            "VXIS_LLAMACPP_BASE_URL": "http://localhost:8080",
            "OPENAI_API_KEY": "test-key",
        },
        clear=True,
    ):
        label, ready = check_brain(interactive=False)

    assert ready is True
    assert label == "api:openai/gpt-5.4"
