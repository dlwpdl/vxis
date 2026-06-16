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
        "VXIS_WORKER_LLM_PROVIDER",
        "VXIS_WORKER_LLM_MODEL",
        "VXIS_WORKER_LLM_BASE_URL",
        "VXIS_SUMMARIZER_LLM_PROVIDER",
        "VXIS_SUMMARIZER_LLM_MODEL",
        "VXIS_SUMMARIZER_LLM_BASE_URL",
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
        assert os.environ["VXIS_WORKER_LLM_PROVIDER"] == "llamacpp"
        assert os.environ["VXIS_WORKER_LLM_MODEL"] == "local-model"
        assert os.environ["VXIS_WORKER_LLM_BASE_URL"] == "http://127.0.0.1:8080"
        assert os.environ["VXIS_SUMMARIZER_LLM_PROVIDER"] == "llamacpp"
        assert os.environ["VXIS_SUMMARIZER_LLM_MODEL"] == "local-model"
        assert os.environ["VXIS_SUMMARIZER_LLM_BASE_URL"] == "http://127.0.0.1:8080"
    finally:
        for key in keys:
            os.environ.pop(key, None)


def test_configure_cloud_environment_sets_director_and_verifier(monkeypatch) -> None:
    keys = [
        "UPSTREAM_LLM_PROVIDER",
        "UPSTREAM_LLM_MODEL",
        "VXIS_DIRECTOR_LLM_PROVIDER",
        "VXIS_DIRECTOR_LLM_MODEL",
        "VXIS_VERIFIER_LLM_PROVIDER",
        "VXIS_VERIFIER_LLM_MODEL",
    ]
    for key in keys:
        monkeypatch.delenv(key, raising=False)

    try:
        base_url = interactive._configure_llm_environment("openai", "gpt-5.4")

        assert base_url == ""
        assert os.environ["UPSTREAM_LLM_PROVIDER"] == "openai"
        assert os.environ["UPSTREAM_LLM_MODEL"] == "gpt-5.4"
        assert os.environ["VXIS_DIRECTOR_LLM_PROVIDER"] == "openai"
        assert os.environ["VXIS_DIRECTOR_LLM_MODEL"] == "gpt-5.4"
        assert os.environ["VXIS_VERIFIER_LLM_PROVIDER"] == "openai"
        assert os.environ["VXIS_VERIFIER_LLM_MODEL"] == "gpt-5.4"
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


# ── NOW-3 #3: parallel/serial agent-execution toggle ──
class TestExecModeToConcurrency:
    def test_serial_is_one_worker(self):
        assert interactive._exec_mode_to_concurrency("serial") == 1

    def test_parallel_is_multiple_workers(self):
        assert interactive._exec_mode_to_concurrency("parallel") == 4

    def test_unknown_or_blank_defaults_serial(self):
        # fail-safe to serial (deterministic, low resource)
        assert interactive._exec_mode_to_concurrency("") == 1
        assert interactive._exec_mode_to_concurrency("bogus") == 1

    def test_case_insensitive(self):
        assert interactive._exec_mode_to_concurrency("PARALLEL") == 4


# ── NOW-3 #2 residual: full profile parity — specialized profile picker ──
class TestSpecializedProfileChoices:
    def test_includes_vc_and_enterprise_profiles(self):
        vals = {c["value"] for c in interactive._specialized_profile_choices()}
        assert "vc-portfolio-monitor" in vals  # the user's "VC"
        assert "pre-investment-dd" in vals
        assert "compliance-mapping" in vals

    def test_excludes_primary_and_engagement_profiles(self):
        vals = {c["value"] for c in interactive._specialized_profile_choices()}
        # primary-4 live in the simple selector, not here
        assert "crown" not in vals and "passive" not in vals
        # p1-adversary-emulation needs the P1 engagement CLI workflow
        assert "p1-adversary-emulation" not in vals

    def test_all_values_are_real_profiles(self):
        from vxis.agent.policy.scan_policy import PROFILE_POLICY_TABLE

        for c in interactive._specialized_profile_choices():
            assert c["value"] in PROFILE_POLICY_TABLE

    def test_labels_carry_attack_badge_and_korean(self):
        choices = interactive._specialized_profile_choices()
        vc = next(c for c in choices if c["value"] == "vc-portfolio-monitor")
        assert "VC" in vc["name"]
        assert "공격력" in vc["name"]
        assert "●" in vc["name"] or "○" in vc["name"]
