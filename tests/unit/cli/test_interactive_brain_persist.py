"""Brain-selection persistence + API-key plausibility.

Saving an API key in the TUI must ALSO persist the provider/model selection, so
a later standalone ``vxis scan`` reuses the same Brain. Without this the wizard
saved only the key while the provider/model lived in process env only, so a
fresh process defaulted the director back to anthropic and the scan failed
preflight with "no Brain" even though the Google key was saved.

Plausibility: the wizard once accepted the target URL fat-fingered into the key
prompt (saved ``GOOGLE_API_KEY=http://localhost:3000``), which then silently
failed every Brain call. The key step now rejects obvious non-keys.
"""
import pytest

from vxis.cli import interactive


def test_persist_writes_key_and_full_selection(tmp_path, monkeypatch):
    store = tmp_path / ".env"
    # the wizard set these in os.environ via _configure_llm_environment (cloud)
    monkeypatch.setenv("UPSTREAM_LLM_PROVIDER", "gemini")
    monkeypatch.setenv("UPSTREAM_LLM_MODEL", "gemini-2.5-pro")
    monkeypatch.setenv("VXIS_DIRECTOR_LLM_PROVIDER", "gemini")
    monkeypatch.setenv("VXIS_DIRECTOR_LLM_MODEL", "gemini-2.5-pro")
    monkeypatch.setenv("VXIS_VERIFIER_LLM_PROVIDER", "gemini")
    monkeypatch.setenv("VXIS_VERIFIER_LLM_MODEL", "gemini-2.5-pro")

    interactive._persist_brain_selection("GOOGLE_API_KEY", "AIza-TESTKEY", path=store)

    text = store.read_text()
    assert "GOOGLE_API_KEY=AIza-TESTKEY" in text
    assert "UPSTREAM_LLM_PROVIDER=gemini" in text
    assert "UPSTREAM_LLM_MODEL=gemini-2.5-pro" in text
    assert "VXIS_DIRECTOR_LLM_PROVIDER=gemini" in text
    assert "VXIS_DIRECTOR_LLM_MODEL=gemini-2.5-pro" in text


def test_persist_skips_unset_brain_vars(tmp_path, monkeypatch):
    """Only persist brain env vars actually set — never write empty placeholders
    that would clobber resolution on the next load."""
    store = tmp_path / ".env"
    for k in (
        "UPSTREAM_LLM_PROVIDER", "UPSTREAM_LLM_MODEL",
        "VXIS_DIRECTOR_LLM_PROVIDER", "VXIS_DIRECTOR_LLM_MODEL",
        "VXIS_VERIFIER_LLM_PROVIDER", "VXIS_VERIFIER_LLM_MODEL",
    ):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("UPSTREAM_LLM_PROVIDER", "gemini")
    monkeypatch.setenv("UPSTREAM_LLM_MODEL", "gemini-2.5-pro")

    interactive._persist_brain_selection("GOOGLE_API_KEY", "k", path=store)

    text = store.read_text()
    assert "GOOGLE_API_KEY=k" in text
    assert "UPSTREAM_LLM_PROVIDER=gemini" in text
    assert "VXIS_DIRECTOR_LLM_PROVIDER=" not in text  # unset → not written


@pytest.mark.parametrize("value", [
    "http://localhost:3000",   # the actual fat-finger — target URL, not a key
    "https://example.com",
    "",
    "   ",
    "short",                   # too short to be a real key
    "has spaces in it not a key",
])
def test_rejects_implausible_api_keys(value):
    assert interactive._is_plausible_api_key(value) is False


@pytest.mark.parametrize("value", [
    "AIzaSyD-1234567890abcdefghijklmnopqrstuv",      # gemini-shaped
    "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234",   # anthropic-shaped
    "tgp_v1_abcdefghijklmnopqrstuvwxyz0123456789",   # together-shaped
])
def test_accepts_plausible_api_keys(value):
    assert interactive._is_plausible_api_key(value) is True
