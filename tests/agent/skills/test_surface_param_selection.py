from __future__ import annotations

from vxis.agent.skills.test_infra import _seeded_git_env_paths
from vxis.agent.skills.test_ssrf import _ssrf_payloads_for_round
from vxis.agent.skills.test_ssrf import _fallback_params_for_url as _ssrf_fallback_params
from vxis.agent.skills.test_ssrf import _select_target_params as _select_ssrf_params
from vxis.agent.skills.test_xss import _fallback_params_for_url as _xss_fallback_params
from vxis.agent.skills.test_xss import _select_target_params as _select_xss_params


def test_xss_prefers_reflective_params_before_generic_ones() -> None:
    params, _parsed_params, _parsed = _select_xss_params(
        "https://example.com/search?page=1&q=test&message=hello"
    )
    assert params[:2] == ["q", "message"]


def test_ssrf_prefers_url_like_params_before_generic_ones() -> None:
    params, _parsed_params, _parsed = _select_ssrf_params(
        "https://example.com/fetch?page=1&redirect=%2Fhome&url=http://example.com"
    )
    assert params[:2] == ["url", "redirect"]


def test_xss_fallback_params_follow_redirect_context() -> None:
    assert _xss_fallback_params("https://example.com/redirect")[:2] == ["returnUrl", "redirect"]


def test_ssrf_fallback_params_follow_proxy_context() -> None:
    assert _ssrf_fallback_params("https://example.com/proxy/import")[:2] == ["url", "uri"]


def test_ssrf_payload_rounds_partition_dataset() -> None:
    assert len(_ssrf_payloads_for_round(1)) == 8
    assert len(_ssrf_payloads_for_round(2)) == 8
    assert len(_ssrf_payloads_for_round(3)) == 4
    assert len(_ssrf_payloads_for_round(4)) == 20


def test_infra_seed_paths_expand_to_nested_git_and_env_targets() -> None:
    expanded = _seeded_git_env_paths([
        "/ftp/acme.md",
        "https://example.com/releases/build.env",
    ])
    paths = {path for path, _signature in expanded}
    assert "/ftp/.git/config" in paths
    assert "/ftp/.env" in paths
    assert "/releases/build.env" in paths
