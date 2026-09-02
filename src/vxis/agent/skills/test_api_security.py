"""Skill: test_api_security — API authz, mass assignment, verb tampering."""
from __future__ import annotations
from typing import Any

import logging

from ._api_security_attack_loops import _run_mass_assignment_checks
from ._api_security_attack_loops import _run_protocol_checks
from ._api_security_surface_discovery import _discover_nextjs_admin_surface
from ._api_security_surface_discovery import _extract_discovered_privileged_candidates
from ._api_security_surface_discovery import _probe_action_read_bypass
from ._api_security_surface_discovery import _probe_graphql_surface
from ._api_security_surface_discovery import _probe_openapi_surface
from ._api_security_surface_discovery import _privileged_probe_candidates
from ._api_security_self_write import _extract_discovered_self_write_candidates
from ._api_security_self_write import _normalize_path
from ._api_security_self_write import _self_write_seed_values
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

MASS_ASSIGN_FIELDS = _load_ds("test_api_security", "mass_assign_fields")  # ADR-007 Phase 3-9 — data in data/payloads/test_api_security.json

VERB_TAMPER_PATHS = _load_ds("test_api_security", "verb_tamper_paths")  # ADR-007 Phase 3-9 — data in data/payloads/test_api_security.json

async def execute(target_url: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Test API security: mass assignment, rate limiting, verb tampering.

    Returns:
        {"vulnerable": bool, "findings": [...], "tested": int}
    """
    from vxis.interaction.hands import SessionManager

    target = target_url.rstrip("/")
    findings: list[dict[str, Any]] = []
    tested = 0
    nextjs_findings: list[dict[str, Any]] = []
    action_candidates: dict[str, set[str]] = {}
    graphql_candidates: list[dict[str, Any]] = []
    openapi_candidates: list[dict[str, Any]] = []

    auth_headers: dict[str, str] = {}
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)

    try:
        graphql_findings, graphql_candidates, graphql_tested = await _probe_graphql_surface(
            _session,
            target,
            auth_headers,
        )
        tested += graphql_tested
        findings.extend(graphql_findings)
    except Exception:
        logger.exception("GraphQL API surface probes failed")

    try:
        openapi_findings, openapi_candidates, openapi_tested = await _probe_openapi_surface(
            _session,
            target,
            auth_headers,
        )
        tested += openapi_tested
        findings.extend(openapi_findings)
    except Exception:
        logger.exception("OpenAPI API surface probes failed")

    try:
        nextjs_findings, action_candidates, nextjs_tested = await _discover_nextjs_admin_surface(
            _session,
            target,
        )
        tested += nextjs_tested
        findings.extend(nextjs_findings)
        action_findings, action_tested = await _probe_action_read_bypass(
            _session,
            target,
            action_candidates,
        )
        tested += action_tested
        findings.extend(action_findings)
    except Exception:
        logger.exception("Next.js/action API authorization probes failed")

    discovered_inputs = (
        list(kwargs.get("discovered_paths") or [])
        + list(kwargs.get("discovered_endpoints") or [])
        + list(kwargs.get("discovered_auth_only_endpoints") or [])
    )
    login_paths = [
        _normalize_path(str(path or "")).split("?", 1)[0]
        for path in list(kwargs.get("login_paths") or [])
        if str(path or "").strip()
    ]
    self_write_seed_values = _self_write_seed_values(
        discovered_inputs,
        kwargs.get("identities"),
        kwargs.get("credentials"),
    )
    discovered_candidates = _extract_discovered_privileged_candidates(discovered_inputs)
    self_write_candidates = _extract_discovered_self_write_candidates(
        discovered_inputs,
        seed_values=self_write_seed_values,
    )
    privileged_probe_paths = _privileged_probe_candidates(
        nextjs_findings,
        action_candidates,
        openapi_candidates=openapi_candidates,
        graphql_candidates=graphql_candidates,
        discovered_candidates=discovered_candidates,
    )
    mass_findings, mass_tested = await _run_mass_assignment_checks(
        _session,
        target=target,
        auth_headers=auth_headers,
        mass_assign_fields=MASS_ASSIGN_FIELDS,
        self_write_candidates=self_write_candidates,
        self_write_seed_values=self_write_seed_values,
        privileged_probe_paths=privileged_probe_paths,
        login_paths=login_paths,
        foothold_token=token,
        identities=kwargs.get("identities"),
    )
    findings.extend(mass_findings)
    tested += mass_tested

    protocol_findings, protocol_tested = await _run_protocol_checks(
        _session,
        target=target,
        auth_headers=auth_headers,
        verb_tamper_paths=VERB_TAMPER_PATHS,
    )
    findings.extend(protocol_findings)
    tested += protocol_tested

    return {"vulnerable": len(findings) > 0, "findings": findings, "tested": tested}
