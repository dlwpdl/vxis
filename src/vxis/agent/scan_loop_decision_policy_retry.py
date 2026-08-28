from __future__ import annotations

import logging
import re
from typing import Any, Callable
from urllib.parse import urlparse

from vxis.agent.scan_loop_state import VectorCandidate

logger = logging.getLogger("vxis.agent.scan_loop_decision_policy")


class ScanLoopDecisionPolicyRetryMixin:
    def _next_retry_round(
        self, skill_name: str, candidate: VectorCandidate | None = None
    ) -> int | None:
        skill = str(skill_name).strip().lower()
        if skill not in {"test_injection", "test_xss", "test_ssrf"}:
            return None
        seen_round = 1
        if candidate is not None:
            match = re.search(r"round\s+(\d+)", str(candidate.last_summary or ""), re.IGNORECASE)
            if match:
                seen_round = max(seen_round, int(match.group(1)))
        for message in self.state.messages[-48:]:
            if message.get("role") != "tool":
                continue
            content = message.get("content", {})
            if not isinstance(content, dict) or content.get("name") != "run_skill":
                continue
            args = content.get("args", {})
            if not isinstance(args, dict):
                continue
            if str(args.get("skill") or "").strip().lower() != skill:
                continue
            params = args.get("params", {})
            if isinstance(params, dict):
                round_value = params.get("round", 1)
                try:
                    seen_round = max(seen_round, int(round_value))
                except (TypeError, ValueError):
                    logger.debug("ignoring non-integer retry round for %s: %r", skill, round_value)
        return min(seen_round + 1, 3)

    def _run_skill_action(
        self,
        requested_skill: str,
        *,
        target: str,
        hint_blob: str = "",
        params: dict[str, Any] | None = None,
        retry_candidate: VectorCandidate | None = None,
    ) -> tuple[str, dict[str, Any]] | None:
        skill = self._pivoted_skill_name(requested_skill)
        if not skill:
            return None
        action_params = (
            dict(params)
            if params is not None
            else self._best_skill_params(skill, hint_blob=hint_blob)
        )
        if retry_candidate is not None and retry_candidate.status == "retryable":
            next_round = self._next_retry_round(skill, retry_candidate)
            if next_round is not None:
                action_params["round"] = next_round
        if skill == "attempt_auth" and not action_params:
            action_params = {}
        return ("run_skill", {"skill": skill, "target_url": target, "params": action_params})

    def _forced_candidate_action(
        self, candidate: VectorCandidate
    ) -> tuple[str, dict[str, Any]] | None:
        allowed = self._platform_allowed_skills()
        if "run_skill" not in self.registry.list_tools() or not allowed:
            return None
        blob = f"{candidate.vector_id} {candidate.title} {candidate.evidence}".lower()
        target = str(self.state.target)
        kind = self._target_kind_name()
        family = self._candidate_family(candidate)
        if kind == "desktop":
            for tokens, skills in (
                (("secret", "storage", "keychain", "token"), ("test_local_storage_secrets",)),
                (("deep", "link", "url", "scheme"), ("test_deeplink_abuse",)),
                (("signature", "trust", "entitlement", "binary"), ("test_signature_audit",)),
                ((), ("test_ipc_injection", "test_binary_protections")),
            ):
                if tokens and not any(token in blob for token in tokens):
                    continue
                for requested in skills:
                    action = self._run_skill_action(
                        requested, target=target, hint_blob=blob, params={}
                    )
                    if action is not None:
                        return action
            return None
        if kind != "web":
            return None
        family_skill_map = {
            "auth": "attempt_auth",
            "idor": "test_idor",
            "injection": "test_injection",
            "xss": "test_xss",
            "ssrf": "test_ssrf",
            "disclosure": "test_sensitive_files",
            "infra": "enumerate_endpoints",
        }
        family_skill = family_skill_map.get(family)
        if family_skill:
            return self._run_skill_action(
                family_skill, target=target, hint_blob=blob, retry_candidate=candidate
            )
        return self._run_skill_action("enumerate_endpoints", target=target, params={})

    def _known_surface_urls(self) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()

        def _remember(value: str) -> None:
            clean = str(value or "").strip()
            if not clean or clean in seen:
                return
            seen.add(clean)
            urls.append(clean)

        for message in self.state.messages:
            content = message.get("content", {})
            if not isinstance(content, dict):
                continue
            args = content.get("args", {})
            result = content.get("result", {})
            if isinstance(args, dict):
                for key in ("url", "target_url", "affected_component"):
                    if args.get(key):
                        _remember(str(args[key]))
            if isinstance(result, dict):
                data = result.get("data", {})
                if isinstance(data, dict):
                    for key in ("url", "affected_component"):
                        if data.get(key):
                            _remember(str(data[key]))
                    for ep in data.get("accessible", []) or []:
                        if isinstance(ep, dict) and ep.get("path"):
                            path = str(ep["path"])
                            if path.startswith("http"):
                                _remember(path)
                            else:
                                _remember(self.state.target.rstrip("/") + path)
        for finding in self.state.findings:
            component = str(finding.get("affected_component", "") or "")
            if component:
                _remember(component)
        return urls

    def _recent_skill_surface_counts(self, skill_name: str, *, window: int = 24) -> dict[str, int]:
        skill = str(skill_name).strip().lower()
        if not skill:
            return {}
        counts: dict[str, int] = {}
        for message in self.state.messages[-window:]:
            if message.get("role") != "tool":
                continue
            content = message.get("content", {})
            if not isinstance(content, dict) or content.get("name") != "run_skill":
                continue
            args = content.get("args", {})
            if not isinstance(args, dict):
                continue
            real_skill = str(args.get("skill") or "").strip().lower()
            if real_skill != skill:
                continue
            params = args.get("params", {}) if isinstance(args.get("params"), dict) else {}
            surface = str(
                params.get("url")
                or params.get("url_pattern")
                or params.get("base_url")
                or args.get("target_url")
                or ""
            ).strip()
            if not surface:
                continue
            counts[surface] = counts.get(surface, 0) + 1
        return counts

    def _surface_candidates_for_skill(self, skill_name: str, *, hint_blob: str = "") -> list[str]:
        skill = str(skill_name).strip().lower()
        target = str(self.state.target).rstrip("/")
        urls = self._known_surface_urls()
        blob = hint_blob.lower()
        seen: set[str] = set()
        ordered: list[str] = []

        def _push(url: str) -> None:
            clean = str(url or "").strip()
            if not clean or clean in seen:
                return
            seen.add(clean)
            ordered.append(clean)

        def _matches(url: str) -> bool:
            lower = url.lower()
            if skill == "test_injection":
                return "?" in lower and any(
                    token in lower for token in ("search", "login", "q=", "query", "filter")
                )
            if skill == "test_xss":
                return "?" in lower and any(
                    token in lower
                    for token in (
                        "search",
                        "q=",
                        "query",
                        "return",
                        "redirect",
                        "next",
                        "message",
                        "comment",
                    )
                )
            if skill == "test_ssrf":
                return any(
                    token in lower
                    for token in (
                        "url=",
                        "uri=",
                        "dest=",
                        "redirect",
                        "next=",
                        "callback",
                        "return",
                        "proxy",
                        "fetch",
                    )
                )
            if skill in {"test_api_security", "test_business_logic"}:
                return any(
                    token in lower
                    for token in ("/api/", "order", "cart", "checkout", "profile", "account")
                )
            return False

        if blob:
            for url in urls:
                lower = url.lower()
                if any(
                    token and token in lower
                    for token in re.split(r"[^a-z0-9_/.-]+", blob)
                    if len(token) >= 4
                ):
                    _push(url)

        for url in urls:
            if _matches(url):
                _push(url)
        for url in urls:
            if "?" in url:
                _push(url)
        if skill == "test_injection":
            _push(f"{target}/search?q=test")
        elif skill == "test_xss":
            _push(f"{target}/search?q=test")
            _push(f"{target}/redirect?next=/profile")
        elif skill == "test_ssrf":
            _push(f"{target}/redirect?url=http://example.com")
            _push(f"{target}/proxy?url=http://example.com")
        elif skill in {"test_api_security", "test_business_logic"}:
            _push(target)
        return ordered

    def _best_skill_params(self, skill_name: str, *, hint_blob: str = "") -> dict[str, Any]:
        skill = str(skill_name).strip().lower()
        target = str(self.state.target).rstrip("/")
        urls = self._known_surface_urls()
        blob = hint_blob.lower()

        def _pick(predicate: Callable[[str], bool]) -> str | None:
            for url in urls:
                lower = url.lower()
                if predicate(lower):
                    return url
            return None

        def _seed_paths(limit: int = 8) -> list[str]:
            seen: set[str] = set()
            out: list[str] = []
            for url in urls:
                parsed = urlparse(url)
                path = (parsed.path or "/").strip()
                if not path or path == "/":
                    continue
                if len(path) > 1:
                    path = path.rstrip("/")
                if path in seen:
                    continue
                seen.add(path)
                out.append(path)
                if len(out) >= limit:
                    break
            return out

        def _pick_untried(candidates: list[str]) -> str | None:
            recent = self._recent_skill_surface_counts(skill)
            scored = sorted(
                enumerate(candidates),
                key=lambda item: (recent.get(item[1], 0), item[0]),
            )
            return scored[0][1] if scored else None

        if skill == "test_injection":
            picked = _pick_untried(self._surface_candidates_for_skill(skill, hint_blob=blob)) or (
                _pick(
                    lambda u: (
                        "?" in u
                        and any(
                            token in u for token in ("search", "login", "q=", "query", "filter")
                        )
                    )
                )
                or _pick(lambda u: "?" in u)
                or f"{target}/search?q=test"
            )
            return {"url": picked}
        if skill == "test_xss":
            picked = _pick_untried(self._surface_candidates_for_skill(skill, hint_blob=blob)) or (
                _pick(
                    lambda u: (
                        "?" in u
                        and any(
                            token in u
                            for token in ("search", "q=", "query", "return", "redirect", "next")
                        )
                    )
                )
                or _pick(lambda u: "?" in u)
                or f"{target}/search?q=test"
            )
            return {"url": picked, "browser_confirm": True}
        if skill == "test_ssrf":
            picked = _pick_untried(self._surface_candidates_for_skill(skill, hint_blob=blob)) or (
                _pick(
                    lambda u: any(
                        token in u
                        for token in (
                            "url=",
                            "uri=",
                            "dest=",
                            "redirect",
                            "next=",
                            "callback",
                            "return",
                        )
                    )
                )
                or f"{target}/redirect?url=http://example.com"
            )
            return {"url": picked}
        if skill == "test_idor":
            picked = _pick(lambda u: bool(re.search(r"/\d+(?:/|$)", u)))
            token = self._latest_auth_token()
            authz_params = self._latest_authz_context_params()
            if picked:
                pattern = re.sub(r"/\d+(?=(/|$))", "/{id}", picked, count=1)
                params = {"url_pattern": pattern}
                if token:
                    params["token"] = token
                    params["max_id"] = 30
                params.update({k: v for k, v in authz_params.items() if v})
                if params.get("identities"):
                    params.setdefault("max_id", 30)
                return params
            params = {"base_url": target}
            if token:
                params["token"] = token
                params["max_id"] = 30
            params.update({k: v for k, v in authz_params.items() if v})
            if params.get("identities"):
                params.setdefault("max_id", 30)
            return params
        if skill in {"test_api_security", "test_business_logic"}:
            picked = (
                _pick(
                    lambda u: any(
                        token in u
                        for token in ("/api/", "order", "cart", "checkout", "profile", "account")
                    )
                )
                or target
            )
            params = {"url": picked}
            if skill == "test_business_logic":
                captured_flows = self._recent_captured_business_flows()
                if captured_flows:
                    params["captured_flows"] = captured_flows
            return params
        if skill == "execute_chain":
            token = self._latest_auth_token()
            params: dict[str, Any] = {
                "template": "post_auth_crown",
                "url_pattern": f"{target}/api/users/{{id}}",
            }
            if token:
                params["token"] = token
            params.update({k: v for k, v in self._latest_authz_context_params().items() if v})
            return params
        if skill == "post_auth_enum":
            return {"base_url": target}
        if skill == "test_infra":
            return {"seed_paths": _seed_paths()}
        return {}

    def _skill_supports_surface_retry(self, skill_name: str) -> bool:
        return str(skill_name).strip().lower() in {
            "test_injection",
            "test_xss",
            "test_ssrf",
            "test_api_security",
            "test_business_logic",
        }

    def _should_retry_skill_on_fresh_surface(
        self,
        skill_name: str,
        current_params: dict[str, Any] | None = None,
    ) -> bool:
        skill = str(skill_name).strip().lower()
        if not self._skill_supports_surface_retry(skill):
            return False
        params = dict(current_params or {})
        current_surface = str(
            params.get("url") or params.get("url_pattern") or params.get("base_url") or ""
        ).strip()
        alternatives = self._surface_candidates_for_skill(skill)
        if current_surface and any(surface != current_surface for surface in alternatives):
            return True
        fresh = self._best_skill_params(skill)
        next_surface = str(
            fresh.get("url") or fresh.get("url_pattern") or fresh.get("base_url") or ""
        ).strip()
        if not current_surface or not next_surface:
            return False
        return current_surface != next_surface

    def _alternate_surface_params(
        self,
        skill_name: str,
        current_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        skill = str(skill_name).strip().lower()
        params = dict(current_params or {})
        current_surface = str(
            params.get("url") or params.get("url_pattern") or params.get("base_url") or ""
        ).strip()
        for surface in self._surface_candidates_for_skill(skill):
            if surface and surface != current_surface:
                if skill == "test_idor":
                    return {"url_pattern": surface}
                if skill == "post_auth_enum":
                    return {"base_url": surface}
                return {"url": surface}
        return self._best_skill_params(skill)

    def _reroute_blocked_skill(
        self,
        requested_skill: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        skill = str(requested_skill).strip().lower()
        if not skill:
            return "", dict(params or {})
        if self._recent_blocked_skill_count(
            skill
        ) >= 3 and self._should_retry_skill_on_fresh_surface(skill, params):
            return skill, self._normalize_skill_params(
                skill, self._alternate_surface_params(skill, params)
            )
        rerouted = self._pivoted_skill_name(skill)
        if not rerouted:
            if self._recent_blocked_skill_count(skill) >= 3:
                return "", dict(params or {})
            rerouted = skill
        return rerouted, self._normalize_skill_params(rerouted, params)
