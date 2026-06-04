"""Rule-based block classifier for v3 block-aware adaptation.

This module is intentionally detection-only. It never mutates payloads, rotates
transport, retries requests, or invokes any bypass adapter. The
``suggested_strategy`` field is metadata for a future coordinator to interpret.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class BlockKind(StrEnum):
    NONE = "none"
    WAF_SIGNATURE = "waf-signature"
    WAF_RATE = "waf-rate"
    IP_BAN = "ip-ban"
    HONEYPOT = "honeypot"
    BEHAVIORAL = "behavioral"


SuggestedStrategy = Literal[
    "encoding-mutation",
    "polyglot",
    "case-mutation",
    "timing-jitter",
    "tor-rotate",
    "ghost-strict",
    "browser-emulation",
    "abandon-surface",
]


class BlockSignal(BaseModel):
    kind: BlockKind
    detector: str
    evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    suggested_strategy: SuggestedStrategy | None = None

    @property
    def blocked(self) -> bool:
        return self.kind != BlockKind.NONE


@dataclass(frozen=True)
class _ResponseSnapshot:
    status_code: int | None
    headers: dict[str, str]
    body: str


@dataclass(frozen=True)
class _Candidate:
    signal: BlockSignal
    priority: int


_BLOCK_STATUS_CODES = {401, 403, 406, 409, 423, 429, 451, 503}
_MAX_EVIDENCE = 8


class BlockClassifier:
    """Classify HTTP block signals from a response and optional recent history."""

    def inspect(
        self,
        http_response: Any,
        recent_response_history: list[Any] | tuple[Any, ...] | None = None,
    ) -> BlockSignal:
        current = _snapshot_response(http_response)
        history = [_snapshot_response(item) for item in (recent_response_history or [])]
        candidates: list[_Candidate] = []

        self._detect_known_wafs(current, candidates)
        self._detect_rate_limit(current, history, candidates)
        self._detect_ip_ban(current, history, candidates)
        self._detect_honeypot(current, candidates)
        self._detect_behavioral(current, candidates)
        self._detect_generic_block(current, candidates)

        if not candidates:
            return BlockSignal(
                kind=BlockKind.NONE,
                detector="none",
                evidence=[],
                confidence=0.0,
                suggested_strategy=None,
            )

        best = max(candidates, key=lambda item: (item.signal.confidence, item.priority))
        return best.signal

    def _detect_known_wafs(self, response: _ResponseSnapshot, candidates: list[_Candidate]) -> None:
        status = response.status_code
        blocked_status = status in _BLOCK_STATUS_CODES
        body = response.body.lower()
        headers = response.headers

        cloudflare = _collect_evidence(
            headers,
            body,
            header_names=("cf-ray", "cf-request-id", "cf-cache-status"),
            header_contains={"server": ("cloudflare",), "set-cookie": ("__cf_bm", "cf_clearance")},
            body_markers=(
                "attention required! | cloudflare",
                "checking your browser before accessing",
                "cloudflare ray id",
                "error 1020",
                "sorry, you have been blocked",
            ),
        )
        if cloudflare and (blocked_status or _has_body_marker(cloudflare)):
            self._append_candidate(
                candidates,
                kind=BlockKind.WAF_SIGNATURE,
                detector="cloudflare",
                evidence=cloudflare,
                confidence=0.93 if blocked_status else 0.78,
                strategy="encoding-mutation",
                priority=60,
            )

        akamai = _collect_evidence(
            headers,
            body,
            header_names=("akamai-grn", "x-akamai-session-info"),
            header_contains={"server": ("akamaighost", "akamai")},
            body_markers=("access denied", "akamai", "reference #"),
        )
        if akamai and (blocked_status or _has_body_marker(akamai)):
            self._append_candidate(
                candidates,
                kind=BlockKind.WAF_SIGNATURE,
                detector="akamai",
                evidence=akamai,
                confidence=0.9 if blocked_status else 0.76,
                strategy="case-mutation",
                priority=58,
            )

        incapsula = _collect_evidence(
            headers,
            body,
            header_names=("x-iinfo",),
            header_contains={
                "server": ("incapsula", "imperva"),
                "set-cookie": ("visid_incap", "incap_ses"),
            },
            body_markers=(
                "incapsula incident id",
                "_incapsula_resource",
                "request unsuccessful. incapsula",
                "imperva",
            ),
        )
        if incapsula and (blocked_status or _has_body_marker(incapsula)):
            self._append_candidate(
                candidates,
                kind=BlockKind.WAF_SIGNATURE,
                detector="incapsula",
                evidence=incapsula,
                confidence=0.91 if blocked_status else 0.77,
                strategy="polyglot",
                priority=58,
            )

        aws_waf = _collect_evidence(
            headers,
            body,
            header_names=("x-amzn-waf-action", "x-amzn-requestid", "x-amzn-trace-id"),
            header_contains={"server": ("awselb",)},
            body_markers=("aws waf", "generated by aws waf", "request blocked"),
        )
        if aws_waf and (blocked_status or "header x-amzn-waf-action" in " ".join(aws_waf)):
            self._append_candidate(
                candidates,
                kind=BlockKind.WAF_SIGNATURE,
                detector="aws-waf",
                evidence=aws_waf,
                confidence=0.88 if blocked_status else 0.74,
                strategy="encoding-mutation",
                priority=56,
            )

    def _detect_rate_limit(
        self,
        response: _ResponseSnapshot,
        history: list[_ResponseSnapshot],
        candidates: list[_Candidate],
    ) -> None:
        statuses = [item.status_code for item in [*history, response]]
        recent_429_count = sum(1 for status in statuses if status == 429)
        body = response.body.lower()
        evidence: list[str] = []
        if response.status_code == 429:
            evidence.append("status 429")
        if recent_429_count >= 2:
            evidence.append(f"recent history contains {recent_429_count} HTTP 429 responses")
        if "retry-after" in response.headers:
            evidence.append("header retry-after present")
        if response.headers.get("x-ratelimit-remaining", "").strip() == "0":
            evidence.append("header x-ratelimit-remaining=0")
        for marker in ("too many requests", "rate limit", "request limit exceeded"):
            if marker in body:
                evidence.append(f"body contains '{marker}'")

        if not evidence:
            return

        detector = "generic-rate-limit"
        if (
            _header_contains(response.headers, "server", ("cloudflare",))
            or "cf-ray" in response.headers
        ):
            detector = "cloudflare"
        confidence = 0.95 if response.status_code == 429 else 0.78
        self._append_candidate(
            candidates,
            kind=BlockKind.WAF_RATE,
            detector=detector,
            evidence=evidence,
            confidence=confidence,
            strategy="timing-jitter",
            priority=70,
        )

    def _detect_ip_ban(
        self,
        response: _ResponseSnapshot,
        history: list[_ResponseSnapshot],
        candidates: list[_Candidate],
    ) -> None:
        body = response.body.lower()
        evidence: list[str] = []
        if response.status_code in {403, 451}:
            for marker in (
                "your ip has been banned",
                "ip address blocked",
                "your ip is blocked",
                "blacklisted ip",
                "blocked due to suspicious activity",
                "access from your location has been blocked",
            ):
                if marker in body:
                    evidence.append(f"body contains '{marker}'")

        recent_403_count = sum(1 for item in [*history, response] if item.status_code == 403)
        if recent_403_count >= 4 and "temporarily blocked" in body:
            evidence.append(f"recent history contains {recent_403_count} HTTP 403 responses")

        if evidence:
            self._append_candidate(
                candidates,
                kind=BlockKind.IP_BAN,
                detector="ip-ban",
                evidence=evidence,
                confidence=0.9,
                strategy="abandon-surface",
                priority=80,
            )

    def _detect_honeypot(self, response: _ResponseSnapshot, candidates: list[_Candidate]) -> None:
        body = response.body.lower()
        evidence = _collect_evidence(
            response.headers,
            body,
            header_names=("x-honeypot", "x-canary-token"),
            body_markers=(
                "honeypot",
                "canary token",
                "canarytokens.com",
                "trap endpoint",
            ),
        )
        if evidence:
            self._append_candidate(
                candidates,
                kind=BlockKind.HONEYPOT,
                detector="explicit-honeypot-marker",
                evidence=evidence,
                confidence=0.92,
                strategy="abandon-surface",
                priority=90,
            )

    def _detect_behavioral(self, response: _ResponseSnapshot, candidates: list[_Candidate]) -> None:
        body = response.body.lower()
        evidence = _collect_evidence(
            response.headers,
            body,
            header_names=("x-distil-cs", "x-datadome", "x-px-block"),
            header_contains={
                "set-cookie": ("datadome", "_px", "perimeterx"),
                "server": ("datadome", "distil"),
            },
            body_markers=(
                "verify you are human",
                "unusual traffic",
                "captcha",
                "bot detection",
                "perimeterx",
                "datadome",
                "javascript is required",
            ),
        )
        if evidence and (
            response.status_code in _BLOCK_STATUS_CODES
            or any("body contains" in item for item in evidence)
        ):
            self._append_candidate(
                candidates,
                kind=BlockKind.BEHAVIORAL,
                detector="behavioral-bot-defense",
                evidence=evidence,
                confidence=0.84,
                strategy="browser-emulation",
                priority=50,
            )

    def _detect_generic_block(
        self, response: _ResponseSnapshot, candidates: list[_Candidate]
    ) -> None:
        body = response.body.lower()
        evidence: list[str] = []
        if response.status_code in {403, 406, 409, 423, 451}:
            evidence.append(f"status {response.status_code}")
        elif response.status_code == 503 and any(
            marker in body for marker in ("service unavailable", "temporarily unavailable")
        ):
            evidence.append("status 503")

        for marker in (
            "access denied",
            "forbidden",
            "request blocked",
            "blocked by security policy",
            "not acceptable",
        ):
            if marker in body:
                evidence.append(f"body contains '{marker}'")

        if not evidence:
            return

        body_marker_count = sum(1 for item in evidence if item.startswith("body contains"))
        confidence = 0.72 if body_marker_count else 0.55
        self._append_candidate(
            candidates,
            kind=BlockKind.WAF_SIGNATURE,
            detector="generic-http-block",
            evidence=evidence,
            confidence=confidence,
            strategy="browser-emulation",
            priority=10,
        )

    def _append_candidate(
        self,
        candidates: list[_Candidate],
        *,
        kind: BlockKind,
        detector: str,
        evidence: list[str],
        confidence: float,
        strategy: SuggestedStrategy,
        priority: int,
    ) -> None:
        candidates.append(
            _Candidate(
                signal=BlockSignal(
                    kind=kind,
                    detector=detector,
                    evidence=_dedupe_preserve_order(evidence)[:_MAX_EVIDENCE],
                    confidence=max(0.0, min(1.0, confidence)),
                    suggested_strategy=strategy,
                ),
                priority=priority,
            )
        )


def _snapshot_response(response: Any) -> _ResponseSnapshot:
    if response is None:
        return _ResponseSnapshot(status_code=None, headers={}, body="")

    status = _extract_status(response)
    headers = _normalize_headers(_extract_headers(response))
    body = _extract_body(response)
    return _ResponseSnapshot(status_code=status, headers=headers, body=body)


def _extract_status(response: Any) -> int | None:
    for name in ("status_code", "status", "code"):
        value = _get_value(response, name)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _extract_headers(response: Any) -> Any:
    return _get_value(response, "headers") or {}


def _extract_body(response: Any) -> str:
    for name in ("text", "body", "content"):
        value = _get_value(response, name)
        if value is None:
            continue
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)
    return ""


def _get_value(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _normalize_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        try:
            headers = dict(headers)
        except (TypeError, ValueError):
            headers = {}
    normalized: dict[str, str] = {}
    for key, value in headers.items():
        normalized[str(key).lower()] = str(value)
    return normalized


def _collect_evidence(
    headers: dict[str, str],
    body: str,
    *,
    header_names: tuple[str, ...] = (),
    header_contains: dict[str, tuple[str, ...]] | None = None,
    body_markers: tuple[str, ...] = (),
) -> list[str]:
    evidence: list[str] = []
    for name in header_names:
        if name in headers:
            evidence.append(f"header {name} present")

    for name, markers in (header_contains or {}).items():
        value = headers.get(name, "").lower()
        for marker in markers:
            if marker.lower() in value:
                evidence.append(f"header {name} contains '{marker}'")

    for marker in body_markers:
        marker_lower = marker.lower()
        if marker_lower in body:
            evidence.append(f"body contains '{marker_lower}'")

    return _dedupe_preserve_order(evidence)


def _has_body_marker(evidence: list[str]) -> bool:
    return any(item.startswith("body contains") for item in evidence)


def _header_contains(headers: dict[str, str], name: str, markers: tuple[str, ...]) -> bool:
    value = headers.get(name, "").lower()
    return any(marker.lower() in value for marker in markers)


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped
