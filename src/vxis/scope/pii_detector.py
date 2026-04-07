"""PII Detector | 개인정보 탐지기."""

from __future__ import annotations

import re

from vxis.scope.schemas import PIIDetection

PII_PATTERNS: dict[str, str] = {
    "email":       r"[\w._+-]+@[\w.-]+\.[A-Za-z]{2,}",
    "ssn_kr":      r"\d{6}-\d{7}",
    "ssn_us":      r"\d{3}-\d{2}-\d{4}",
    "phone_kr":    r"01[016789][- ]?\d{3,4}[- ]?\d{4}",
    "phone_us":    r"\+?1?[- ]?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}",
    "credit_card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
    "jwt":         r"eyJ[A-Za-z0-9_=\-]{10,}\.eyJ[A-Za-z0-9_=\-]{10,}\.[A-Za-z0-9_=\-]{10,}",
    "api_key":     r"(?:api[_-]?key|apikey|sk_|pk_)[\"'\s:=]*[A-Za-z0-9_\-]{20,}",
    "aws_key":     r"AKIA[0-9A-Z]{16}",
    "password":    r"(?:password|passwd|pwd)[\"'\s:=]+[\"']?[^\s\"']{6,}",
    "private_key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
}


class PIIDetector:
    """Scan text for PII patterns and produce a redacted view."""

    def __init__(self) -> None:
        self._compiled: dict[str, re.Pattern[str]] = {
            name: re.compile(pattern) for name, pattern in PII_PATTERNS.items()
        }

    def scan(self, text: str) -> PIIDetection:
        if not text:
            return PIIDetection(found=False, types=[], matches={}, redacted_text=text or "")

        matches: dict[str, list[str]] = {}
        for pii_type, pattern in self._compiled.items():
            hits = pattern.findall(text)
            if hits:
                # findall may return tuples for groups; normalize to strings
                normalized: list[str] = []
                for h in hits:
                    if isinstance(h, tuple):
                        normalized.append("".join(h))
                    else:
                        normalized.append(h)
                matches[pii_type] = normalized

        redacted = text
        for pii_type, hits in matches.items():
            for hit in hits:
                if hit and hit in redacted:
                    redacted = redacted.replace(hit, f"[REDACTED:{pii_type.upper()}]")

        return PIIDetection(
            found=bool(matches),
            types=list(matches.keys()),
            matches=matches,
            redacted_text=redacted,
        )
