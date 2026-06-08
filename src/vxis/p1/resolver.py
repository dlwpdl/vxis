from __future__ import annotations

import ipaddress
import socket
from typing import Protocol

from vxis.p1.scope import normalize_target


class Resolver(Protocol):
    def ips(self, host: str) -> list[str]: ...


class DnsResolver:
    def ips(self, host: str) -> list[str]:
        normalized = normalize_target(host)
        if not normalized:
            return []
        try:
            ipaddress.ip_address(normalized)
            return [normalized]
        except ValueError:
            pass
        infos = socket.getaddrinfo(normalized, None)
        return sorted({str(item[4][0]) for item in infos})


class FakeResolver:
    def __init__(self, table: dict[str, list[str]] | None = None):
        self.table = {normalize_target(k): list(v) for k, v in (table or {}).items()}

    def ips(self, host: str) -> list[str]:
        normalized = normalize_target(host)
        return list(self.table.get(normalized, []))


def resolve_all(target: str, resolver: Resolver) -> list[str]:
    normalized = normalize_target(target)
    values = [normalized] if normalized else []
    try:
        values.extend(resolver.ips(normalized))
    except OSError:
        pass
    return _dedupe(values)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        normalized = normalize_target(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out
