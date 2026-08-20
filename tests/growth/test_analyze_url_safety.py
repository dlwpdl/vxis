from __future__ import annotations

import socket

import pytest

from vxis.growth.analyze import _validate_public_article_url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "https://user:password@example.com/article",
    ],
)
def test_article_url_rejects_non_public_destinations(url: str) -> None:
    with pytest.raises(ValueError):
        _validate_public_article_url(url)


def test_article_url_rejects_hostname_with_any_private_resolution(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 443)),
        ],
    )

    with pytest.raises(ValueError, match="public"):
        _validate_public_article_url("https://example.com/article")


def test_article_url_accepts_globally_routable_http_destination(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ],
    )

    assert _validate_public_article_url("https://example.com/article") == (
        "https://example.com/article"
    )
