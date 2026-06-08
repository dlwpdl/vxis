from vxis.p1.resolver import FakeResolver, resolve_all


def test_resolve_all_includes_original_and_ips():
    resolver = FakeResolver({"app.acme.com": ["10.0.0.12", "10.0.0.13"]})
    assert resolve_all("https://app.acme.com/login", resolver) == [
        "app.acme.com",
        "10.0.0.12",
        "10.0.0.13",
    ]


def test_resolve_all_dedupes_ip_literals():
    resolver = FakeResolver({"10.0.0.5": ["10.0.0.5"]})
    assert resolve_all("10.0.0.5", resolver) == ["10.0.0.5"]
