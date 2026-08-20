"""--ghost must reach manifest targets — regression for the multi-scan bypass."""

from vxis.cli.multi_scan import _ghost_run_target
from vxis.interaction.surface import TargetKind


def test_ghost_prefixes_web_url_when_enabled():
    assert (
        _ghost_run_target("https://example.com", TargetKind.WEB, ghost=True)
        == "ghost://example.com"
    )


def test_no_prefix_when_ghost_disabled():
    assert (
        _ghost_run_target("https://example.com", TargetKind.WEB, ghost=False)
        == "https://example.com"
    )


def test_already_ghost_url_is_untouched():
    assert (
        _ghost_run_target("ghost://example.com", TargetKind.WEB, ghost=True)
        == "ghost://example.com"
    )


def test_non_web_kind_is_untouched():
    assert (
        _ghost_run_target("/path/to/App.app", TargetKind.DESKTOP, ghost=True)
        == "/path/to/App.app"
    )
