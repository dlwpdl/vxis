"""Shared 'dossier' identity (vxis.cli.theme) used by both the input wizard and
the scan TUI — palette + the Textual theme + the InquirerPy style build cleanly,
and the input wizard routes prompts through the style-injecting shim."""

from __future__ import annotations

from vxis.cli import theme


def test_palette_is_hex():
    for hex_value in (theme.BRASS, theme.CYAN, theme.GREEN, theme.HAIR, theme.INK):
        assert hex_value.startswith("#") and len(hex_value) == 7


def test_textual_theme_is_vxis():
    t = theme.vxis_textual_theme()
    assert t.name == "vxis"
    assert t.primary == theme.BRASS
    assert t.secondary == theme.CYAN


def test_inquirer_style_builds_without_error():
    assert theme.vxis_inquirer_style() is not None


def test_input_wizard_uses_styled_shim():
    from vxis.cli import interactive

    # `inquirer` in the wizard is the style-injecting shim, not the raw module —
    # so every prompt in that module inherits the dossier palette.
    assert interactive.inquirer.__class__.__name__ == "_StyledInquirer"
    assert interactive._VXIS_PROMPT_STYLE is not None
    assert callable(interactive.inquirer.select)


def test_select_routes_through_textual_proxy():
    # Every list menu (inquirer.select) is rendered as the dossier Textual menu;
    # the shim returns a proxy whose .execute() picks Textual or InquirerPy.
    from vxis.cli import interactive

    proxy = interactive.inquirer.select(message="m", choices=[{"name": "A", "value": "a"}])
    assert proxy.__class__.__name__ == "_TextualSelectProxy"
    assert hasattr(proxy, "execute")
