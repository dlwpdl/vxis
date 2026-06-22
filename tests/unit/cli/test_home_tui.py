"""Pilot tests for the Textual home menu (dossier identity), headless via run_test."""

from textual.widgets import OptionList

from vxis.cli.home_tui import VxisHome


async def test_home_mounts_with_theme_and_menu():
    app = VxisHome()
    async with app.run_test():
        assert app.theme == "vxis"
        menu = app.query_one("#menu", OptionList)
        assert menu.option_count == 6


async def test_enter_selects_highlighted_action():
    app = VxisHome()
    async with app.run_test() as pilot:
        await pilot.press("enter")  # first option (scan) is highlighted on focus
    assert app.return_value == "scan"


async def test_arrow_then_enter_selects_next_action():
    app = VxisHome()
    async with app.run_test() as pilot:
        await pilot.press("down")
        await pilot.press("enter")
    assert app.return_value == "results"


async def test_q_quits_with_exit():
    app = VxisHome()
    async with app.run_test() as pilot:
        await pilot.press("q")
    assert app.return_value == "exit"
