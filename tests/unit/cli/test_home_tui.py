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


async def test_q_quits_returns_none():
    # q/escape returns None — run_interactive treats None like "exit".
    app = VxisHome()
    async with app.run_test() as pilot:
        await pilot.press("q")
    assert app.return_value is None


async def test_selecting_quit_item_returns_exit():
    app = VxisHome()
    async with app.run_test() as pilot:
        for _ in range(5):  # move from Scan (0) down to Quit (5)
            await pilot.press("down")
        await pilot.press("enter")
    assert app.return_value == "exit"


async def test_run_menu_submenu_returns_selected_value():
    from vxis.cli.home_tui import VxisMenu

    app = VxisMenu(
        items=[("industry", "산업 스캔"), ("client", "클라이언트 관리")],
        title="고급 기능",
        show_banner=False,
    )
    async with app.run_test() as pilot:
        assert app.query_one("#menu", OptionList).option_count == 2
        await pilot.press("down")
        await pilot.press("enter")
    assert app.return_value == "client"


async def test_run_menu_quit_returns_none():
    from vxis.cli.home_tui import VxisMenu

    app = VxisMenu(items=[("a", "A"), ("b", "B")], title="X")
    async with app.run_test() as pilot:
        await pilot.press("escape")
    assert app.return_value is None
