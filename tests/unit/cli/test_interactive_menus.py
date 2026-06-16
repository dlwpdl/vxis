"""NOW-3 menu restructure — collapse the top level + reorder the scan wizard.

Pure choice-builders keep the (interactive) menus testable: the main menu
collapses 9 items to a short top level + an Advanced submenu, and the scan
wizard leads with the recommended AI auto scan and groups advanced types.
"""
from InquirerPy.separator import Separator

from vxis.cli import interactive
from vxis.cli.interactive import SCAN_CATEGORIES


class TestMainMenuStructure:
    def test_top_level_is_collapsed(self):
        vals = {c["value"] for c in interactive._main_menu_choices() if isinstance(c, dict)}
        assert {"scan", "results", "report", "advanced", "settings", "exit"} <= vals
        # industry / client / plugins / dashboard move under Advanced, not top level
        assert {"industry", "client", "plugins", "dashboard"}.isdisjoint(vals)

    def test_advanced_submenu_groups_the_moved_items(self):
        vals = {c["value"] for c in interactive._advanced_menu_choices() if isinstance(c, dict)}
        assert {"industry", "client", "plugins", "dashboard", "back"} <= vals


class TestScanWizardOrder:
    def _dict_choices(self):
        return [c for c in interactive._ordered_scan_choices() if isinstance(c, dict)]

    def test_ai_auto_is_first_and_recommended(self):
        first = self._dict_choices()[0]
        assert first["value"] == "ai_auto"
        assert "권장" in first["name"]

    def test_all_categories_present(self):
        assert {c["value"] for c in self._dict_choices()} == set(SCAN_CATEGORIES.keys())

    def test_advanced_types_after_a_separator(self):
        seq = interactive._ordered_scan_choices()
        sep_idx = next(i for i, c in enumerate(seq) if isinstance(c, Separator))
        after = {c["value"] for c in seq[sep_idx:] if isinstance(c, dict)}
        assert {"full", "batch", "custom"} <= after

    def test_batch_label_drops_finance_jargon(self):
        name = SCAN_CATEGORIES["batch"]["name"]
        assert "PE 포트폴리오" not in name
        assert "CSV" in name
