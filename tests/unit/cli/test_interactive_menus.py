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


class TestSettingsMenu:
    def test_settings_offers_model_refresh_and_back(self):
        from vxis.cli import interactive
        vals = {c["value"] for c in interactive._settings_menu_choices() if isinstance(c, dict)}
        assert "refresh_models" in vals
        assert "back" in vals


class TestBackNavigation:
    def test_back_choices_appends_back_sentinel(self):
        from vxis.cli import interactive
        base = [{"name": "A", "value": "a"}, {"name": "B", "value": "b"}]
        out = interactive._back_choices(base)
        assert out[0]["value"] == "a" and out[1]["value"] == "b"  # originals preserved
        backs = [c for c in out if isinstance(c, dict) and c.get("value") is interactive._BACK]
        assert len(backs) == 1  # exactly one back entry, carrying the _BACK sentinel

    def test_steps_complete_when_all_advance(self):
        from vxis.cli import interactive
        seq = []
        steps = [lambda s: (seq.append(0) or True), lambda s: (seq.append(1) or True)]
        assert interactive._run_wizard_steps(steps, {}) is True
        assert seq == [0, 1]

    def test_back_returns_to_previous_step(self):
        from vxis.cli import interactive
        seq = []
        state = {"used": False}

        def s0(st):
            seq.append("s0")
            return True

        def s1(st):
            seq.append("s1")
            if not st["used"]:
                st["used"] = True
                return interactive._BACK
            return True

        assert interactive._run_wizard_steps([s0, s1], state) is True
        assert seq == ["s0", "s1", "s0", "s1"]  # backed up to s0, then forward

    def test_none_aborts(self):
        from vxis.cli import interactive
        assert interactive._run_wizard_steps([lambda s: None], {}) is False

    def test_back_from_first_step_aborts(self):
        from vxis.cli import interactive
        assert interactive._run_wizard_steps([lambda s: interactive._BACK], {}) is False


class TestBrainFirstDelegation:
    def test_tui_passes_every_scan_param(self, monkeypatch):
        """Regression: calling the typer `scan` command directly turns any
        unpassed parameter into an OptionInfo object (→ 'OptionInfo has no
        attribute strip'). The TUI must pass ALL of scan's params explicitly."""
        import inspect

        from vxis.cli import interactive
        from vxis.cli import main as climain

        scan_params = set(inspect.signature(climain.scan).parameters)  # real sig first
        captured = {}

        def fake_scan(**kwargs):
            captured.update(kwargs)

        monkeypatch.setattr(climain, "scan", fake_scan)
        interactive._run_brain_first_scan_from_tui("http://localhost:3000", "crown")

        missing = scan_params - set(captured)
        assert not missing, f"TUI did not pass scan params (become OptionInfo): {missing}"
        # and nothing passed should be a typer OptionInfo
        import typer.models as tmodels
        leaked = {k for k, v in captured.items() if isinstance(v, tmodels.OptionInfo)}
        assert not leaked, f"OptionInfo leaked for: {leaked}"
