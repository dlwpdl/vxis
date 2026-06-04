from __future__ import annotations

import inspect

import vxis.cli.main as cli_main


def test_scheduler_diff_and_retest_order_scan_records_by_started_at() -> None:
    source = "\n".join(
        [
            inspect.getsource(cli_main._diff_latest_two_for_target),
            inspect.getsource(cli_main.retest_cmd),
        ]
    )

    assert "ScanRecord.created_at" not in source
    assert "ScanRecord.started_at.desc()" in source
