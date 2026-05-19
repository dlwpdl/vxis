#!/usr/bin/env python3
"""Run pytest with a readline crash workaround for this local Python build."""
from __future__ import annotations

import sys
import types


def main() -> int:
    # This venv resolves the CPython readline extension from an Anaconda base
    # install, and importing it segfaults on this machine. Pytest imports
    # readline during capture setup, so we stub it before importing pytest.
    sys.modules.setdefault("readline", types.ModuleType("readline"))

    import pytest

    return pytest.main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
