"""Shared test fixtures and lightweight pytest shims for VXIS."""

from __future__ import annotations

import asyncio
import inspect


def pytest_addoption(parser):
    # Local shim so pyproject's asyncio_mode does not warn when
    # pytest-asyncio is absent in this environment.
    parser.addini("asyncio_mode", "Local asyncio shim mode", default="auto")


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "asyncio: run an async test via the local asyncio shim when pytest-asyncio is unavailable",
    )


def pytest_pyfunc_call(pyfuncitem):
    """Minimal async-test runner when pytest-asyncio is not installed."""
    testfunction = pyfuncitem.obj
    if not inspect.iscoroutinefunction(testfunction):
        return None

    kwargs = {
        name: pyfuncitem.funcargs[name]
        for name in pyfuncitem._fixtureinfo.argnames
    }
    asyncio.run(testfunction(**kwargs))
    return True
