"""Desktop attack skills — phase-J (macOS-only e2e slice).

Phase-F of the universal pentesting plan ships 8 desktop skills with the
full DESK-* vector matrix. This package starts with the smallest viable
slice — `test_local_storage_secrets` — so a real `vxis scan ... --kind
desktop` run can complete end-to-end on macOS today, before the rest of
phase-F lands.
"""
from vxis.agent.skills.desktop.test_local_storage_secrets import execute as test_local_storage_secrets

__all__ = ["test_local_storage_secrets"]
