"""FileBasedBrain 단위 테스트."""
import json
import os
import tempfile
from pathlib import Path

import pytest


def test_atomic_write_creates_file():
    """atomic_write가 JSON 파일을 정상 생성하는지 확인."""
    from vxis.agent.brain_filebased import atomic_write

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.json")
        data = {"key": "value", "number": 42}
        atomic_write(path, data)

        assert os.path.exists(path)
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded == data


def test_atomic_write_no_partial_file_on_error():
    """atomic_write 실패 시 깨진 파일이 남지 않는지 확인."""
    from vxis.agent.brain_filebased import atomic_write

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.json")

        class BadObj:
            def __repr__(self):
                raise RuntimeError("serialize error")

        with pytest.raises((TypeError, RuntimeError)):
            atomic_write(path, {"bad": BadObj()})

        assert not os.path.exists(path)


def test_atomic_write_overwrites_existing():
    """atomic_write가 기존 파일을 원자적으로 덮어쓰는지 확인."""
    from vxis.agent.brain_filebased import atomic_write

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.json")
        atomic_write(path, {"v": 1})
        atomic_write(path, {"v": 2})

        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["v"] == 2
