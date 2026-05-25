"""FileBasedBrain 단위 테스트."""

import json
import os
import tempfile

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


def test_think_writes_observation_and_waits_for_decision():
    """think()가 observation.json을 쓰고 decision.json을 기다리는지 확인."""
    import threading
    import time

    from vxis.agent.brain_filebased import FileBasedBrain, atomic_write
    from vxis.agent.brain import AgentObservation

    with tempfile.TemporaryDirectory() as tmpdir:
        brain = FileBasedBrain(brain_dir=tmpdir, timeout_per_vector=5, poll_interval=0.1)

        obs = AgentObservation(
            target="http://localhost:8081",
            tech_stack=["PHP", "Apache"],
            findings=[{"id": "F-001", "type": "sqli"}],
        )

        def write_decision():
            time.sleep(0.5)
            decision_path = os.path.join(tmpdir, "decision.json")
            atomic_write(
                decision_path,
                {
                    "vector_id": "WEB-XSS-001",
                    "attempt": True,
                    "reasoning": "test decision",
                    "targets": [
                        {
                            "endpoint": "/search.php",
                            "param": "q",
                            "payloads": ["<script>alert(1)</script>"],
                        }
                    ],
                },
            )

        t = threading.Thread(target=write_decision)
        t.start()

        actions = brain.think(obs)
        t.join()

        obs_path = os.path.join(tmpdir, "observation.json")
        assert os.path.exists(obs_path)
        assert len(actions) >= 1
        assert actions[0].tool != "SKIP"


def test_think_timeout_returns_skip():
    """decision.json이 오지 않으면 타임아웃 후 SKIP 반환."""
    from vxis.agent.brain_filebased import FileBasedBrain
    from vxis.agent.brain import AgentObservation

    with tempfile.TemporaryDirectory() as tmpdir:
        brain = FileBasedBrain(brain_dir=tmpdir, timeout_per_vector=1, poll_interval=0.1)
        obs = AgentObservation(target="http://localhost:8081")
        actions = brain.think(obs)
        assert len(actions) == 1
        assert actions[0].tool == "SKIP"
        assert "timeout" in actions[0].reasoning
