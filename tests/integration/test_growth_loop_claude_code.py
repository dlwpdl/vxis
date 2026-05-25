"""FileBasedBrain E2E 통합 테스트."""

import json
import tempfile
import threading
import time
from pathlib import Path


def test_filebased_brain_protocol_roundtrip():
    """FileBasedBrain이 observation을 쓰고 decision을 읽는 전체 라운드트립."""
    from vxis.agent.brain_filebased import FileBasedBrain, atomic_write, STATE_WAITING_FOR_BRAIN
    from vxis.agent.brain import AgentObservation

    with tempfile.TemporaryDirectory() as tmpdir:
        brain = FileBasedBrain(brain_dir=tmpdir, timeout_per_vector=10, poll_interval=0.2)

        vectors = [
            ("WEB-SQLI-001", True, "test SQL injection"),
            ("WEB-XSS-001", True, "test XSS"),
            ("WEB-CSRF-001", False, "skip CSRF"),
        ]

        results = []

        def brain_simulator():
            """Claude Code 역할 시뮬레이션."""
            status_path = Path(tmpdir) / "status.json"
            dec_path = Path(tmpdir) / "decision.json"

            for idx, (vector_id, attempt, reasoning) in enumerate(vectors, 1):
                # status.json이 waiting_for_brain이 될 때까지 대기 (올바른 step)
                for _ in range(50):
                    if status_path.exists():
                        status = json.loads(status_path.read_text())
                        if (
                            status.get("state") == STATE_WAITING_FOR_BRAIN
                            and status.get("vector_index") == idx
                        ):
                            break
                    time.sleep(0.1)

                # observation.json 확인
                obs_path = Path(tmpdir) / "observation.json"
                if obs_path.exists():
                    obs = json.loads(obs_path.read_text())
                    results.append({"vector": vector_id, "obs_step": obs.get("step")})

                # decision.json 작성
                atomic_write(
                    str(dec_path),
                    {
                        "vector_id": vector_id,
                        "attempt": attempt,
                        "reasoning": reasoning,
                        "targets": [{"endpoint": "/test", "param": "q", "payloads": ["test"]}]
                        if attempt
                        else [],
                    },
                )

        t = threading.Thread(target=brain_simulator)
        t.start()

        obs = AgentObservation(target="http://localhost:8081", tech_stack=["PHP"])

        all_actions = []
        for _ in vectors:
            actions = brain.think(obs)
            all_actions.append(actions)
            if actions and actions[0].tool != "SKIP":
                brain.record_result(actions[0], {"success": True, "findings": []})

        t.join()

        # 검증
        assert len(results) == 3
        assert results[0]["obs_step"] == 1
        assert results[2]["obs_step"] == 3

        # 첫 두 벡터는 attempt=True → PROBE
        assert all_actions[0][0].tool == "PROBE"
        assert all_actions[1][0].tool == "PROBE"
        # 세 번째는 attempt=False → SKIP
        assert all_actions[2][0].tool == "SKIP"

        # execution log 확인
        log = brain.get_execution_log()
        assert "Step 1" in log
        assert "Step 3" in log

        # mark_done 확인
        brain.mark_done()
        status = json.loads(Path(tmpdir, "status.json").read_text())
        assert status["state"] == "done"
        assert status["total_vectors"] == 3
