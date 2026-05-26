from vxis.agent.agent_graph_runtime import (
    agent_graph_agents_from_messages,
    agent_graph_crown_chain_next,
    agent_graph_director_brief,
    agent_graph_director_next_step,
    agent_graph_evidence_artifact_brief,
    agent_graph_has_valid_evidence_artifact,
    agent_graph_needs_evidence_artifact,
    agent_graph_result_needs_crown_chain,
    agent_graph_terminal_branch_status,
)


def test_agents_from_messages_collects_and_prioritizes_active_agents():
    messages = [
        {
            "content": {
                "name": "agent_graph",
                "result": {
                    "data": {
                        "agents": [
                            {"id": "finished-1", "status": "finished", "created_at": "1"},
                            {"id": "running-1", "status": "running", "created_at": "2"},
                        ]
                    }
                },
            }
        },
        {
            "content": {
                "name": "agent_graph",
                "result": {
                    "data": {
                        "agent": {
                            "id": "waiting-1",
                            "status": "waiting",
                            "created_at": "0",
                        }
                    }
                },
            }
        },
    ]

    agents = agent_graph_agents_from_messages(messages)

    assert [agent["id"] for agent in agents] == ["waiting-1", "running-1", "finished-1"]


def test_director_brief_keeps_worker_evidence_and_next_step():
    agents = [
        {
            "id": "agent-1",
            "role": "exploit_worker",
            "status": "waiting",
            "task": "Validate IDOR by replaying captured user profile request",
            "skills": ["test_idor"],
            "executions": [
                {"tool": "run_skill", "ok": True, "summary": "profile id 2 returned 200"}
            ],
            "skill_context": 'action: run_skill(skill="test_idor")',
        }
    ]

    brief = agent_graph_director_brief(agents, local_strict=False)

    joined = "\n".join(brief)
    assert "agent-1 waiting exploit_worker" in joined
    assert "run_skill ok: profile id 2 returned 200" in joined
    assert "finish or send sharper instruction to agent-1" in joined
    assert 'worker_card: action: run_skill(skill="test_idor")' in joined


def test_director_brief_forces_rerun_when_positive_artifact_is_invalid():
    agent = {
        "id": "agent-2",
        "role": "exploit_worker",
        "status": "waiting",
        "task": "Validate SQL injection on /search",
        "skills": ["test_injection"],
        "executions": [{"tool": "run_skill", "ok": True, "summary": "confirmed SQL injection"}],
        "result_package": {
            "verdict_guess": "needs_proof",
            "evidence_artifact": {
                "schema": "vxis.agent_graph.evidence_artifact.v1",
                "claim": "SQL injection on /search",
                "target": "http://localhost:3000/search",
                "control": {},
                "payload": {},
                "observed_delta": "",
                "repro_steps": [],
                "missing_fields": ["control", "payload", "observed_delta", "repro_steps"],
                "valid": False,
            },
        },
        "escalation": {
            "status": "needs_proof",
            "reason": "positive-looking child output lacks valid EvidenceArtifact fields",
        },
    }

    brief = "\n".join(agent_graph_director_brief([agent], local_strict=False))

    assert agent_graph_needs_evidence_artifact(agent) is True
    assert agent_graph_has_valid_evidence_artifact(agent) is False
    assert "director_next=run agent-2 for valid EvidenceArtifact" in brief
    assert "proof: invalid missing=control,payload,observed_delta,repro_steps" in brief
    assert agent_graph_director_next_step(agent) == "run agent-2 for valid EvidenceArtifact"


def test_director_brief_allows_finish_when_artifact_is_valid():
    agent = {
        "id": "agent-3",
        "role": "exploit_worker",
        "status": "waiting",
        "task": "Validate SQL injection on /search",
        "executions": [{"tool": "run_skill", "ok": True, "summary": "confirmed SQL injection"}],
        "result_package": {
            "verdict_guess": "candidate_positive",
            "evidence_artifact": {
                "schema": "vxis.agent_graph.evidence_artifact.v1",
                "claim": "SQL injection on /search",
                "target": "http://localhost:3000/search",
                "control": {"request": "GET /search?q=test", "response_status": 200},
                "payload": {"request": "GET /search?q='", "response_status": 500},
                "observed_delta": "control HTTP 200 vs payload HTTP 500",
                "repro_steps": ["send control", "send payload", "compare"],
                "missing_fields": [],
                "valid": True,
            },
        },
    }

    assert agent_graph_needs_evidence_artifact(agent) is False
    assert agent_graph_has_valid_evidence_artifact(agent) is True
    assert "proof: valid" in agent_graph_evidence_artifact_brief(agent, width=120)
    assert agent_graph_director_next_step(agent) == "finish agent-3 or open crown-chain pivot"


def test_positive_worker_result_requires_crown_chain_before_terminal_close():
    agent = {
        "id": "agent-2",
        "role": "exploit_worker",
        "status": "finished",
        "result": "Confirmed SQL injection exposed admin table rows",
    }

    assert agent_graph_result_needs_crown_chain(agent["result"])
    assert "create post_exploit_worker" in agent_graph_crown_chain_next(agent)
    assert "create post_exploit_worker" in agent_graph_director_next_step(agent)
    assert agent_graph_terminal_branch_status(agent) == "proven"


def test_clean_result_does_not_trigger_crown_chain():
    result = "Clean: not vulnerable after replay and payload checks"

    assert not agent_graph_result_needs_crown_chain(result)
    assert (
        agent_graph_terminal_branch_status({"status": "finished", "result": result}) == "exhausted"
    )
