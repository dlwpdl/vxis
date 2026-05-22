from vxis.agent.agent_graph_runtime import (
    agent_graph_agents_from_messages,
    agent_graph_crown_chain_next,
    agent_graph_director_brief,
    agent_graph_director_next_step,
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
            "executions": [{"tool": "run_skill", "ok": True, "summary": "profile id 2 returned 200"}],
            "skill_context": 'action: run_skill(skill="test_idor")',
        }
    ]

    brief = agent_graph_director_brief(agents, local_strict=False)

    joined = "\n".join(brief)
    assert "agent-1 waiting exploit_worker" in joined
    assert "run_skill ok: profile id 2 returned 200" in joined
    assert "finish or send sharper instruction to agent-1" in joined
    assert 'worker_card: action: run_skill(skill="test_idor")' in joined


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
    assert agent_graph_terminal_branch_status({"status": "finished", "result": result}) == "exhausted"
