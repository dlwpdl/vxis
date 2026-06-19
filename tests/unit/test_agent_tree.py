"""build_agent_tree — flat control_plane agents → nested parallel tree."""
from vxis.agent.agent_tree import build_agent_tree


def test_nests_children_under_parent():
    agents = [
        {"id": "director", "status": "running", "role": "director"},
        {"id": "w1", "parent_id": "director", "status": "running", "task": "sqli"},
        {"id": "w2", "parent_id": "director", "status": "waiting", "task": "ssrf"},
        {"id": "w1a", "parent_id": "w1", "status": "done", "task": "login probe"},
    ]
    tree = build_agent_tree(agents)
    assert [n["agent"]["id"] for n in tree] == ["director"]      # single root
    director = tree[0]
    assert [c["agent"]["id"] for c in director["children"]] == ["w1", "w2"]
    assert [c["agent"]["id"] for c in director["children"][0]["children"]] == ["w1a"]


def test_missing_parent_becomes_root():
    agents = [{"id": "orphan", "parent_id": "ghost", "status": "running"}]
    tree = build_agent_tree(agents)
    assert [n["agent"]["id"] for n in tree] == ["orphan"]


def test_multiple_roots_order_preserved():
    agents = [{"id": "a"}, {"id": "b"}, {"id": "c", "parent_id": "a"}]
    tree = build_agent_tree(agents)
    assert [n["agent"]["id"] for n in tree] == ["a", "b"]
    assert [c["agent"]["id"] for c in tree[0]["children"]] == ["c"]


def test_self_parent_is_cycle_safe_root():
    tree = build_agent_tree([{"id": "x", "parent_id": "x"}])
    assert [n["agent"]["id"] for n in tree] == ["x"]
    assert tree[0]["children"] == []


def test_empty_and_idless():
    assert build_agent_tree([]) == []
    assert build_agent_tree([{"status": "running"}]) == []  # no id → skipped
