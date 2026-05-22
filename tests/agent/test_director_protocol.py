from vxis.agent.director_protocol import render_director_protocol_memory


def test_frontier_web_protocol_requires_worker_evidence_and_crown_chain():
    protocol = render_director_protocol_memory(local_strict=False, target_kind="web")

    assert "director owns strategy" in protocol
    assert "workers own bounded proof" in protocol
    assert "Positive worker result must spawn post_exploit_worker" in protocol
    assert "browser/proxy requests are evidence" in protocol


def test_desktop_protocol_does_not_pull_web_surface_by_default():
    protocol = render_director_protocol_memory(local_strict=False, target_kind="desktop")

    assert "desktop tools only" in protocol
    assert "no web skills unless target has a real URL surface" in protocol
    assert "browser/proxy requests are evidence" not in protocol


def test_local_protocol_is_short_and_strict():
    protocol = render_director_protocol_memory(local_strict=True, target_kind="web")

    assert "keep one active proof path" in protocol
    assert "Worker must run tool/skill before positive finish" in protocol
    assert "Finish only after verify/report/link_chain" in protocol
    assert len(protocol) < 280
