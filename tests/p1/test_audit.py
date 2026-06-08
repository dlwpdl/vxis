from vxis.p1.audit import AuditLog


def test_append_chains_hashes(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    first = log.append(eng_id="e1", operator="BAC", action="recon", target="app", decision="ALLOW")
    second = log.append(eng_id="e1", operator="BAC", action="c2", target="app", decision="REJECT")
    entries = log.read()
    assert entries[0]["hash"] == first["hash"]
    assert second["prev_hash"] == first["hash"]
    assert log.verify() is True


def test_tamper_breaks_verify(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(eng_id="e1", operator="BAC", action="c2", target="10.0.0.5", decision="ALLOW")
    path.write_text(path.read_text().replace("10.0.0.5", "10.0.0.9"))
    assert log.verify() is False


def test_reordering_breaks_verify(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(eng_id="e1", operator="BAC", action="one", target="a", decision="ALLOW")
    log.append(eng_id="e1", operator="BAC", action="two", target="b", decision="ALLOW")
    lines = path.read_text().splitlines()
    path.write_text("\n".join(reversed(lines)) + "\n")
    assert log.verify() is False
