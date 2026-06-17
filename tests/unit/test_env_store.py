"""Persisted env store — save API keys once instead of re-entering every run."""
from vxis.config import env_store


def test_upsert_then_load_roundtrip(tmp_path):
    p = tmp_path / ".env"
    env_store.upsert_env("GOOGLE_API_KEY", "sk-abc", path=p)
    loaded = env_store.load_env(path=p, override=True)
    assert loaded["GOOGLE_API_KEY"] == "sk-abc"
    assert "GOOGLE_API_KEY=sk-abc" in p.read_text()


def test_upsert_updates_in_place_preserving_others(tmp_path):
    p = tmp_path / ".env"
    env_store.upsert_env("A", "1", path=p)
    env_store.upsert_env("B", "2", path=p)
    env_store.upsert_env("A", "9", path=p)  # update A
    text = p.read_text()
    assert text.count("A=") == 1  # not duplicated
    assert "A=9" in text and "B=2" in text  # updated + preserved


def test_load_does_not_override_existing_env(tmp_path, monkeypatch):
    p = tmp_path / ".env"
    p.write_text("OPENAI_API_KEY=from-file\n", encoding="utf-8")
    monkeypatch.setenv("OPENAI_API_KEY", "from-env")
    env_store.load_env(path=p)  # default: do not override
    import os
    assert os.environ["OPENAI_API_KEY"] == "from-env"


def test_load_sets_unset_keys(tmp_path, monkeypatch):
    p = tmp_path / ".env"
    p.write_text("# comment\nTOGETHER_API_KEY=tok\n\n", encoding="utf-8")
    monkeypatch.delenv("TOGETHER_API_KEY", raising=False)
    env_store.load_env(path=p)
    import os
    assert os.environ["TOGETHER_API_KEY"] == "tok"


def test_load_missing_file_is_noop(tmp_path):
    assert env_store.load_env(path=tmp_path / "nope.env") == {}
