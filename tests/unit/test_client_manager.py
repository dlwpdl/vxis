"""Unit tests for ClientManager and Client dataclass.

Covers:
- create_client saves TOML file
- get_client loads from TOML
- list_clients returns all clients
- update_client modifies existing
- delete_client removes file
- get_client nonexistent returns None
- client_id is slugified from name
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vxis.config.client_manager import Client, ClientManager, _slugify


# ---------------------------------------------------------------------------
# _slugify helper
# ---------------------------------------------------------------------------


class TestSlugify:
    def test_lowercases_input(self) -> None:
        assert _slugify("ACME") == "acme"

    def test_replaces_spaces_with_hyphens(self) -> None:
        assert _slugify("ACME Corporation") == "acme-corporation"

    def test_strips_special_characters(self) -> None:
        slug = _slugify("Foo & Bar 2024!")
        assert slug == "foo-bar-2024"

    def test_collapses_multiple_separators(self) -> None:
        slug = _slugify("One  Two   Three")
        assert slug == "one-two-three"

    def test_no_leading_trailing_hyphens(self) -> None:
        slug = _slugify("  Leading trailing  ")
        assert not slug.startswith("-")
        assert not slug.endswith("-")

    def test_numbers_preserved(self) -> None:
        assert "2024" in _slugify("Client 2024")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def clients_dir(tmp_path: Path) -> Path:
    return tmp_path / "clients"


@pytest.fixture()
def manager(clients_dir: Path) -> ClientManager:
    return ClientManager(clients_dir)


def _make_client(
    name: str = "ACME Corporation",
    domains: list[str] | None = None,
    client_id: str = "",
) -> Client:
    if domains is None:
        domains = ["acme.example.com", "admin.acme.example.com"]
    resolved_id = client_id or _slugify(name)
    return Client(id=resolved_id, name=name, domains=domains)


# ---------------------------------------------------------------------------
# ClientManager.create_client
# ---------------------------------------------------------------------------


class TestCreateClient:
    def test_creates_toml_file(self, manager: ClientManager, clients_dir: Path) -> None:
        client = _make_client()
        path = manager.create_client(client)
        assert path.exists()
        assert path.suffix == ".toml"

    def test_file_named_after_client_id(self, manager: ClientManager, clients_dir: Path) -> None:
        client = _make_client(name="Example Inc", client_id="example-inc")
        path = manager.create_client(client)
        assert path.name == "example-inc.toml"

    def test_returns_path_object(self, manager: ClientManager) -> None:
        client = _make_client()
        result = manager.create_client(client)
        assert isinstance(result, Path)

    def test_creates_clients_dir_if_absent(self, tmp_path: Path) -> None:
        new_dir = tmp_path / "nested" / "clients"
        mgr = ClientManager(new_dir)
        client = _make_client()
        mgr.create_client(client)
        assert new_dir.exists()

    def test_auto_generates_id_from_name_when_empty(
        self, manager: ClientManager, clients_dir: Path
    ) -> None:
        client = Client(id="", name="Zero Id Corp", domains=["zero.example.com"])
        path = manager.create_client(client)
        assert path.name == "zero-id-corp.toml"
        assert client.id == "zero-id-corp"


# ---------------------------------------------------------------------------
# ClientManager.get_client
# ---------------------------------------------------------------------------


class TestGetClient:
    def test_returns_none_for_nonexistent_client(self, manager: ClientManager) -> None:
        result = manager.get_client("does-not-exist")
        assert result is None

    def test_loads_client_by_id(self, manager: ClientManager) -> None:
        client = _make_client(name="Load Me Inc", client_id="load-me-inc")
        manager.create_client(client)
        loaded = manager.get_client("load-me-inc")
        assert loaded is not None
        assert loaded.id == "load-me-inc"

    def test_loaded_name_matches_original(self, manager: ClientManager) -> None:
        client = _make_client(name="Name Check Ltd", client_id="name-check-ltd")
        manager.create_client(client)
        loaded = manager.get_client("name-check-ltd")
        assert loaded is not None
        assert loaded.name == "Name Check Ltd"

    def test_loaded_domains_match_original(self, manager: ClientManager) -> None:
        domains = ["a.example.com", "b.example.com"]
        client = _make_client(name="Domain Test", client_id="domain-test", domains=domains)
        manager.create_client(client)
        loaded = manager.get_client("domain-test")
        assert loaded is not None
        assert loaded.domains == domains

    def test_loaded_industry_matches(self, manager: ClientManager) -> None:
        client = _make_client(client_id="industry-test")
        client.industry = "financial"
        manager.create_client(client)
        loaded = manager.get_client("industry-test")
        assert loaded is not None
        assert loaded.industry == "financial"

    def test_loaded_contact_info_matches(self, manager: ClientManager) -> None:
        client = _make_client(client_id="contact-test")
        client.contact_name = "Jane Doe"
        client.contact_email = "jane@example.com"
        manager.create_client(client)
        loaded = manager.get_client("contact-test")
        assert loaded is not None
        assert loaded.contact_name == "Jane Doe"
        assert loaded.contact_email == "jane@example.com"


# ---------------------------------------------------------------------------
# ClientManager.list_clients
# ---------------------------------------------------------------------------


class TestListClients:
    def test_empty_dir_returns_empty_list(self, manager: ClientManager) -> None:
        assert manager.list_clients() == []

    def test_returns_all_clients(self, manager: ClientManager) -> None:
        manager.create_client(_make_client(name="Alpha", client_id="alpha"))
        manager.create_client(_make_client(name="Beta", client_id="beta"))
        manager.create_client(_make_client(name="Gamma", client_id="gamma"))
        clients = manager.list_clients()
        assert len(clients) == 3

    def test_client_ids_in_result(self, manager: ClientManager) -> None:
        manager.create_client(_make_client(name="Alpha", client_id="alpha"))
        manager.create_client(_make_client(name="Beta", client_id="beta"))
        ids = {c.id for c in manager.list_clients()}
        assert ids == {"alpha", "beta"}

    def test_returns_list_type(self, manager: ClientManager) -> None:
        assert isinstance(manager.list_clients(), list)

    def test_non_toml_files_ignored(self, manager: ClientManager, clients_dir: Path) -> None:
        manager.create_client(_make_client(client_id="real-client"))
        # Place a non-TOML file in the directory
        (clients_dir / "README.txt").write_text("ignore me", encoding="utf-8")
        clients = manager.list_clients()
        assert len(clients) == 1


# ---------------------------------------------------------------------------
# ClientManager.update_client
# ---------------------------------------------------------------------------


class TestUpdateClient:
    def test_update_modifies_existing_file(self, manager: ClientManager) -> None:
        client = _make_client(name="Original Name", client_id="updatable")
        manager.create_client(client)

        client.name = "Updated Name"
        manager.update_client(client)

        loaded = manager.get_client("updatable")
        assert loaded is not None
        assert loaded.name == "Updated Name"

    def test_update_changes_domains(self, manager: ClientManager) -> None:
        client = _make_client(client_id="domain-updatable", domains=["old.example.com"])
        manager.create_client(client)

        client.domains = ["new.example.com", "other.example.com"]
        manager.update_client(client)

        loaded = manager.get_client("domain-updatable")
        assert loaded is not None
        assert "new.example.com" in loaded.domains
        assert "old.example.com" not in loaded.domains

    def test_update_returns_path(self, manager: ClientManager) -> None:
        client = _make_client(client_id="path-test")
        manager.create_client(client)
        path = manager.update_client(client)
        assert isinstance(path, Path)
        assert path.exists()


# ---------------------------------------------------------------------------
# ClientManager.delete_client
# ---------------------------------------------------------------------------


class TestDeleteClient:
    def test_delete_removes_file(self, manager: ClientManager, clients_dir: Path) -> None:
        client = _make_client(client_id="to-delete")
        manager.create_client(client)
        toml_path = clients_dir / "to-delete.toml"
        assert toml_path.exists()

        manager.delete_client("to-delete")
        assert not toml_path.exists()

    def test_delete_returns_true_on_success(self, manager: ClientManager) -> None:
        client = _make_client(client_id="deletable")
        manager.create_client(client)
        result = manager.delete_client("deletable")
        assert result is True

    def test_delete_returns_false_for_nonexistent(self, manager: ClientManager) -> None:
        result = manager.delete_client("never-existed")
        assert result is False

    def test_deleted_client_not_returned_by_get(self, manager: ClientManager) -> None:
        client = _make_client(client_id="gone")
        manager.create_client(client)
        manager.delete_client("gone")
        assert manager.get_client("gone") is None

    def test_deleted_client_not_in_list(self, manager: ClientManager) -> None:
        manager.create_client(_make_client(name="Keep", client_id="keep"))
        manager.create_client(_make_client(name="Remove", client_id="remove"))
        manager.delete_client("remove")
        ids = {c.id for c in manager.list_clients()}
        assert "remove" not in ids
        assert "keep" in ids


# ---------------------------------------------------------------------------
# Client ID slugification
# ---------------------------------------------------------------------------


class TestClientIdSlugification:
    def test_create_client_auto_slugifies_name(self, manager: ClientManager) -> None:
        client = Client(id="", name="Big Corp Ltd", domains=["bigcorp.example.com"])
        manager.create_client(client)
        # The ID should have been set to the slugified name
        assert client.id == "big-corp-ltd"
        loaded = manager.get_client("big-corp-ltd")
        assert loaded is not None

    def test_explicit_id_not_overwritten(self, manager: ClientManager) -> None:
        client = Client(id="custom-id", name="Any Name", domains=["any.example.com"])
        manager.create_client(client)
        assert client.id == "custom-id"
        loaded = manager.get_client("custom-id")
        assert loaded is not None
        assert loaded.id == "custom-id"
