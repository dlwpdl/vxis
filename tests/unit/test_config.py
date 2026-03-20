"""
Unit tests for vxis.config.schema.

All tests operate on default-constructed objects or monkeypatched env vars so
no real filesystem state, .env file, or running services are required.
"""

from __future__ import annotations

import pytest

from vxis.config.schema import (
    ScanProfile,
    ToolSettings,
    VXISConfig,
)


# ---------------------------------------------------------------------------
# ToolSettings defaults
# ---------------------------------------------------------------------------


class TestToolSettingsDefaults:
    def test_enabled_is_true_by_default(self) -> None:
        ts = ToolSettings()
        assert ts.enabled is True

    def test_extra_args_is_empty_string_by_default(self) -> None:
        ts = ToolSettings()
        assert ts.extra_args == ""

    def test_timeout_override_is_none_by_default(self) -> None:
        ts = ToolSettings()
        assert ts.timeout_override is None

    def test_can_disable_tool(self) -> None:
        ts = ToolSettings(enabled=False)
        assert ts.enabled is False

    def test_can_set_timeout_override(self) -> None:
        ts = ToolSettings(timeout_override=30)
        assert ts.timeout_override == 30


# ---------------------------------------------------------------------------
# Default scan profiles
# ---------------------------------------------------------------------------


class TestDefaultProfiles:
    """VXISConfig must ship with exactly the four canonical profiles."""

    @pytest.fixture()
    def config(self) -> VXISConfig:
        # Instantiate with no env vars / .env so we test pure defaults.
        return VXISConfig()

    def test_four_default_profiles_exist(self, config: VXISConfig) -> None:
        assert set(config.profiles.keys()) == {
            "passive",
            "stealth",
            "standard",
            "aggressive",
        }

    def test_passive_profile_is_scan_profile_instance(self, config: VXISConfig) -> None:
        assert isinstance(config.profiles["passive"], ScanProfile)

    def test_stealth_rate_limit_less_than_standard(self, config: VXISConfig) -> None:
        stealth = config.profiles["stealth"]
        standard = config.profiles["standard"]
        assert stealth.rate_limit < standard.rate_limit

    def test_aggressive_max_concurrency_at_least_8(self, config: VXISConfig) -> None:
        aggressive = config.profiles["aggressive"]
        assert aggressive.max_concurrency >= 8

    def test_passive_rate_limit_is_zero(self, config: VXISConfig) -> None:
        """Passive profile makes no direct network requests; rate limit is 0."""
        assert config.profiles["passive"].rate_limit == 0

    def test_stealth_max_concurrency_less_than_aggressive(
        self, config: VXISConfig
    ) -> None:
        assert (
            config.profiles["stealth"].max_concurrency
            < config.profiles["aggressive"].max_concurrency
        )

    def test_profile_names_match_dict_keys(self, config: VXISConfig) -> None:
        """The ScanProfile.name field must be consistent with its dict key."""
        for key, profile in config.profiles.items():
            assert profile.name == key


# ---------------------------------------------------------------------------
# VXISConfig infrastructure defaults
# ---------------------------------------------------------------------------


class TestVXISConfigDefaults:
    @pytest.fixture()
    def config(self) -> VXISConfig:
        return VXISConfig()

    def test_default_db_url_contains_sqlite(self, config: VXISConfig) -> None:
        assert "sqlite" in config.db_url

    def test_default_log_level_is_info(self, config: VXISConfig) -> None:
        assert config.log_level == "INFO"

    def test_report_company_name_default(self, config: VXISConfig) -> None:
        assert config.report_company_name == "VXIS Security"

    def test_tools_dict_is_empty_by_default(self, config: VXISConfig) -> None:
        assert config.tools == {}


# ---------------------------------------------------------------------------
# SecretStr fields default to None
# ---------------------------------------------------------------------------


class TestSecretStrDefaults:
    @pytest.fixture()
    def config(self) -> VXISConfig:
        return VXISConfig()

    def test_shodan_api_key_defaults_to_none(self, config: VXISConfig) -> None:
        assert config.shodan_api_key is None

    def test_censys_api_id_defaults_to_none(self, config: VXISConfig) -> None:
        assert config.censys_api_id is None

    def test_censys_api_secret_defaults_to_none(self, config: VXISConfig) -> None:
        assert config.censys_api_secret is None

    def test_anthropic_api_key_defaults_to_none(self, config: VXISConfig) -> None:
        assert config.anthropic_api_key is None

    def test_github_token_defaults_to_none(self, config: VXISConfig) -> None:
        assert config.github_token is None


# ---------------------------------------------------------------------------
# Environment variable override
# ---------------------------------------------------------------------------


class TestEnvVarOverride:
    def test_log_level_overridden_by_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VXIS_LOG_LEVEL", "DEBUG")
        config = VXISConfig()
        assert config.log_level == "DEBUG"

    def test_log_level_warning_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VXIS_LOG_LEVEL", "WARNING")
        config = VXISConfig()
        assert config.log_level == "WARNING"

    def test_report_company_name_overridden_by_env_var(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("VXIS_REPORT_COMPANY_NAME", "Acme Corp")
        config = VXISConfig()
        assert config.report_company_name == "Acme Corp"

    def test_db_url_overridden_by_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VXIS_DB_URL", "postgresql+asyncpg://localhost/vxis_test")
        config = VXISConfig()
        assert config.db_url == "postgresql+asyncpg://localhost/vxis_test"

    def test_shodan_api_key_set_via_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VXIS_SHODAN_API_KEY", "test-key-abc123")
        config = VXISConfig()
        assert config.shodan_api_key is not None
        # SecretStr — raw value must be accessed via get_secret_value()
        assert config.shodan_api_key.get_secret_value() == "test-key-abc123"

    def test_secret_str_not_leaked_in_repr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SecretStr must not expose the secret in string representation."""
        monkeypatch.setenv("VXIS_ANTHROPIC_API_KEY", "sk-ant-super-secret")
        config = VXISConfig()
        assert "sk-ant-super-secret" not in repr(config)
        assert "sk-ant-super-secret" not in str(config.anthropic_api_key)
