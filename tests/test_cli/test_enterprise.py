"""Tests for enterprise CLI commands."""


import pytest
from typer.testing import CliRunner

from provchain.cli.main import app
from provchain.config import Config


@pytest.fixture
def runner():
    return CliRunner()


def test_login_command_persists_enterprise_config(runner, tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("provchain.cli.commands.enterprise.Path.home", lambda: tmp_path)
        result = runner.invoke(
            app,
            [
                "login",
                "--api-key",
                "pce_test_123",
                "--url",
                "https://enterprise.example.com",
            ],
        )

    assert result.exit_code == 0
    config = Config(config_path=tmp_path / ".provchain" / "config.toml")
    assert config.get("enterprise", "enabled") is True
    assert config.get("enterprise", "api_key") == "pce_test_123"
    assert config.get("enterprise", "api_url") == "https://enterprise.example.com"


def test_logout_command_clears_enterprise_api_key(runner, tmp_path):
    config_path = tmp_path / ".provchain" / "config.toml"
    config = Config(config_path=config_path)
    config.set("enterprise", "enabled", True)
    config.set("enterprise", "api_key", "pce_test_123")
    config.set("enterprise", "api_url", "https://enterprise.example.com")
    config.save()

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("provchain.cli.commands.enterprise.Path.home", lambda: tmp_path)
        result = runner.invoke(app, ["logout"])

    assert result.exit_code == 0
    refreshed = Config(config_path=config_path)
    assert refreshed.get("enterprise", "enabled") is False
    assert refreshed.get("enterprise", "api_key") == ""
