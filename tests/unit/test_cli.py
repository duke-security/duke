"""Tests for Duke's command-line interface."""

from typer.testing import CliRunner

from duke.cli.app import app

runner = CliRunner()


def test_help_displays_project_description() -> None:
    """The help command should explain Duke's purpose."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Learn Python through security detection" in result.stdout
    assert "version" in result.stdout


def test_version_displays_installed_version() -> None:
    """The version command should display Duke's installed version."""
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "Duke version 0.1.0" in result.stdout
