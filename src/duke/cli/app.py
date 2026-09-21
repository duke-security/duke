"""Command-line interface for Duke."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version

import typer
from rich.console import Console

app = typer.Typer(
    name="duke",
    help="Learn Python through security detection, investigation, and response.",
    no_args_is_help=True,
)

console = Console()


def get_version() -> str:
    """Return the installed Duke version."""
    try:
        return package_version("duke-security")
    except PackageNotFoundError:
        return "unknown"


@app.callback()
def main() -> None:
    """Learn Python through modern security-engineering workflows."""



@app.command()
def version() -> None:
    """Display the installed Duke version."""
    console.print(f"Duke version {get_version()}")


if __name__ == "__main__":
    app()
