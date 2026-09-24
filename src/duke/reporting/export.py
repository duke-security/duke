"""Safe export of rendered incident reports.

Mirrors the overwrite-protection contract of ``simulation.export``: an
existing output path is never silently replaced unless the caller
explicitly passes ``overwrite=True``.
"""

from pathlib import Path

__all__ = ["export_report"]


def export_report(
    markdown: str,
    output_path: Path,
    *,
    overwrite: bool = False,
) -> Path:
    """Write a rendered report without silently overwriting a file."""
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {output_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Guarantee exactly one trailing newline for byte-deterministic output.
    output_path.write_text(markdown.rstrip("\n") + "\n", encoding="utf-8")

    return output_path
