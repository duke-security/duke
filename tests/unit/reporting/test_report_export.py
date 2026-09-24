"""Tests for safe report export."""

from pathlib import Path

import pytest

from duke.reporting import export_report


def test_export_writes_content_and_creates_parent(tmp_path: Path, markdown) -> None:
    out = tmp_path / "nested" / "dir" / "report.md"

    result = export_report(markdown, out)

    assert result == out
    assert out.exists()
    assert out.read_text(encoding="utf-8") == markdown.rstrip("\n") + "\n"


def test_export_refuses_to_overwrite_without_force(tmp_path: Path, markdown) -> None:
    out = tmp_path / "report.md"
    out.write_text("existing", encoding="utf-8")

    with pytest.raises(FileExistsError):
        export_report(markdown, out)

    assert out.read_text(encoding="utf-8") == "existing"


def test_export_overwrites_with_force(tmp_path: Path, markdown) -> None:
    out = tmp_path / "report.md"
    out.write_text("existing", encoding="utf-8")

    export_report(markdown, out, overwrite=True)

    assert out.read_text(encoding="utf-8") == markdown.rstrip("\n") + "\n"


def test_export_is_byte_deterministic(tmp_path: Path, markdown) -> None:
    first = tmp_path / "a.md"
    second = tmp_path / "b.md"

    export_report(markdown, first)
    export_report(markdown, second)

    assert first.read_bytes() == second.read_bytes()
    assert first.read_bytes().endswith(b"\n")
    assert not first.read_bytes().endswith(b"\n\n")
