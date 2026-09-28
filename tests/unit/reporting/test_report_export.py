"""Tests for safe report export."""

import os
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


def test_export_leaves_no_orphan_temporary_file(tmp_path: Path, markdown) -> None:
    out = tmp_path / "report.md"
    export_report(markdown, out)
    leftovers = [p for p in tmp_path.iterdir() if p.name != "report.md"]
    assert leftovers == []


def test_export_does_not_partially_write_on_first_time_failure(
    tmp_path: Path, markdown, monkeypatch
) -> None:
    out = tmp_path / "report.md"

    def boom_link(src, dst):
        raise OSError("link failed")

    # The no-force path publishes via an atomic os.link; inject a failure there.
    monkeypatch.setattr(os, "link", boom_link)
    with pytest.raises(OSError, match="link failed"):
        export_report(markdown, out)

    # No destination and no orphan temp file.
    assert not out.exists()
    assert [p for p in tmp_path.iterdir()] == []


def test_export_with_force_failure_leaves_original_untouched(
    tmp_path: Path, markdown, monkeypatch
) -> None:
    out = tmp_path / "report.md"
    original = "pre-existing bytes"
    out.write_text(original, encoding="utf-8")

    def boom_replace(src, dst):
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", boom_replace)
    with pytest.raises(OSError, match="replace failed"):
        export_report(markdown, out, overwrite=True)

    # The pre-existing destination is unchanged and no temp file remains.
    assert out.read_text(encoding="utf-8") == original
    assert [p for p in tmp_path.iterdir()] == [out]


def test_export_cleans_up_temporary_file_on_write_error(
    tmp_path: Path, markdown, monkeypatch
) -> None:
    out = tmp_path / "report.md"

    import tempfile

    real_mkstemp = tempfile.mkstemp

    def fake_mkstemp(**kwargs):
        # Create a real temp file, then return an invalid descriptor so the
        # write step fails and the temporary path must be cleaned up.
        fd, name = real_mkstemp(**kwargs)
        os.close(fd)
        return -1, name

    monkeypatch.setattr(tempfile, "mkstemp", fake_mkstemp)
    with pytest.raises((OSError, ValueError)):
        export_report(markdown, out)

    # No destination and no orphan temp file.
    assert not out.exists()
    assert [p for p in tmp_path.iterdir()] == []


def test_export_successful_t1078_bytes_preserved(tmp_path: Path) -> None:
    """A successful export writes exactly the normalized markdown bytes."""
    markdown = "line1\nline2\n\n"
    out = tmp_path / "report.md"
    export_report(markdown, out)
    assert out.read_text(encoding="utf-8") == "line1\nline2\n"


def test_no_force_race_preserves_concurrent_destination(
    tmp_path: Path, markdown, monkeypatch
) -> None:
    """Without --force, a destination created after the pre-check but before
    publication is never overwritten (atomic no-clobber)."""
    out = tmp_path / "report.md"
    concurrent = "created by another process"

    real_link = os.link

    def racing_link(src, dst):
        # Simulate a concurrent writer creating the destination just before the
        # no-clobber publication.
        Path(dst).write_text(concurrent, encoding="utf-8")
        # The real link then fails because the destination now exists.
        real_link(src, dst)

    monkeypatch.setattr(os, "link", racing_link)
    with pytest.raises(FileExistsError):
        export_report(markdown, out, overwrite=False)

    # The concurrently-created destination is preserved byte-for-byte, no new
    # report appeared, and no orphan temp file remains.
    assert out.read_text(encoding="utf-8") == concurrent
    assert [p for p in tmp_path.iterdir()] == [out]


def test_force_race_replaces_as_authorized(
    tmp_path: Path, markdown, monkeypatch
) -> None:
    """With --force, a destination created during publication is replaced."""
    out = tmp_path / "report.md"
    real_replace = os.replace

    def racing_replace(src, dst):
        Path(dst).write_text("concurrent", encoding="utf-8")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", racing_replace)
    export_report(markdown, out, overwrite=True)

    # The authorized replacement wins.
    assert out.read_text(encoding="utf-8") == markdown.rstrip("\n") + "\n"
    assert [p for p in tmp_path.iterdir()] == [out]
