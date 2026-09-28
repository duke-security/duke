"""Safe atomic export of rendered incident reports.

Mirrors the overwrite-protection contract of ``simulation.export``: an
existing output path is never silently replaced unless the caller explicitly
passes ``overwrite=True``. Export is **atomic**: the complete content is first
written to a uniquely created temporary file in the destination directory,
flushed and closed, and only then published over the destination.

Publication is tailored to the overwrite mode:

- with ``overwrite=True`` the destination is replaced atomically via
  ``os.replace`` after the complete write succeeds;
- without ``overwrite`` the destination is published atomically and
  **without clobbering** via ``os.link``, which fails if the destination
  appeared between the initial existence pre-check and publication, closing
  the check-then-replace race.

A pre-existing destination is left unchanged if the write or publication
never completes, no new destination file is left behind on a failed first-time
export, and no orphan temporary file remains after a failure. The temporary
path is an implementation detail and never appears in output.
"""

import os
import tempfile
from pathlib import Path

__all__ = ["export_report"]


def export_report(
    markdown: str,
    output_path: Path,
    *,
    overwrite: bool = False,
) -> Path:
    """Write a rendered report atomically without silently overwriting a file."""
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {output_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Guarantee exactly one trailing newline for byte-deterministic output.
    content = markdown.rstrip("\n") + "\n"

    descriptor, tmp_path = tempfile.mkstemp(
        prefix=".duke-report-",
        suffix=".tmp",
        dir=str(output_path.parent),
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            # Atomic replace after the complete write succeeds.
            os.replace(tmp_path, output_path)
        else:
            # Atomic no-clobber publication: fails with FileExistsError if the
            # destination appeared since the pre-check, preserving it.
            os.link(tmp_path, output_path)
            os.unlink(tmp_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return output_path
