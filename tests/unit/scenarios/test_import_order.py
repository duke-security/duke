"""Fresh-process import-order tests for circular-import safety.

The scenario registry intentionally keeps ``duke.scenarios.builtins`` (the
composition root that imports the capability packages) separate from
``duke.scenarios.__init__`` to avoid a cycle through
``duke.simulation.t1078 -> duke.scenarios``. These tests load modules in a
clean interpreter each time so Python's import cache cannot mask a circular
import that only appears with a particular order.
"""

import os
import subprocess
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[3] / "src"


def _fresh_import(code: str, tmp_path: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(_SRC)}
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )


def test_import_cli_before_builtins(tmp_path: Path) -> None:
    proc = _fresh_import(
        "import duke.cli.app; import duke.scenarios.builtins",
        tmp_path,
    )
    assert proc.returncode == 0, proc.stderr


def test_import_builtins_before_cli(tmp_path: Path) -> None:
    proc = _fresh_import(
        "import duke.scenarios.builtins; import duke.cli.app",
        tmp_path,
    )
    assert proc.returncode == 0, proc.stderr
