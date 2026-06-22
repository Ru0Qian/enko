from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tools" / "run_small_semantic_regression.py"


def load_regression_module():
    spec = importlib.util.spec_from_file_location("run_small_semantic_regression", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_small_smoke_command_uses_logcat_fallback_and_diagnostics(tmp_path: Path, monkeypatch) -> None:
    regression = load_regression_module()
    args = regression.build_parser().parse_args(
        [
            "--output-dir",
            str(tmp_path / "out"),
            "--adb",
            "adb",
            "--collect-success-diagnostics",
        ]
    )
    calls: list[tuple[list[str], int]] = []

    def fake_run(cmd: list[str], *, timeout: int = 300) -> None:
        calls.append((cmd, timeout))

    monkeypatch.setattr(regression, "run", fake_run)

    regression.smoke_one(args, tmp_path / "small-light.apk")

    assert len(calls) == 1
    cmd, timeout = calls[0]
    assert timeout == args.smoke_timeout
    assert "--expect-log" in cmd
    assert cmd[cmd.index("--expect-log") + 1] == "Hash verification: true"
    assert "--log-tag" in cmd
    assert cmd[cmd.index("--log-tag") + 1] == "SmallMain"
    assert "--post-success-wait" in cmd
    assert cmd[cmd.index("--post-success-wait") + 1] == "2.0"
    assert "--diagnostics-dir" in cmd
    assert cmd[cmd.index("--diagnostics-dir") + 1] == str(tmp_path / "out" / "diagnostics" / "small-light")
    assert "--collect-success-diagnostics" in cmd
    assert "--adb" in cmd
