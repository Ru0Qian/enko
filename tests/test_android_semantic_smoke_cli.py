from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tools" / "android_semantic_smoke.py"


def load_smoke_module():
    spec = importlib.util.spec_from_file_location("android_semantic_smoke", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parser_exposes_diagnostics_and_health_check_options(tmp_path: Path) -> None:
    smoke = load_smoke_module()

    args = smoke.build_parser().parse_args(
        [
            "--apk",
            "app.apk",
            "--diagnostics-dir",
            str(tmp_path / "diag"),
            "--post-success-wait",
            "2.5",
            "--collect-success-diagnostics",
        ]
    )

    assert args.diagnostics_dir == str(tmp_path / "diag")
    assert args.post_success_wait == 2.5
    assert args.collect_success_diagnostics is True


def test_write_result_creates_structured_smoke_json(tmp_path: Path) -> None:
    smoke = load_smoke_module()
    args = smoke.build_parser().parse_args(
        [
            "--apk",
            "app.apk",
            "--package",
            "com.example.app",
            "--activity",
            ".MainActivity",
            "--diagnostics-dir",
            str(tmp_path),
        ]
    )

    smoke.write_result(
        args,
        ok=True,
        timings={"install": 123, "verify": 456},
        diagnostics={"logcat.txt": str(tmp_path / "logcat.txt")},
    )

    data = (tmp_path / "smoke-result.json").read_text(encoding="utf-8")
    assert '"ok": true' in data
    assert '"package": "com.example.app"' in data
    assert '"install": 123' in data
    assert "logcat.txt" in data
