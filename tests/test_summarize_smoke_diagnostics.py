from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tools" / "summarize_smoke_diagnostics.py"


def load_summary_module():
    spec = importlib.util.spec_from_file_location("summarize_smoke_diagnostics", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parse_proxy_timings_from_logcat() -> None:
    summary = load_summary_module()
    logcat = """
05-05 10:00:00.000  111  111 I ProxyApplication: timing: runtime-config=3ms
05-05 10:00:00.010  111  111 I ProxyApplication: timing: payload-decrypt-parse=17ms
05-05 10:00:00.020  111  111 I ProxyApplication: timing: install-payload.total=31ms
"""

    timings = summary.parse_proxy_timings(logcat)

    assert timings["runtime-config"] == 3
    assert timings["payload-decrypt-parse"] == 17
    assert timings["install-payload.total"] == 31


def test_extract_log_signals_keeps_anr_and_large_frame_skips() -> None:
    summary = load_summary_module()
    logcat = """
05-05 10:00:00.000  111  111 I Choreographer: Skipped 8 frames! The application may be doing too much work.
05-05 10:00:01.000  111  111 I Choreographer: Skipped 77 frames! The application may be doing too much work.
05-05 10:00:02.000  222  222 E ActivityManager: ANR in com.example.app
"""

    signals = summary.extract_log_signals(logcat, "com.example.app")

    assert len(signals) == 2
    assert "Skipped 77 frames" in signals[0]
    assert "ANR in com.example.app" in signals[1]


def test_summarize_result_collects_slow_stages_and_signals(tmp_path: Path) -> None:
    summary = load_summary_module()
    diag = tmp_path / "scenario-hardened-complex-business"
    diag.mkdir()
    (diag / "smoke-result.json").write_text(
        json.dumps(
            {
                "ok": True,
                "apk": "app.apk",
                "package": "com.example.app",
                "activity": ".MainActivity",
                "timings_ms": {"install": 100, "verify": 2500, "total": 3000},
                "error": "",
            }
        ),
        encoding="utf-8",
    )
    (diag / "logcat.txt").write_text(
        "05-05 10:00:00.000 I ProxyApplication: timing: vmp-register=2501ms\n"
        "05-05 10:00:01.000 I Choreographer: Skipped 45 frames! The application may be doing too much work.\n",
        encoding="utf-8",
    )

    entry = summary.summarize_result(diag / "smoke-result.json", slow_threshold_ms=2000)

    assert entry["id"] == "scenario-hardened-complex-business"
    assert entry["slow_stages"] == {"verify": 2500, "total": 3000}
    assert entry["proxy_slow_stages"] == {"vmp-register": 2501}
    assert len(entry["signals"]) == 1


def test_main_writes_json_and_markdown(tmp_path: Path) -> None:
    summary = load_summary_module()
    diag = tmp_path / "diag" / "small"
    diag.mkdir(parents=True)
    (diag / "smoke-result.json").write_text(
        json.dumps(
            {
                "ok": True,
                "package": "com.example.app",
                "activity": ".MainActivity",
                "timings_ms": {"total": 120},
                "error": "",
            }
        ),
        encoding="utf-8",
    )

    json_out = tmp_path / "summary.json"
    md_out = tmp_path / "summary.md"
    code = summary.main(
        [
            "--diagnostics-dir",
            str(tmp_path / "diag"),
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(md_out),
        ]
    )

    assert code == 0
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["summary"]["passed"] == 1
    assert "| small | PASS | 120 |" in md_out.read_text(encoding="utf-8")
