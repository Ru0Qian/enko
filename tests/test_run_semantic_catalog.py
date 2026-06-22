from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tools" / "run_semantic_catalog.py"


def load_catalog_module():
    spec = importlib.util.spec_from_file_location("run_semantic_catalog", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_catalog_covers_small_scenarios_and_real_sample() -> None:
    catalog_mod = load_catalog_module()
    entries = catalog_mod.build_catalog()
    ids = {entry.id for entry in entries}

    assert "small-raw-debug" in ids
    assert "small-hardened-current" in ids
    assert "scenario-raw-java-basic" in ids
    assert "scenario-raw-complex-business" in ids
    assert "scenario-hardened-complex-business" in ids
    assert "real-gagademo" in ids

    real = next(entry for entry in entries if entry.id == "real-gagademo")
    business = next(entry for entry in entries if entry.id == "scenario-raw-complex-business")
    assert real.semantic is False
    assert business.trigger_id.endswith(":id/btnState")
    assert business.flag == "flag{enko_business_matrix_2026}"


def test_smoke_command_includes_diagnostics_and_trigger(tmp_path: Path) -> None:
    catalog_mod = load_catalog_module()
    entry = next(
        item
        for item in catalog_mod.build_catalog()
        if item.id == "scenario-raw-complex-business"
    )

    cmd = catalog_mod.smoke_command(
        entry,
        adb="adb",
        diagnostics_dir=tmp_path,
        post_success_wait=1.5,
        collect_success_diagnostics=True,
    )

    assert "--diagnostics-dir" in cmd
    assert cmd[cmd.index("--diagnostics-dir") + 1] == str(tmp_path / entry.id)
    assert "--post-success-wait" in cmd
    assert cmd[cmd.index("--post-success-wait") + 1] == "1.5"
    assert "--collect-success-diagnostics" in cmd
    assert "--trigger-id" in cmd
    assert entry.trigger_id in cmd


def test_selected_entries_preserves_order() -> None:
    catalog_mod = load_catalog_module()
    selected = catalog_mod.selected_entries(
        catalog_mod.build_catalog(),
        ["real-gagademo", "small-raw-debug"],
    )

    assert [entry.id for entry in selected] == ["real-gagademo", "small-raw-debug"]


def test_run_cmd_converts_timeout_to_failed_result(monkeypatch) -> None:
    catalog_mod = load_catalog_module()

    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(["smoke"], timeout=7, output="partial log")

    monkeypatch.setattr(catalog_mod.subprocess, "run", fake_run)

    proc = catalog_mod.run_cmd(["smoke"], timeout=7)

    assert proc.returncode == 124
    assert "partial log" in proc.stdout
    assert "timed out after 7s" in proc.stdout


def test_force_stop_package_uses_adb_shell(monkeypatch) -> None:
    catalog_mod = load_catalog_module()
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout="")

    monkeypatch.setattr(catalog_mod.subprocess, "run", fake_run)

    catalog_mod.force_stop_package("adb", "com.example.app")
    catalog_mod.force_stop_package("adb", "")

    assert calls == [
        (
            ["adb", "shell", "am", "force-stop", "com.example.app"],
            {
                "text": True,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.STDOUT,
                "timeout": 20,
                "errors": "replace",
                "check": False,
            },
        )
    ]
