from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tools" / "run_scenario_matrix.py"


def load_matrix_module():
    spec = importlib.util.spec_from_file_location("run_scenario_matrix", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_scenario_catalog_covers_distinct_semantic_paths() -> None:
    matrix = load_matrix_module()

    assert set(matrix.SCENARIOS) == {
        "complex-business",
        "java-basic",
        "reflection",
        "native-jni",
        "resource-state",
    }
    assert matrix.SCENARIOS["java-basic"].package == "com.enko.test.scenario.javabasic"
    assert matrix.SCENARIOS["reflection"].activity == "com.enko.test.scenario.MainActivity"
    assert matrix.SCENARIOS["complex-business"].flag == "flag{enko_business_matrix_2026}"
    assert matrix.SCENARIOS["native-jni"].raw_apk.name == "app-nativeJni-debug.apk"
    assert matrix.SCENARIOS["resource-state"].gradle_task == ":app:assembleResourceStateDebug"


def test_selected_scenarios_preserves_cli_order() -> None:
    matrix = load_matrix_module()

    selected = matrix.selected_scenarios(["resource-state", "java-basic"])

    assert [scenario.name for scenario in selected] == ["resource-state", "java-basic"]


def test_harden_command_uses_lab_safe_full_protection_defaults(tmp_path: Path) -> None:
    matrix = load_matrix_module()
    args = matrix.build_parser().parse_args(
        [
            "--output-dir",
            str(tmp_path),
            "--target-abis",
            "arm64-v8a,x86_64",
            "--ollvm-required",
        ]
    )
    tools = {
        "ndk": Path("D:/Android/ndk"),
        "apktool": Path("D:/tools/apktool.bat"),
        "zipalign": Path("D:/Android/zipalign.exe"),
        "apksigner": Path("D:/Android/apksigner.bat"),
    }
    scenario = matrix.SCENARIOS["reflection"]

    cmd = matrix.harden_command(
        args,
        tools,
        scenario,
        Path("input.apk"),
        tmp_path / "out.apk",
        tmp_path / "out.report.json",
        "light",
    )

    assert "--risk-policy" in cmd and cmd[cmd.index("--risk-policy") + 1] == "log"
    assert "--risk-profile" in cmd and cmd[cmd.index("--risk-profile") + 1] == "compat"
    assert "--disable-root-check" in cmd
    assert "--disable-emulator-check" in cmd
    assert "--protection-map" in cmd
    assert "protection-map-ui-safe.txt" in cmd[cmd.index("--protection-map") + 1]
    assert "--vmp-shell-dex" in cmd
    assert "--polymorphic-shell" in cmd
    assert "--dex2c-ollvm-required" in cmd
    assert "--target-abis" in cmd and cmd[cmd.index("--target-abis") + 1] == "arm64-v8a,x86_64"
    assert "--sign" in cmd
    assert "--keystore" in cmd


def test_harden_command_can_emit_unsigned_external_signing_artifact(tmp_path: Path) -> None:
    matrix = load_matrix_module()
    args = matrix.build_parser().parse_args(
        [
            "--skip-sign",
            "--no-vmp-shell-dex",
            "--no-polymorphic-shell",
            "--no-dex2c-ollvm",
        ]
    )
    tools = {
        "ndk": Path("D:/Android/ndk"),
        "apktool": Path("D:/tools/apktool.bat"),
        "zipalign": Path("D:/Android/zipalign.exe"),
        "apksigner": Path("D:/Android/apksigner.bat"),
    }
    scenario = matrix.SCENARIOS["java-basic"]

    cmd = matrix.harden_command(
        args,
        tools,
        scenario,
        Path("input.apk"),
        tmp_path / "out.apk",
        tmp_path / "out.report.json",
        "stable",
    )

    assert "--skip-sign" in cmd
    assert "--sign" not in cmd
    assert "--keystore" not in cmd
    assert "--vmp-shell-dex" not in cmd
    assert "--polymorphic-shell" not in cmd
    assert "--no-dex2c-ollvm" in cmd


def test_smoke_command_records_per_variant_diagnostics(tmp_path: Path, monkeypatch) -> None:
    matrix = load_matrix_module()
    calls: list[list[str]] = []

    def fake_run(cmd, *, cwd=matrix.REPO_ROOT, timeout=300):
        calls.append(cmd)
        return None

    monkeypatch.setattr(matrix, "run", fake_run)
    args = matrix.build_parser().parse_args(
        [
            "--output-dir",
            str(tmp_path),
            "--diagnostics-dir",
            str(tmp_path / "diag"),
        ]
    )
    scenario = matrix.SCENARIOS["complex-business"]

    diag_dir = matrix.smoke_one(
        args,
        "adb",
        scenario,
        Path("app.apk"),
        variant="hardened-light",
    )

    cmd = calls[0]
    assert diag_dir == tmp_path / "diag" / "complex-business" / "hardened-light"
    assert "--diagnostics-dir" in cmd
    assert cmd[cmd.index("--diagnostics-dir") + 1] == str(diag_dir)
    assert "--post-success-wait" in cmd
    assert "--collect-success-diagnostics" in cmd
    assert "--trigger-id" in cmd
    assert f"{scenario.package}:id/btnState" in cmd


def test_stress_profile_selects_heavy_map() -> None:
    matrix = load_matrix_module()
    args = matrix.build_parser().parse_args(["--map-profile", "stress"])

    assert matrix.resolve_protection_map(args).name == "protection-map.txt"
