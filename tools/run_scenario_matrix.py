from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_APP_DIR = REPO_ROOT / "test_apks" / "scenario_app"
STRESS_PROTECTION_MAP = SCENARIO_APP_DIR / "protection-map.txt"
UI_SAFE_PROTECTION_MAP = SCENARIO_APP_DIR / "protection-map-ui-safe.txt"
DEFAULT_KEYSTORE = REPO_ROOT / "enko-ci.jks"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "output" / "scenario-matrix"
DEFAULT_FLAG = "flag{enko_matrix_2026}"
DEFAULT_EXPECT_TEXT = "CORRECT! Flag accepted"
DEFAULT_READY_TEXT = "App started successfully"
DEFAULT_OLLVM_CLANG = Path("D:/Env/tool/hikari-llvm19/install/bin/clang.exe")


class MatrixError(RuntimeError):
    pass


@dataclass(frozen=True)
class Scenario:
    name: str
    flavor: str
    package: str
    activity: str
    flag: str
    description: str

    @property
    def gradle_task(self) -> str:
        return f":app:assemble{self.flavor[0].upper()}{self.flavor[1:]}Debug"

    @property
    def raw_apk(self) -> Path:
        return (
            SCENARIO_APP_DIR
            / "app"
            / "build"
            / "outputs"
            / "apk"
            / self.flavor
            / "debug"
            / f"app-{self.flavor}-debug.apk"
        )


SCENARIOS: dict[str, Scenario] = {
    "java-basic": Scenario(
        name="java-basic",
        flavor="javaBasic",
        package="com.enko.test.scenario.javabasic",
        activity="com.enko.test.scenario.MainActivity",
        flag=DEFAULT_FLAG,
        description="pure Java string, hash, loop, and byte-array logic",
    ),
    "reflection": Scenario(
        name="reflection",
        flavor="reflection",
        package="com.enko.test.scenario.reflection",
        activity="com.enko.test.scenario.MainActivity",
        flag=DEFAULT_FLAG,
        description="Class.forName, Method.invoke, and hidden helper methods",
    ),
    "native-jni": Scenario(
        name="native-jni",
        flavor="nativeJni",
        package="com.enko.test.scenario.nativejni",
        activity="com.enko.test.scenario.MainActivity",
        flag=DEFAULT_FLAG,
        description="Java wrapper plus business native library verification",
    ),
    "resource-state": Scenario(
        name="resource-state",
        flavor="resourceState",
        package="com.enko.test.scenario.resstate",
        activity="com.enko.test.scenario.MainActivity",
        flag=DEFAULT_FLAG,
        description="raw resource decoding plus SharedPreferences state",
    ),
    "complex-business": Scenario(
        name="complex-business",
        flavor="complexBusiness",
        package="com.enko.test.scenario.business",
        activity="com.enko.test.scenario.MainActivity",
        flag="flag{enko_business_matrix_2026}",
        description="triggered business flow, SQLite order, pricing, resource license, reflection, and JNI rules",
    ),
}


def run(cmd: list[str], *, cwd: Path = REPO_ROOT, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    print("[cmd]", " ".join(str(part) for part in cmd))
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        errors="replace",
    )
    if proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
    if proc.returncode != 0:
        raise MatrixError(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc


def first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


def sdk_roots() -> list[Path]:
    roots: list[Path] = []
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.environ.get(key)
        if value:
            roots.append(Path(value))
    roots.append(Path("D:/Env/tool/Android-Sdk"))
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append(Path(local) / "Android" / "Sdk")
    return [root for root in roots if root.exists()]


def newest_child(parent: Path) -> Path | None:
    if not parent.exists():
        return None
    children = [child for child in parent.iterdir() if child.is_dir()]
    if not children:
        return None
    return sorted(children, key=lambda p: p.name)[-1]


def find_build_tool(name: str) -> Path | None:
    found = shutil.which(name)
    if found:
        return Path(found)
    if os.name == "nt" and not name.lower().endswith((".exe", ".bat", ".cmd")):
        for suffix in (".exe", ".bat", ".cmd"):
            found = shutil.which(name + suffix)
            if found:
                return Path(found)
    for root in sdk_roots():
        build_tools = newest_child(root / "build-tools")
        if not build_tools:
            continue
        for candidate in (
            build_tools / name,
            build_tools / f"{name}.exe",
            build_tools / f"{name}.bat",
            build_tools / f"{name}.cmd",
        ):
            if candidate.exists():
                return candidate
    return None


def find_ndk() -> Path | None:
    for key in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"):
        value = os.environ.get(key)
        if value and Path(value).exists():
            return Path(value)
    for root in sdk_roots():
        ndk = newest_child(root / "ndk")
        if ndk:
            return ndk
    return None


def default_shell_apk() -> Path:
    return first_existing(
        [
            REPO_ROOT / "shell-app" / "app" / "build" / "outputs" / "apk" / "release" / "app-release-unsigned.apk",
            REPO_ROOT / "shell-app" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk",
        ]
    ) or REPO_ROOT / "shell-app" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"


def default_gradle() -> Path | None:
    bundled = REPO_ROOT / "tools" / "gradle-8.2.1" / "bin" / ("gradle.bat" if os.name == "nt" else "gradle")
    if bundled.exists():
        return bundled
    found = shutil.which("gradle")
    return Path(found) if found else None


def resolve_tools(args: argparse.Namespace, *, need_harden: bool) -> dict[str, Path]:
    gradle = Path(args.gradle) if args.gradle else default_gradle()
    if not gradle:
        raise MatrixError("missing gradle. Set --gradle or keep tools/gradle-8.2.1 available.")

    tools = {"gradle": gradle}
    if not need_harden:
        return tools

    apktool = Path(args.apktool) if args.apktool else first_existing([REPO_ROOT / "tools" / "apktool.bat"])
    if not apktool:
        found = shutil.which("apktool")
        apktool = Path(found) if found else None

    zipalign = Path(args.zipalign) if args.zipalign else find_build_tool("zipalign")
    apksigner = Path(args.apksigner) if args.apksigner else find_build_tool("apksigner")
    ndk = Path(args.ndk_path) if args.ndk_path else find_ndk()

    missing = []
    if not apktool:
        missing.append("apktool")
    if not zipalign:
        missing.append("zipalign")
    if not apksigner:
        missing.append("apksigner")
    if not ndk:
        missing.append("ndk")
    if missing:
        raise MatrixError("missing tool(s): " + ", ".join(missing))

    tools.update(
        {
            "apktool": apktool,
            "zipalign": zipalign,
            "apksigner": apksigner,
            "ndk": ndk,
        }
    )
    return tools


def selected_scenarios(names: list[str] | None) -> list[Scenario]:
    if not names:
        return list(SCENARIOS.values())
    selected: list[Scenario] = []
    for name in names:
        try:
            selected.append(SCENARIOS[name])
        except KeyError as exc:
            raise MatrixError(f"unknown scenario: {name}") from exc
    return selected


def require_file(path: Path, label: str) -> None:
    if not path.exists():
        raise MatrixError(f"{label} not found: {path}")


def build_scenario_apks(
    scenarios: list[Scenario],
    gradle: Path,
    *,
    skip_build: bool,
    timeout: int,
) -> dict[str, Path]:
    if not skip_build:
        if len(scenarios) == len(SCENARIOS):
            run([str(gradle), "assembleDebug"], cwd=SCENARIO_APP_DIR, timeout=timeout)
        else:
            run([str(gradle), *(scenario.gradle_task for scenario in scenarios)], cwd=SCENARIO_APP_DIR, timeout=timeout)

    raw_apks: dict[str, Path] = {}
    for scenario in scenarios:
        raw_apk = scenario.raw_apk.resolve()
        require_file(raw_apk, f"{scenario.name} raw APK")
        raw_apks[scenario.name] = raw_apk
    return raw_apks


def harden_command(
    args: argparse.Namespace,
    tools: dict[str, Path],
    scenario: Scenario,
    input_apk: Path,
    output_apk: Path,
    report_json: Path,
    preset: str,
) -> list[str]:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "packer" / "harden_apk.py"),
        "--input-apk",
        str(input_apk),
        "--shell-apk",
        str(Path(args.shell_apk).resolve()),
        "--output-apk",
        str(output_apk),
        "--risk-policy",
        args.risk_policy,
        "--risk-profile",
        args.risk_profile,
        "--allow-proxy-vpn",
        "--disable-root-check",
        "--disable-emulator-check",
        "--per-apk-key",
        "--protection-map",
        str(resolve_protection_map(args)),
        "--vmp-dex-obfuscation-preset",
        preset,
        "--ndk-path",
        str(tools["ndk"]),
        "--apktool",
        str(tools["apktool"]),
        "--zipalign",
        str(tools["zipalign"]),
        "--apksigner",
        str(tools["apksigner"]),
        "--report-json",
        str(report_json),
    ]

    if args.vmp_shell_dex:
        cmd.append("--vmp-shell-dex")
    if args.polymorphic_shell:
        cmd.append("--polymorphic-shell")
    if args.ollvm_required:
        cmd.append("--dex2c-ollvm-required")
    if args.no_dex2c_ollvm:
        cmd.append("--no-dex2c-ollvm")
    if args.ollvm_clang:
        cmd.extend(["--dex2c-ollvm-clang", str(Path(args.ollvm_clang).resolve())])
    if args.target_abis:
        cmd.extend(["--target-abis", args.target_abis])
    if args.min_extract_count >= 0:
        cmd.extend(["--min-extract-count", str(args.min_extract_count)])
    if args.min_vmp_dex_count >= 0:
        cmd.extend(["--min-vmp-dex-count", str(args.min_vmp_dex_count)])
    if args.min_dex2c_count >= 0:
        cmd.extend(["--min-dex2c-count", str(args.min_dex2c_count)])
    if args.min_security_score > 0:
        cmd.extend(["--min-security-score", str(args.min_security_score)])
    if args.skip_sign:
        cmd.append("--skip-sign")
    else:
        cmd.extend(
            [
                "--sign",
                "--keystore",
                str(Path(args.keystore).resolve()),
                "--ks-pass",
                args.ks_pass,
                "--key-alias",
                args.key_alias,
                "--key-pass",
                args.key_pass,
            ]
        )
    return cmd


def harden_one(
    args: argparse.Namespace,
    tools: dict[str, Path],
    scenario: Scenario,
    input_apk: Path,
    preset: str,
) -> Path:
    output_dir = Path(args.output_dir).resolve() / args.map_profile / scenario.name / preset
    output_dir.mkdir(parents=True, exist_ok=True)
    output_apk = output_dir / f"{scenario.name}-{args.map_profile}-{preset}.apk"
    report_json = output_dir / f"{scenario.name}-{args.map_profile}-{preset}.report.json"
    cmd = harden_command(args, tools, scenario, input_apk, output_apk, report_json, preset)
    run(cmd, timeout=args.harden_timeout)
    return output_apk


def resolve_adb(adb_arg: str) -> str | None:
    if adb_arg:
        return adb_arg
    return os.environ.get("ADB") or shutil.which("adb")


def adb_has_online_device(adb: str) -> bool:
    try:
        proc = subprocess.run(
            [adb, "get-state"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "device"


def smoke_adb(args: argparse.Namespace) -> str | None:
    if args.smoke == "never":
        return None
    adb = resolve_adb(args.adb)
    if adb and adb_has_online_device(adb):
        return adb
    if args.smoke == "always":
        raise MatrixError("no online Android device/emulator for --smoke always")
    print("[scenario-matrix] no online Android device/emulator; skipping smoke tests")
    return None


def smoke_diagnostics_dir(
    args: argparse.Namespace,
    scenario: Scenario,
    *,
    variant: str,
) -> Path:
    root = (
        Path(args.diagnostics_dir).resolve()
        if args.diagnostics_dir
        else Path(args.output_dir).resolve() / args.map_profile / "diagnostics"
    )
    return root / scenario.name / variant


def smoke_one(
    args: argparse.Namespace,
    adb: str,
    scenario: Scenario,
    apk: Path,
    *,
    variant: str,
) -> Path:
    diag_dir = smoke_diagnostics_dir(args, scenario, variant=variant)
    cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "android_semantic_smoke.py"),
        "--apk",
        str(apk),
        "--package",
        scenario.package,
        "--activity",
        scenario.activity,
        "--flag",
        args.flag or scenario.flag,
        "--expect-text",
        args.expect_text,
        "--expect-log",
        args.expect_log,
        "--ready-text",
        args.ready_text,
        "--adb",
        adb,
        "--expect-timeout",
        str(args.expect_timeout),
        "--post-success-wait",
        str(args.post_success_wait),
        "--diagnostics-dir",
        str(diag_dir),
    ]
    if args.collect_success_diagnostics:
        cmd.append("--collect-success-diagnostics")
    if scenario.name == "complex-business":
        cmd.extend(
            [
                "--trigger-id",
                f"{scenario.package}:id/btnState",
                "--trigger-ready-text",
                "Business trigger ready",
                "--trigger-log",
                "business trigger ready",
                "--trigger-timeout",
                str(args.expect_timeout),
            ]
        )
    run(cmd, timeout=args.smoke_timeout)
    return diag_dir


def write_summary(args: argparse.Namespace, summary: dict[str, object]) -> None:
    path = Path(args.summary_json or Path(args.output_dir).resolve() / args.map_profile / "summary.json").resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[scenario-matrix] summary: {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build, harden, and optionally Android-smoke multiple Enko semantic scenario APKs."
    )
    parser.add_argument(
        "--scenario",
        action="append",
        choices=sorted(SCENARIOS),
        help="Scenario to run. Can be passed multiple times. Defaults to all scenarios.",
    )
    parser.add_argument(
        "--preset",
        action="append",
        choices=("stable", "light", "medium"),
        help="VMP obfuscation preset to harden. Can be passed multiple times. Defaults to light.",
    )
    parser.add_argument("--skip-build", action="store_true", help="Use existing scenario APKs.")
    parser.add_argument("--skip-harden", action="store_true", help="Only build/smoke raw scenario APKs.")
    parser.add_argument(
        "--smoke",
        choices=("auto", "always", "never"),
        default="auto",
        help="Run Android semantic smoke tests. auto runs only when an online device is present.",
    )
    parser.add_argument(
        "--smoke-raw",
        action="store_true",
        help="Also smoke raw debug APKs before hardening when a device is available.",
    )
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--summary-json", default="")
    parser.add_argument("--shell-apk", default=str(default_shell_apk()))
    parser.add_argument(
        "--map-profile",
        default="ui-safe",
        choices=("ui-safe", "stress"),
        help="ui-safe keeps UI wrappers fast; stress uses the heavier full protection map.",
    )
    parser.add_argument(
        "--protection-map",
        default="",
        help="Override the selected map profile with an explicit protection-map path.",
    )
    parser.add_argument("--keystore", default=str(DEFAULT_KEYSTORE))
    parser.add_argument("--ks-pass", default="enkotest")
    parser.add_argument("--key-alias", default="enko")
    parser.add_argument("--key-pass", default="enkotest")
    parser.add_argument(
        "--skip-sign",
        action="store_true",
        help="Leave hardened APKs unsigned/aligned for external signing. Smoke tests require signed APKs.",
    )
    parser.add_argument("--risk-policy", default="log", choices=("block", "degrade", "warn", "log", "off"))
    parser.add_argument("--risk-profile", default="compat", choices=("strict", "balanced", "compat"))
    parser.add_argument("--target-abis", default="", help="Comma-separated ABIs, e.g. arm64-v8a,x86_64.")
    parser.add_argument("--vmp-shell-dex", dest="vmp_shell_dex", action="store_true", default=True)
    parser.add_argument("--no-vmp-shell-dex", dest="vmp_shell_dex", action="store_false")
    parser.add_argument("--polymorphic-shell", dest="polymorphic_shell", action="store_true", default=True)
    parser.add_argument("--no-polymorphic-shell", dest="polymorphic_shell", action="store_false")
    parser.add_argument("--no-dex2c-ollvm", action="store_true", help="Disable default DEX2C OLLVM/Hikari compile.")
    parser.add_argument("--ollvm-clang", default=str(DEFAULT_OLLVM_CLANG))
    parser.add_argument("--ollvm-required", action="store_true")
    parser.add_argument("--min-extract-count", type=int, default=0)
    parser.add_argument("--min-vmp-dex-count", type=int, default=1)
    parser.add_argument("--min-dex2c-count", type=int, default=0)
    parser.add_argument("--min-security-score", type=int, default=0)
    parser.add_argument("--flag", default="", help="Override the scenario's default flag.")
    parser.add_argument("--expect-text", default=DEFAULT_EXPECT_TEXT)
    parser.add_argument("--expect-log", default="verify result=true")
    parser.add_argument("--ready-text", default=DEFAULT_READY_TEXT)
    parser.add_argument("--adb", default="")
    parser.add_argument("--gradle", default="")
    parser.add_argument("--apktool", default="")
    parser.add_argument("--zipalign", default="")
    parser.add_argument("--apksigner", default="")
    parser.add_argument("--ndk-path", default="")
    parser.add_argument("--build-timeout", type=int, default=600)
    parser.add_argument("--harden-timeout", type=int, default=900)
    parser.add_argument("--smoke-timeout", type=int, default=180)
    parser.add_argument("--expect-timeout", type=int, default=20)
    parser.add_argument("--post-success-wait", type=float, default=1.0)
    parser.add_argument(
        "--diagnostics-dir",
        default="",
        help="Root directory for per-scenario smoke diagnostics. Defaults under output/<map-profile>/diagnostics.",
    )
    parser.add_argument(
        "--collect-success-diagnostics",
        action="store_true",
        default=True,
        help="Collect logcat/UI/dumpsys artifacts for passing smoke tests too.",
    )
    parser.add_argument(
        "--no-collect-success-diagnostics",
        dest="collect_success_diagnostics",
        action="store_false",
    )
    return parser


def resolve_protection_map(args: argparse.Namespace) -> Path:
    if args.protection_map:
        return Path(args.protection_map).resolve()
    if args.map_profile == "stress":
        return STRESS_PROTECTION_MAP.resolve()
    return UI_SAFE_PROTECTION_MAP.resolve()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    presets = args.preset or ["light"]

    try:
        scenarios = selected_scenarios(args.scenario)
        require_file(SCENARIO_APP_DIR / "settings.gradle", "scenario Gradle project")
        args.protection_map = str(resolve_protection_map(args))
        if not args.skip_harden:
            require_file(Path(args.shell_apk).resolve(), "shell APK")
            require_file(Path(args.protection_map).resolve(), "protection map")
            if not args.skip_sign:
                require_file(Path(args.keystore).resolve(), "keystore")

        tools = resolve_tools(args, need_harden=not args.skip_harden)
        print("[scenario-matrix] tools:")
        for name, path in tools.items():
            print(f"  {name}: {path}")

        print("[scenario-matrix] scenarios:")
        for scenario in scenarios:
            print(f"  {scenario.name}: {scenario.description}")

        raw_apks = build_scenario_apks(
            scenarios,
            tools["gradle"],
            skip_build=args.skip_build,
            timeout=args.build_timeout,
        )

        adb = smoke_adb(args)
        smoke_hardened = bool(adb)
        if args.skip_sign and not args.skip_harden:
            smoke_hardened = False
            if args.smoke == "always":
                raise MatrixError("--smoke always cannot install unsigned hardened APKs; remove --skip-sign")
            if adb:
                print("[scenario-matrix] --skip-sign set; skipping hardened APK smoke tests")
        summary: dict[str, object] = {
            "flag_override": args.flag,
            "map_profile": args.map_profile,
            "presets": presets,
            "scenarios": {},
        }
        raw_smoke_diagnostics: dict[str, str] = {}

        if adb and (args.smoke_raw or args.skip_harden):
            for scenario in scenarios:
                print(f"[scenario-matrix] raw Android smoke scenario={scenario.name}")
                diag_dir = smoke_one(args, adb, scenario, raw_apks[scenario.name], variant="raw")
                raw_smoke_diagnostics[scenario.name] = str(diag_dir)

        for scenario in scenarios:
            scenario_summary: dict[str, object] = {
                "package": scenario.package,
                "activity": scenario.activity,
                "flag": args.flag or scenario.flag,
                "raw_apk": str(raw_apks[scenario.name]),
                "smoke_diagnostics": {
                    "raw": raw_smoke_diagnostics.get(scenario.name, ""),
                },
                "hardened": {},
            }
            if not args.skip_harden:
                for preset in presets:
                    print(f"[scenario-matrix] hardening scenario={scenario.name} preset={preset}")
                    hardened_apk = harden_one(args, tools, scenario, raw_apks[scenario.name], preset)
                    scenario_summary["hardened"][preset] = str(hardened_apk)
                    if smoke_hardened:
                        print(f"[scenario-matrix] hardened Android smoke scenario={scenario.name} preset={preset}")
                        diag_dir = smoke_one(
                            args,
                            adb,
                            scenario,
                            hardened_apk,
                            variant=f"hardened-{preset}",
                        )
                        scenario_summary["smoke_diagnostics"][preset] = str(diag_dir)
            summary["scenarios"][scenario.name] = scenario_summary

        write_summary(args, summary)
        print("[scenario-matrix] PASS")
        return 0
    except (MatrixError, subprocess.TimeoutExpired) as exc:
        print(f"[scenario-matrix] FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
