from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT_APK = REPO_ROOT / "test_apks" / "small_app" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
DEFAULT_EXTRACT_MAP = REPO_ROOT / "test_apks" / "flag_extract_methods.txt"
DEFAULT_VMP_MAP = REPO_ROOT / "test_apks" / "flag_vmp_methods.txt"
DEFAULT_KEYSTORE = REPO_ROOT / "enko-ci.jks"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "output" / "semantic-regression"
DEFAULT_PACKAGE = "com.enko.test.small"
DEFAULT_ACTIVITY = ".MainActivity"
DEFAULT_FLAG = "flag{3nk0_h4rd3n1ng_r3v3rs3_2026}"
DEFAULT_READY_TEXT = "App started successfully"
DEFAULT_EXPECT_TEXT = "CORRECT! Flag accepted"
DEFAULT_EXPECT_LOG = "Hash verification: true"
DEFAULT_LOG_TAG = "SmallMain"


class RegressionError(RuntimeError):
    pass


def run(cmd: list[str], *, timeout: int = 300) -> None:
    print("[cmd]", " ".join(str(part) for part in cmd))
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        errors="replace",
    )
    if proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
    if proc.returncode != 0:
        raise RegressionError(f"command failed ({proc.returncode}): {' '.join(cmd)}")


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


def require_file(path: Path, label: str) -> None:
    if not path.exists():
        raise RegressionError(f"{label} not found: {path}")


def resolve_tools(args: argparse.Namespace) -> dict[str, Path]:
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
        raise RegressionError("missing tool(s): " + ", ".join(missing))

    return {
        "apktool": apktool,
        "zipalign": zipalign,
        "apksigner": apksigner,
        "ndk": ndk,
    }


def harden_one(args: argparse.Namespace, tools: dict[str, Path], preset: str) -> Path:
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_apk = output_dir / f"small-{preset}.apk"
    report_json = output_dir / f"small-{preset}.report.json"

    cmd = [
        sys.executable,
        str(REPO_ROOT / "packer" / "harden_apk.py"),
        "--input-apk",
        str(Path(args.input_apk).resolve()),
        "--shell-apk",
        str(Path(args.shell_apk).resolve()),
        "--output-apk",
        str(output_apk),
        "--sign",
        "--keystore",
        str(Path(args.keystore).resolve()),
        "--ks-pass",
        args.ks_pass,
        "--key-alias",
        args.key_alias,
        "--key-pass",
        args.key_pass,
        "--risk-policy",
        "log",
        "--risk-profile",
        "compat",
        "--disable-root-check",
        "--disable-emulator-check",
        "--allow-proxy-vpn",
        "--per-apk-key",
        "--extract-methods",
        str(Path(args.extract_methods).resolve()),
        "--vmp-dex-methods",
        str(Path(args.vmp_methods).resolve()),
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
    run(cmd, timeout=args.harden_timeout)
    return output_apk


def smoke_one(args: argparse.Namespace, apk: Path) -> None:
    diagnostics_dir = Path(args.diagnostics_dir).resolve() if args.diagnostics_dir else Path(args.output_dir).resolve() / "diagnostics"
    cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "android_semantic_smoke.py"),
        "--apk",
        str(apk),
        "--package",
        args.package,
        "--activity",
        args.activity,
        "--flag",
        args.flag,
        "--ready-text",
        args.ready_text,
        "--expect-text",
        args.expect_text,
        "--expect-log",
        args.expect_log,
        "--log-tag",
        args.log_tag,
        "--expect-timeout",
        str(args.expect_timeout),
        "--post-success-wait",
        str(args.post_success_wait),
        "--diagnostics-dir",
        str(diagnostics_dir / apk.stem),
    ]
    if args.collect_success_diagnostics:
        cmd.append("--collect-success-diagnostics")
    if args.adb:
        cmd.extend(["--adb", args.adb])
    run(cmd, timeout=args.smoke_timeout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Rebuild protected small APK(s) and verify flag semantics.")
    parser.add_argument("--input-apk", default=str(DEFAULT_INPUT_APK))
    parser.add_argument("--shell-apk", default=str(default_shell_apk()))
    parser.add_argument("--extract-methods", default=str(DEFAULT_EXTRACT_MAP))
    parser.add_argument("--vmp-methods", default=str(DEFAULT_VMP_MAP))
    parser.add_argument("--keystore", default=str(DEFAULT_KEYSTORE))
    parser.add_argument("--ks-pass", default="enkotest")
    parser.add_argument("--key-alias", default="enko")
    parser.add_argument("--key-pass", default="enkotest")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--package", default=DEFAULT_PACKAGE)
    parser.add_argument("--activity", default=DEFAULT_ACTIVITY)
    parser.add_argument("--flag", default=DEFAULT_FLAG)
    parser.add_argument("--ready-text", default=DEFAULT_READY_TEXT)
    parser.add_argument("--expect-text", default=DEFAULT_EXPECT_TEXT)
    parser.add_argument("--expect-log", default=DEFAULT_EXPECT_LOG)
    parser.add_argument("--log-tag", default=DEFAULT_LOG_TAG)
    parser.add_argument("--diagnostics-dir", default="")
    parser.add_argument(
        "--preset",
        action="append",
        choices=("stable", "light", "medium"),
        help="VMP obfuscation preset to test. Can be passed multiple times. Defaults to light.",
    )
    parser.add_argument("--skip-smoke", action="store_true", help="Only harden APKs; do not install/run on Android.")
    parser.add_argument("--adb", default=os.environ.get("ADB", ""))
    parser.add_argument("--apktool", default="")
    parser.add_argument("--zipalign", default="")
    parser.add_argument("--apksigner", default="")
    parser.add_argument("--ndk-path", default="")
    parser.add_argument("--harden-timeout", type=int, default=300)
    parser.add_argument("--smoke-timeout", type=int, default=180)
    parser.add_argument("--expect-timeout", type=int, default=10)
    parser.add_argument("--post-success-wait", type=float, default=2.0)
    parser.add_argument("--collect-success-diagnostics", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    presets = args.preset or ["light"]

    try:
        for path, label in (
            (Path(args.input_apk), "input APK"),
            (Path(args.shell_apk), "shell APK"),
            (Path(args.extract_methods), "extract method list"),
            (Path(args.vmp_methods), "VMP method list"),
            (Path(args.keystore), "keystore"),
        ):
            require_file(path.resolve(), label)

        tools = resolve_tools(args)
        print("[semantic-regression] tools:")
        for name, path in tools.items():
            print(f"  {name}: {path}")

        outputs: list[Path] = []
        for preset in presets:
            print(f"[semantic-regression] hardening preset={preset}")
            output_apk = harden_one(args, tools, preset)
            outputs.append(output_apk)
            if not args.skip_smoke:
                print(f"[semantic-regression] Android smoke preset={preset}")
                smoke_one(args, output_apk)

        print("[semantic-regression] PASS")
        for output in outputs:
            print(f"  {output}")
        return 0
    except (RegressionError, subprocess.TimeoutExpired) as exc:
        print(f"[semantic-regression] FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
