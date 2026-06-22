from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


DEFAULT_FLAG = "flag{3nk0_h4rd3n1ng_r3v3rs3_2026}"
DEFAULT_EXPECT_TEXT = "CORRECT! Flag accepted"
REMOTE_DUMP_PATH = "/sdcard/enko-window.xml"


class SmokeError(RuntimeError):
    pass


@dataclass(frozen=True)
class Bounds:
    left: int
    top: int
    right: int
    bottom: int

    @property
    def center(self) -> tuple[int, int]:
        return ((self.left + self.right) // 2, (self.top + self.bottom) // 2)


def run(cmd: list[str], *, timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        errors="replace",
    )
    if check and proc.returncode != 0:
        raise SmokeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stdout}")
    return proc


def adb_shell(adb: str, *args: str, timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run([adb, "shell", *args], timeout=timeout, check=check)


def require_adb(path: str | None) -> str:
    adb = path or os.environ.get("ADB") or shutil.which("adb")
    if not adb:
        raise SmokeError("adb not found. Set --adb or put adb in PATH.")
    return adb


def require_device(adb: str) -> None:
    state = run([adb, "get-state"], timeout=10, check=False).stdout.strip()
    if state != "device":
        devices = run([adb, "devices"], timeout=10, check=False).stdout.strip()
        raise SmokeError(f"no online Android device/emulator. adb state={state!r}\n{devices}")


def parse_bounds(raw: str) -> Bounds | None:
    match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", raw or "")
    if not match:
        return None
    left, top, right, bottom = (int(part) for part in match.groups())
    return Bounds(left, top, right, bottom)


def parse_dumpsys_bounds(raw: str) -> Bounds | None:
    match = re.fullmatch(r"(\d+),(\d+)-(\d+),(\d+)", raw or "")
    if not match:
        return None
    left, top, right, bottom = (int(part) for part in match.groups())
    return Bounds(left, top, right, bottom)


def dump_ui(adb: str) -> str:
    adb_shell(adb, "uiautomator", "dump", REMOTE_DUMP_PATH, timeout=20)
    return run([adb, "exec-out", "cat", REMOTE_DUMP_PATH], timeout=20).stdout


def dump_activity_top(adb: str) -> str:
    return adb_shell(adb, "dumpsys", "activity", "top", timeout=60).stdout


def find_node_bounds(ui_xml: str, *, resource_id: str | None = None, text: str | None = None) -> Bounds:
    try:
        root = ET.fromstring(ui_xml)
    except ET.ParseError as exc:
        raise SmokeError(f"could not parse UI dump: {exc}\n{ui_xml[:500]}") from exc

    for node in root.iter("node"):
        if resource_id and node.attrib.get("resource-id") != resource_id:
            continue
        if text and node.attrib.get("text") != text:
            continue
        bounds = parse_bounds(node.attrib.get("bounds", ""))
        if bounds:
            return bounds

    wanted = resource_id or text or "<unknown>"
    raise SmokeError(f"UI node not found: {wanted}\n{ui_xml[:2000]}")


def resource_name(resource_id: str) -> str:
    return resource_id.rsplit("/", 1)[-1]


def find_dumpsys_bounds(dumpsys_text: str, *, resource: str) -> Bounds:
    pattern = re.compile(r"\b(?P<rect>\d+,\d+-\d+,\d+)\s+#[0-9a-fA-F]+\s+app:id/" + re.escape(resource) + r"\}")
    for line in dumpsys_text.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        bounds = parse_dumpsys_bounds(match.group("rect"))
        if bounds:
            return bounds
    raise SmokeError(f"dumpsys view not found: app:id/{resource}\n{dumpsys_text[:2000]}")


def tap_bounds(adb: str, bounds: Bounds) -> None:
    x, y = bounds.center
    adb_shell(adb, "input", "tap", str(x), str(y), timeout=10)


def android_input_text(adb: str, text: str) -> None:
    # Android's input command uses %s for spaces. The flag corpus should avoid
    # shell-sensitive characters beyond braces, but this keeps normal text safe.
    escaped = text.replace("%", "%25").replace(" ", "%s")
    adb_shell(adb, "input", "text", escaped, timeout=30)


def clear_focused_text(adb: str) -> None:
    adb_shell(adb, "input", "keyevent", "KEYCODE_MOVE_END", timeout=10, check=False)
    adb_shell(
        adb,
        "sh",
        "-c",
        "i=0; while [ $i -lt 96 ]; do input keyevent KEYCODE_DEL; i=$((i+1)); done",
        timeout=30,
        check=False,
    )


def wait_for_text(adb: str, expected: str, *, timeout: int) -> str:
    deadline = time.monotonic() + timeout
    last_xml = ""
    while time.monotonic() < deadline:
        last_xml = dump_ui(adb)
        if expected in last_xml:
            return last_xml
        time.sleep(1)
    raise SmokeError(f"expected UI text not found within {timeout}s: {expected!r}\n{last_xml[:2000]}")


def wait_for_dumpsys_view(adb: str, resource: str, *, timeout: int) -> Bounds:
    deadline = time.monotonic() + timeout
    last_dump = ""
    while time.monotonic() < deadline:
        last_dump = dump_activity_top(adb)
        try:
            return find_dumpsys_bounds(last_dump, resource=resource)
        except SmokeError:
            time.sleep(1)
    raise SmokeError(f"dumpsys view not found within {timeout}s: app:id/{resource}\n{last_dump[:2000]}")


def wait_for_logcat(adb: str, expected: str, *, tag: str, timeout: int) -> str:
    deadline = time.monotonic() + timeout
    last_log = ""
    while time.monotonic() < deadline:
        cmd = [adb, "logcat", "-d"]
        if tag:
            cmd.extend(["-s", tag])
        last_log = run(cmd, timeout=20, check=False).stdout
        if expected in last_log:
            return last_log
        time.sleep(1)
    raise SmokeError(f"expected log text not found within {timeout}s: {expected!r}\n{last_log[-2000:]}")


def check_process_alive(adb: str, package: str) -> None:
    proc = adb_shell(adb, "pidof", package, timeout=10, check=False)
    if proc.returncode != 0 or not proc.stdout.strip():
        logcat = run(
            [adb, "logcat", "-d", "-s", "AndroidRuntime", "ProxyApplication", "agpcore", "SmallMain", "FlagChecker"],
            timeout=20,
            check=False,
        ).stdout
        raise SmokeError(f"app process is not alive: {package}\n{logcat[-4000:]}")


def assert_no_anr_or_crash(adb: str, package: str) -> None:
    logcat = run([adb, "logcat", "-d"], timeout=20, check=False).stdout
    suspicious: list[str] = []
    for line in logcat.splitlines():
        if package not in line:
            continue
        if (
            "ANR in" in line
            or "Input dispatching timed out" in line
            or "FATAL EXCEPTION" in line
            or "Force finishing activity" in line
        ):
            suspicious.append(line)
    if suspicious:
        raise SmokeError(
            "ANR/crash signal detected after semantic success:\n"
            + "\n".join(suspicious[-20:])
        )


def install_apk(adb: str, apk: Path, package: str, *, timeout: int) -> None:
    proc = run([adb, "install", "-r", str(apk)], timeout=timeout, check=False)
    if proc.returncode == 0:
        return
    if "INSTALL_FAILED_UPDATE_INCOMPATIBLE" in proc.stdout:
        print(f"[enko-smoke] uninstalling incompatible prior package: {package}")
        run([adb, "uninstall", package], timeout=60, check=False)
        run([adb, "install", "-r", str(apk)], timeout=timeout)
        return
    raise SmokeError(f"command failed ({proc.returncode}): {adb} install -r {apk}\n{proc.stdout}")


def run_dumpsys_log_fallback(
    args: argparse.Namespace,
    adb: str,
    *,
    already_typed: bool = False,
    already_triggered: bool = False,
) -> None:
    if not args.expect_log:
        raise SmokeError("dumpsys fallback requires --expect-log to verify semantic success")

    field_id = args.input_id or f"{args.package}:id/flagInput"
    button_id = args.button_id or f"{args.package}:id/btnVerify"
    trigger_id = args.trigger_id
    field_name = resource_name(field_id)
    button_name = resource_name(button_id)
    trigger_name = resource_name(trigger_id) if trigger_id else ""

    print("[enko-smoke] UIAutomator unavailable; using dumpsys/input/logcat fallback")
    if trigger_id and not already_triggered:
        top = dump_activity_top(adb)
        tap_bounds(adb, find_dumpsys_bounds(top, resource=trigger_name))
        if args.trigger_log:
            wait_for_logcat(adb, args.trigger_log, tag=args.log_tag, timeout=args.trigger_timeout)
        elif args.trigger_ready_text:
            time.sleep(1)

    if not already_typed:
        tap_bounds(adb, wait_for_dumpsys_view(adb, field_name, timeout=args.ready_timeout))
        clear_focused_text(adb)
        android_input_text(adb, args.flag)
        time.sleep(0.5)
    top = dump_activity_top(adb)
    tap_bounds(adb, find_dumpsys_bounds(top, resource=button_name))
    wait_for_logcat(adb, args.expect_log, tag=args.log_tag, timeout=args.expect_timeout)
    print("[enko-smoke] PASS: semantic flag flow accepted via logcat fallback")


def _record_duration(timings: dict[str, int], name: str, start: float) -> None:
    timings[name] = int((time.monotonic() - start) * 1000)


def diagnostics_dir(args: argparse.Namespace) -> Path | None:
    if not args.diagnostics_dir:
        return None
    return Path(args.diagnostics_dir).resolve()


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


def collect_diagnostics(
    args: argparse.Namespace,
    adb: str,
    *,
    status: str,
) -> dict[str, str]:
    out_dir = diagnostics_dir(args)
    if not out_dir:
        return {}
    out_dir.mkdir(parents=True, exist_ok=True)

    written: dict[str, str] = {}

    def save(name: str, text: str) -> None:
        path = out_dir / name
        _write_text(path, text)
        written[name] = str(path)

    save("status.txt", status + "\n")
    commands = {
        "logcat.txt": [adb, "logcat", "-d"],
        "activity-top.txt": [adb, "shell", "dumpsys", "activity", "top"],
        "activity-processes.txt": [adb, "shell", "dumpsys", "activity", "processes"],
        "window.txt": [adb, "shell", "dumpsys", "window"],
        "meminfo.txt": [adb, "shell", "dumpsys", "meminfo", args.package],
        "pid.txt": [adb, "shell", "pidof", args.package],
        "ps.txt": [adb, "shell", "ps", "-A"],
    }
    for name, cmd in commands.items():
        try:
            save(name, run(cmd, timeout=30, check=False).stdout)
        except (SmokeError, subprocess.TimeoutExpired) as exc:
            save(name, f"<collection failed: {exc}>\n")

    try:
        save("window.xml", dump_ui(adb))
    except (SmokeError, subprocess.TimeoutExpired) as exc:
        save("window.xml", f"<collection failed: {exc}>\n")

    return written


def write_result(
    args: argparse.Namespace,
    *,
    ok: bool,
    timings: dict[str, int],
    error: str = "",
    diagnostics: dict[str, str] | None = None,
) -> None:
    out_dir = diagnostics_dir(args)
    if not out_dir:
        return
    payload = {
        "ok": ok,
        "apk": str(Path(args.apk).resolve()),
        "package": args.package,
        "activity": args.activity,
        "flag_length": len(args.flag),
        "expect_text": args.expect_text,
        "expect_log": args.expect_log,
        "timings_ms": timings,
        "error": error,
        "diagnostics": diagnostics or {},
    }
    path = out_dir / "smoke-result.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run_smoke(args: argparse.Namespace) -> dict[str, int]:
    timings: dict[str, int] = {}
    overall_start = time.monotonic()
    stage_start = overall_start

    adb = require_adb(args.adb)
    apk = Path(args.apk).resolve()
    if not apk.exists():
        raise SmokeError(f"APK not found: {apk}")

    require_device(adb)
    _record_duration(timings, "device_ready", stage_start)
    print(f"[enko-smoke] device ready via {adb}")
    print(f"[enko-smoke] installing {apk}")
    stage_start = time.monotonic()
    install_apk(adb, apk, args.package, timeout=args.install_timeout)
    _record_duration(timings, "install", stage_start)

    if not args.no_clear_data:
        stage_start = time.monotonic()
        adb_shell(adb, "pm", "clear", args.package, timeout=20, check=False)
        _record_duration(timings, "clear_data", stage_start)

    run([adb, "logcat", "-c"], timeout=10, check=False)

    component = f"{args.package}/{args.activity}"
    print(f"[enko-smoke] launching {component}")
    stage_start = time.monotonic()
    adb_shell(adb, "am", "start", "-n", component, timeout=20)
    time.sleep(args.launch_wait)
    try:
        check_process_alive(adb, args.package)
    except (SmokeError, subprocess.TimeoutExpired) as exc:
        if args.dumpsys_fallback:
            print(f"[enko-smoke] process check inconclusive: {exc}")
        else:
            raise
    _record_duration(timings, "launch", stage_start)

    field_id = args.input_id or f"{args.package}:id/flagInput"
    button_id = args.button_id or f"{args.package}:id/btnVerify"

    already_typed = False
    already_triggered = False
    try:
        stage_start = time.monotonic()
        ui_xml = wait_for_text(adb, args.ready_text, timeout=args.ready_timeout)
        _record_duration(timings, "wait_ready", stage_start)
        if args.trigger_id:
            stage_start = time.monotonic()
            tap_bounds(adb, find_node_bounds(ui_xml, resource_id=args.trigger_id))
            if args.trigger_log:
                wait_for_logcat(adb, args.trigger_log, tag=args.log_tag, timeout=args.trigger_timeout)
            if args.trigger_ready_text:
                ui_xml = wait_for_text(adb, args.trigger_ready_text, timeout=args.trigger_timeout)
            else:
                ui_xml = dump_ui(adb)
            already_triggered = True
            _record_duration(timings, "trigger", stage_start)

        stage_start = time.monotonic()
        tap_bounds(adb, find_node_bounds(ui_xml, resource_id=field_id))
        android_input_text(adb, args.flag)
        already_typed = True
        time.sleep(0.5)
        _record_duration(timings, "input_flag", stage_start)

        stage_start = time.monotonic()
        ui_xml = dump_ui(adb)
        tap_bounds(adb, find_node_bounds(ui_xml, resource_id=button_id))
        wait_for_text(adb, args.expect_text, timeout=args.expect_timeout)
        check_process_alive(adb, args.package)
        _record_duration(timings, "verify", stage_start)

        stage_start = time.monotonic()
        if args.post_success_wait > 0:
            time.sleep(args.post_success_wait)
        check_process_alive(adb, args.package)
        assert_no_anr_or_crash(adb, args.package)
        _record_duration(timings, "post_success_health", stage_start)
    except (SmokeError, subprocess.TimeoutExpired):
        if not args.dumpsys_fallback:
            raise
        stage_start = time.monotonic()
        run_dumpsys_log_fallback(
            args,
            adb,
            already_typed=already_typed,
            already_triggered=already_triggered,
        )
        _record_duration(timings, "dumpsys_log_fallback", stage_start)
        if args.post_success_wait > 0:
            time.sleep(args.post_success_wait)
        check_process_alive(adb, args.package)
        assert_no_anr_or_crash(adb, args.package)
        timings["total"] = int((time.monotonic() - overall_start) * 1000)
        return timings

    print("[enko-smoke] PASS: semantic flag flow accepted")
    timings["total"] = int((time.monotonic() - overall_start) * 1000)
    return timings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Install an APK and verify the small flag UI flow on Android.")
    parser.add_argument("--apk", required=True, help="APK to install and test.")
    parser.add_argument("--package", default="com.enko.test.small", help="Android application id.")
    parser.add_argument("--activity", default=".MainActivity", help="Launch activity, e.g. .MainActivity.")
    parser.add_argument("--flag", default=DEFAULT_FLAG, help="Flag text to submit.")
    parser.add_argument("--expect-text", default=DEFAULT_EXPECT_TEXT, help="Text expected after verification.")
    parser.add_argument("--expect-log", default="", help="Logcat text expected after verification fallback.")
    parser.add_argument("--ready-text", default="App started successfully", help="Text expected after launch.")
    parser.add_argument("--input-id", default="", help="Resource id of the flag input field.")
    parser.add_argument("--button-id", default="", help="Resource id of the verify button.")
    parser.add_argument("--trigger-id", default="", help="Optional resource id to tap before entering the flag.")
    parser.add_argument("--trigger-ready-text", default="", help="Optional UI text expected after tapping --trigger-id.")
    parser.add_argument("--trigger-log", default="", help="Optional logcat text expected after tapping --trigger-id.")
    parser.add_argument("--trigger-timeout", type=int, default=20)
    parser.add_argument("--adb", default="", help="Path to adb. Defaults to ADB env or PATH.")
    parser.add_argument("--install-timeout", type=int, default=120)
    parser.add_argument("--launch-wait", type=float, default=2.0)
    parser.add_argument("--ready-timeout", type=int, default=20)
    parser.add_argument("--expect-timeout", type=int, default=20)
    parser.add_argument("--log-tag", default="ScenarioMain", help="Logcat tag used by --expect-log fallback.")
    parser.add_argument("--no-dumpsys-fallback", dest="dumpsys_fallback", action="store_false")
    parser.set_defaults(dumpsys_fallback=True)
    parser.add_argument("--no-clear-data", action="store_true", help="Do not clear app data before launch.")
    parser.add_argument("--post-success-wait", type=float, default=1.0, help="Seconds to keep the app alive after semantic success before ANR/crash scan.")
    parser.add_argument("--diagnostics-dir", default="", help="Directory for smoke-result.json, logcat, UI dump, and dumpsys artifacts.")
    parser.add_argument("--collect-success-diagnostics", action="store_true", help="Also collect full diagnostics after a passing smoke run.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    timings: dict[str, int] = {}
    try:
        timings = run_smoke(args)
        adb = require_adb(args.adb)
        diagnostics = (
            collect_diagnostics(args, adb, status="PASS")
            if args.collect_success_diagnostics
            else {}
        )
        write_result(args, ok=True, timings=timings, diagnostics=diagnostics)
        return 0
    except (SmokeError, subprocess.TimeoutExpired) as exc:
        diagnostics: dict[str, str] = {}
        try:
            adb = require_adb(args.adb)
            diagnostics = collect_diagnostics(args, adb, status="FAIL")
        except Exception as diag_exc:  # noqa: BLE001 - diagnostics must not mask the root failure
            diagnostics = {"diagnostics_error": str(diag_exc)}
        write_result(args, ok=False, timings=timings, error=str(exc), diagnostics=diagnostics)
        print(f"[enko-smoke] FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
