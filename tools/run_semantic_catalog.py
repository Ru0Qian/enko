from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = REPO_ROOT / "output" / "semantic-catalog"
SMALL_FLAG = "flag{3nk0_h4rd3n1ng_r3v3rs3_2026}"
SCENARIO_FLAG = "flag{enko_matrix_2026}"
BUSINESS_FLAG = "flag{enko_business_matrix_2026}"


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    group: str
    apk: Path
    package: str = ""
    activity: str = ""
    flag: str = ""
    ready_text: str = "App started successfully"
    expect_text: str = "CORRECT! Flag accepted"
    expect_log: str = "verify result=true"
    log_tag: str = "ScenarioMain"
    trigger_id: str = ""
    trigger_ready_text: str = ""
    trigger_log: str = ""
    semantic: bool = True
    note: str = ""

    @property
    def exists(self) -> bool:
        return self.apk.exists()


def _scenario_entries() -> list[CatalogEntry]:
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    from run_scenario_matrix import SCENARIOS  # imported lazily for testability

    entries: list[CatalogEntry] = []
    for scenario in SCENARIOS.values():
        flag = BUSINESS_FLAG if scenario.name == "complex-business" else SCENARIO_FLAG
        trigger_id = ""
        trigger_ready_text = ""
        trigger_log = ""
        if scenario.name == "complex-business":
            trigger_id = f"{scenario.package}:id/btnState"
            trigger_ready_text = "Business trigger ready"
            trigger_log = "business trigger ready"

        entries.append(
            CatalogEntry(
                id=f"scenario-raw-{scenario.name}",
                group="scenario-raw",
                apk=scenario.raw_apk,
                package=scenario.package,
                activity=scenario.activity,
                flag=flag,
                trigger_id=trigger_id,
                trigger_ready_text=trigger_ready_text,
                trigger_log=trigger_log,
                note=scenario.description,
            )
        )

        hardened = (
            REPO_ROOT
            / "output"
            / "scenario-matrix"
            / "ui-safe"
            / scenario.name
            / "light"
            / f"{scenario.name}-ui-safe-light.apk"
        )
        entries.append(
            CatalogEntry(
                id=f"scenario-hardened-{scenario.name}",
                group="scenario-hardened",
                apk=hardened,
                package=scenario.package,
                activity=scenario.activity,
                flag=flag,
                trigger_id=trigger_id,
                trigger_ready_text=trigger_ready_text,
                trigger_log=trigger_log,
                note=f"hardened ui-safe light: {scenario.description}",
            )
        )
    return entries


def build_catalog() -> list[CatalogEntry]:
    small_common = {
        "package": "com.enko.test.small",
        "activity": "com.enko.test.small.MainActivity",
        "flag": SMALL_FLAG,
        "expect_log": "Hash verification: true",
        "log_tag": "SmallMain",
    }
    entries = [
        CatalogEntry(
            id="small-raw-debug",
            group="small",
            apk=REPO_ROOT / "test_apks" / "small_app" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk",
            note="raw small flag app",
            **small_common,
        ),
        CatalogEntry(
            id="small-hardened-current",
            group="small",
            apk=REPO_ROOT / "test_apks" / "small_app" / "app" / "build" / "outputs" / "apk" / "debug" / "app-hardened-current.apk",
            note="latest local hardened small app",
            **small_common,
        ),
        CatalogEntry(
            id="small-hardened-root",
            group="small",
            apk=REPO_ROOT / "test_apks" / "small_hardened.apk",
            note="root-level small hardened artifact",
            **small_common,
        ),
    ]
    entries.extend(_scenario_entries())
    entries.append(
        CatalogEntry(
            id="real-gagademo",
            group="real-business",
            apk=REPO_ROOT / "gagademo_v3.7.4_c374_release.apk",
            semantic=False,
            note="real business sample; package/activity/semantic flow must be supplied before smoke",
        )
    )
    return entries


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


def selected_entries(catalog: list[CatalogEntry], ids: list[str] | None) -> list[CatalogEntry]:
    if not ids:
        return catalog
    by_id = {entry.id: entry for entry in catalog}
    out: list[CatalogEntry] = []
    for entry_id in ids:
        if entry_id not in by_id:
            raise SystemExit(f"unknown catalog entry: {entry_id}")
        out.append(by_id[entry_id])
    return out


def entry_to_json(entry: CatalogEntry) -> dict[str, object]:
    data = asdict(entry)
    data["apk"] = str(entry.apk)
    data["exists"] = entry.exists
    return data


def smoke_command(
    entry: CatalogEntry,
    *,
    adb: str,
    diagnostics_dir: Path,
    post_success_wait: float,
    collect_success_diagnostics: bool,
) -> list[str]:
    cmd = [
        sys.executable,
        str(TOOLS_DIR / "android_semantic_smoke.py"),
        "--apk",
        str(entry.apk),
        "--package",
        entry.package,
        "--activity",
        entry.activity,
        "--flag",
        entry.flag,
        "--ready-text",
        entry.ready_text,
        "--expect-text",
        entry.expect_text,
        "--expect-log",
        entry.expect_log,
        "--log-tag",
        entry.log_tag,
        "--adb",
        adb,
        "--diagnostics-dir",
        str(diagnostics_dir / entry.id),
        "--post-success-wait",
        str(post_success_wait),
    ]
    if collect_success_diagnostics:
        cmd.append("--collect-success-diagnostics")
    if entry.trigger_id:
        cmd.extend(["--trigger-id", entry.trigger_id])
    if entry.trigger_ready_text:
        cmd.extend(["--trigger-ready-text", entry.trigger_ready_text])
    if entry.trigger_log:
        cmd.extend(["--trigger-log", entry.trigger_log])
    return cmd


def run_cmd(cmd: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    print("[cmd]", " ".join(str(part) for part in cmd))
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        timeout_msg = f"[semantic-catalog] command timed out after {timeout}s"
        proc = subprocess.CompletedProcess(
            cmd,
            124,
            stdout=(stdout + ("\n" if stdout and not stdout.endswith("\n") else "") + timeout_msg + "\n"),
            stderr=None,
        )
    if proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
    return proc


def force_stop_package(adb: str, package: str) -> None:
    if not package:
        return
    try:
        subprocess.run(
            [adb, "shell", "am", "force-stop", package],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            errors="replace",
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"[semantic-catalog] warning: force-stop timed out for {package}")


def write_summary(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[semantic-catalog] summary: {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="List or run known semantic APK smoke flows across small, scenario, and real sample artifacts."
    )
    parser.add_argument("--entry", action="append", help="Catalog entry id to run/list. Defaults to all.")
    parser.add_argument("--list", action="store_true", help="Only print catalog entries.")
    parser.add_argument("--run", action="store_true", help="Run semantic smoke for selected entries with APKs that exist.")
    parser.add_argument("--adb", default="")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--summary-json", default="")
    parser.add_argument("--post-success-wait", type=float, default=1.0)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--include-missing", action="store_true", help="Include missing APK entries in --run summary as skipped.")
    parser.add_argument("--no-collect-success-diagnostics", dest="collect_success_diagnostics", action="store_false")
    parser.set_defaults(collect_success_diagnostics=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    catalog = selected_entries(build_catalog(), args.entry)
    output_dir = Path(args.output_dir).resolve()
    summary_path = Path(args.summary_json).resolve() if args.summary_json else output_dir / "summary.json"

    if args.list or not args.run:
        payload = {"entries": [entry_to_json(entry) for entry in catalog]}
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        if args.summary_json:
            write_summary(summary_path, payload)
        return 0

    adb = resolve_adb(args.adb)
    if not adb or not adb_has_online_device(adb):
        raise SystemExit("no online Android device/emulator. Set --adb or start a device.")

    results: list[dict[str, object]] = []
    failed = False
    for entry in catalog:
        item = entry_to_json(entry)
        if not entry.exists:
            item["status"] = "missing"
            if args.include_missing:
                results.append(item)
            continue
        if not entry.semantic:
            item["status"] = "metadata-only"
            results.append(item)
            continue

        diag_dir = output_dir / "diagnostics"
        cmd = smoke_command(
            entry,
            adb=adb,
            diagnostics_dir=diag_dir,
            post_success_wait=args.post_success_wait,
            collect_success_diagnostics=bool(args.collect_success_diagnostics),
        )
        proc = run_cmd(cmd, timeout=args.timeout)
        force_stop_package(adb, entry.package)
        item["status"] = "passed" if proc.returncode == 0 else "failed"
        item["diagnostics_dir"] = str(diag_dir / entry.id)
        item["returncode"] = proc.returncode
        if proc.returncode != 0:
            failed = True
        results.append(item)

    payload = {"results": results}
    write_summary(summary_path, payload)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
