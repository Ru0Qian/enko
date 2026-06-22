#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]

DEFAULT_CATEGORIES = ("cache", "root-artifacts", "web-temp")
ALL_CATEGORIES = ("cache", "root-artifacts", "web-temp", "output", "android-build")

TOOLCHAIN_DIRS = {
    ROOT / ".tools",
    ROOT / "tools" / "gradle-8.2.1",
}


@dataclass(frozen=True)
class CleanEntry:
    path: Path
    category: str
    reason: str


def is_inside_root(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT)
    except ValueError:
        return False
    return True


def is_toolchain_path(path: Path) -> bool:
    resolved = path.resolve()
    for toolchain in TOOLCHAIN_DIRS:
        try:
            resolved.relative_to(toolchain.resolve())
        except ValueError:
            continue
        return True
    return False


def add_if_exists(entries: list[CleanEntry], path: Path, category: str, reason: str) -> None:
    if not path.exists():
        return
    if path.resolve() == ROOT or not is_inside_root(path):
        return
    if is_toolchain_path(path):
        return
    entries.append(CleanEntry(path, category, reason))


def iter_named_dirs(names: set[str]) -> Iterable[Path]:
    for path in ROOT.rglob("*"):
        if path.is_dir() and path.name in names and not is_toolchain_path(path):
            yield path


def collect_cache() -> list[CleanEntry]:
    entries: list[CleanEntry] = []
    for name in (".mypy_cache", ".pytest_cache", ".ruff_cache", ".playwright-mcp", "_stitch_tmp"):
        add_if_exists(entries, ROOT / name, "cache", "local cache")
    for path in iter_named_dirs({"__pycache__"}):
        add_if_exists(entries, path, "cache", "Python bytecode cache")
    for pattern in ("*.pyc", "*.pyo"):
        for path in ROOT.rglob(pattern):
            add_if_exists(entries, path, "cache", "Python bytecode file")
    return entries


def collect_root_artifacts() -> list[CleanEntry]:
    entries: list[CleanEntry] = []
    for pattern in (
        "demo-app-hardened*.apk",
        "demo-app-hardened*.apk.idsig",
        "demo-app-hardened*.idsig",
        "demo-app-hardened*.report.json",
        "*.report.json",
        "screen*.png",
        "_tmp_*",
        "_crash_window.log",
        "_window_dump.xml",
    ):
        for path in ROOT.glob(pattern):
            add_if_exists(entries, path, "root-artifacts", "generated root artifact")
    return entries


def collect_web_temp() -> list[CleanEntry]:
    entries: list[CleanEntry] = []
    web_root = ROOT / "web-console"
    for name in (".job-cache", "_stitch_extract", "_stitch_preview", "_stitch_ref", "__pycache__"):
        add_if_exists(entries, web_root / name, "web-temp", "web console temporary data")
    for pattern in ("stitch*.zip", "*.bak"):
        for path in web_root.glob(pattern):
            add_if_exists(entries, path, "web-temp", "web console generated file")
    return entries


def collect_output() -> list[CleanEntry]:
    entries: list[CleanEntry] = []
    output = ROOT / "output"
    if output.exists():
        for path in output.iterdir():
            if path.name == ".gitkeep":
                continue
            add_if_exists(entries, path, "output", "generated output")
    return entries


def collect_android_build() -> list[CleanEntry]:
    entries: list[CleanEntry] = []
    for path in (
        ROOT / "demo-app" / ".gradle",
        ROOT / "demo-app" / "build",
        ROOT / "demo-app" / "app" / "build",
        ROOT / "shell-app" / ".gradle",
        ROOT / "shell-app" / "build",
        ROOT / "shell-app" / "app" / ".cxx",
        ROOT / "shell-app" / "app" / "build",
    ):
        add_if_exists(entries, path, "android-build", "Android build cache/output")
    test_apks = ROOT / "test_apks"
    if test_apks.exists():
        for app_dir in test_apks.iterdir():
            if not app_dir.is_dir():
                continue
            for path in (app_dir / ".gradle", app_dir / "build", app_dir / "app" / "build"):
                add_if_exists(entries, path, "android-build", "test APK build cache/output")
    return entries


COLLECTORS = {
    "cache": collect_cache,
    "root-artifacts": collect_root_artifacts,
    "web-temp": collect_web_temp,
    "output": collect_output,
    "android-build": collect_android_build,
}


def collect(categories: Iterable[str]) -> list[CleanEntry]:
    found: dict[Path, CleanEntry] = {}
    for category in categories:
        for entry in COLLECTORS[category]():
            found.setdefault(entry.path.resolve(), entry)
    selected: list[CleanEntry] = []
    selected_dirs: list[Path] = []
    for entry in sorted(found.values(), key=lambda item: len(item.path.relative_to(ROOT).parts)):
        resolved = entry.path.resolve()
        nested = False
        for parent in selected_dirs:
            try:
                resolved.relative_to(parent)
            except ValueError:
                continue
            nested = True
            break
        if nested:
            continue
        selected.append(entry)
        if entry.path.is_dir():
            selected_dirs.append(resolved)
    return sorted(selected, key=lambda item: str(item.path.relative_to(ROOT)).lower())


def measure(path: Path) -> int:
    if path.is_file() or path.is_symlink():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    for child in path.rglob("*"):
        try:
            if child.is_file() or child.is_symlink():
                total += child.stat().st_size
        except OSError:
            continue
    return total


def format_size(size: int) -> str:
    units = ("B", "KB", "MB", "GB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def remove_entry(entry: CleanEntry) -> None:
    path = entry.path
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Clean generated Enko workspace artifacts.")
    parser.add_argument(
        "--category",
        action="append",
        choices=ALL_CATEGORIES,
        help="Category to clean. Can be passed multiple times.",
    )
    parser.add_argument("--all", action="store_true", help="Clean every category, including output and Android builds.")
    parser.add_argument("--apply", action="store_true", help="Delete files. Omit for dry-run.")
    parser.add_argument("--json", action="store_true", help="Print a machine-readable cleanup plan.")
    parser.add_argument("--list-categories", action="store_true", help="Print available categories and exit.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.list_categories:
        print("Available categories:")
        for category in ALL_CATEGORIES:
            marker = "default" if category in DEFAULT_CATEGORIES else "optional"
            print(f"  {category:<14} {marker}")
        return 0

    categories = ALL_CATEGORIES if args.all else tuple(args.category or DEFAULT_CATEGORIES)
    entries = collect(categories)
    measured = [(entry, measure(entry.path)) for entry in entries]
    total_size = sum(size for _entry, size in measured)

    mode = "apply" if args.apply else "dry-run"
    if args.json:
        payload = {
            "mode": mode,
            "root": str(ROOT),
            "categories": list(categories),
            "entries": [
                {
                    "path": str(entry.path.relative_to(ROOT)),
                    "category": entry.category,
                    "reason": entry.reason,
                    "size": size,
                }
                for entry, size in measured
            ],
            "entry_count": len(entries),
            "estimated_size": total_size,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        if args.apply:
            for entry, _size in measured:
                remove_entry(entry)
        return 0

    print(f"Mode: {mode}")
    print(f"Root: {ROOT}")
    print(f"Categories: {', '.join(categories)}")
    print(f"Entries: {len(entries)}")
    print(f"Estimated size: {format_size(total_size)}")

    for entry, _size in measured:
        relative = entry.path.relative_to(ROOT)
        print(f"  [{entry.category}] {relative} - {entry.reason}")

    if not args.apply:
        print("No files deleted. Re-run with --apply to clean.")
        return 0

    for entry, _size in measured:
        remove_entry(entry)
    print(f"Deleted {len(entries)} entries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
