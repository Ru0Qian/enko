#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_GITIGNORE_PATTERNS = (
    "*.jks",
    "*.apk",
    "*.apk.idsig",
    "*.idsig",
    "*.env",
    "deploy/config.env",
    "output/",
    "tools/gradle-8.2.1/",
    "tools/gradle-8.2.1-bin.zip",
    "tools/apktool_3.0.1.jar",
    ".tools/",
)

FORBIDDEN_TRACKED_PATTERNS = (
    "*.jks",
    "*.apk",
    "*.apk.idsig",
    "*.idsig",
    "deploy/config.env",
    "output/*",
    "tools/gradle-8.2.1/*",
    "tools/gradle-8.2.1-bin.zip",
    "tools/apktool_3.0.1.jar",
    ".tools/*",
)


def read_gitignore(root: Path = ROOT) -> set[str]:
    path = root / ".gitignore"
    if not path.exists():
        return set()
    patterns: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patterns.add(line)
    return patterns


def missing_gitignore_patterns(root: Path = ROOT) -> list[str]:
    current = read_gitignore(root)
    return [pattern for pattern in REQUIRED_GITIGNORE_PATTERNS if pattern not in current]


def git_tracked_files(root: Path = ROOT) -> list[str] | None:
    if not (root / ".git").exists() or not shutil.which("git"):
        return None
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=root,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        return None
    return [line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()]


def is_forbidden_tracked(path: str) -> bool:
    normalized = path.replace("\\", "/")
    name = Path(normalized).name
    return any(
        fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(name, pattern)
        for pattern in FORBIDDEN_TRACKED_PATTERNS
    )


def build_report(root: Path = ROOT) -> dict[str, Any]:
    missing = missing_gitignore_patterns(root)
    tracked = git_tracked_files(root)
    forbidden = [] if tracked is None else [path for path in tracked if is_forbidden_tracked(path)]
    return {
        "root": str(root),
        "git_available": tracked is not None,
        "missing_gitignore_patterns": missing,
        "forbidden_tracked_files": forbidden,
        "ok": not missing and not forbidden,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check Enko repository hygiene guardrails.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable report.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(ROOT)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"Root: {report['root']}")
        print(f"Git tracked scan: {'available' if report['git_available'] else 'not available'}")
        if report["missing_gitignore_patterns"]:
            print("Missing .gitignore patterns:")
            for pattern in report["missing_gitignore_patterns"]:
                print(f"  {pattern}")
        if report["forbidden_tracked_files"]:
            print("Forbidden tracked files:")
            for path in report["forbidden_tracked_files"]:
                print(f"  {path}")
        if report["ok"]:
            print("Repository hygiene checks passed.")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
