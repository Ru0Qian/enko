from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIAGNOSTICS_DIR = REPO_ROOT / "output" / "semantic-catalog" / "diagnostics"
DEFAULT_JSON_OUT = REPO_ROOT / "output" / "semantic-catalog" / "diagnostics-summary.json"
DEFAULT_MARKDOWN_OUT = REPO_ROOT / "output" / "semantic-catalog" / "diagnostics-summary.md"

PROXY_TIMING_RE = re.compile(
    r"\bProxyApplication\b.*?\btiming:\s*([A-Za-z0-9_.-]+)=(\d+)ms"
)
SKIPPED_FRAMES_RE = re.compile(r"Skipped\s+(\d+)\s+frames", re.IGNORECASE)
CRITICAL_SIGNAL_PATTERNS = (
    "ANR in",
    "Input dispatching timed out",
    "FATAL EXCEPTION",
    "Force finishing activity",
    "Application Not Responding",
)


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "error": f"could not read smoke-result.json: {exc}",
            "timings_ms": {},
        }
    if not isinstance(data, dict):
        return {
            "ok": False,
            "error": "smoke-result.json root is not an object",
            "timings_ms": {},
        }
    return data


def parse_proxy_timings(logcat_text: str) -> dict[str, int]:
    timings: dict[str, int] = {}
    for match in PROXY_TIMING_RE.finditer(logcat_text):
        timings[match.group(1)] = int(match.group(2))
    return timings


def extract_log_signals(logcat_text: str, package: str = "") -> list[str]:
    signals: list[str] = []
    seen: set[str] = set()
    for line in logcat_text.splitlines():
        if package and package not in line and not any(
            marker in line for marker in CRITICAL_SIGNAL_PATTERNS
        ):
            skipped = SKIPPED_FRAMES_RE.search(line)
            if not skipped:
                continue

        if any(marker in line for marker in CRITICAL_SIGNAL_PATTERNS):
            signal = line.strip()
        else:
            skipped = SKIPPED_FRAMES_RE.search(line)
            if not skipped:
                continue
            frames = int(skipped.group(1))
            if frames < 30:
                continue
            signal = line.strip()

        if signal and signal not in seen:
            signals.append(signal)
            seen.add(signal)
    return signals[-20:]


def slow_items(values: dict[str, Any], threshold_ms: int) -> dict[str, int]:
    out: dict[str, int] = {}
    for key, value in values.items():
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) and value >= threshold_ms:
            out[key] = int(value)
    return out


def find_result_files(roots: list[Path]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        if root.is_file() and root.name == "smoke-result.json":
            files.append(root.resolve())
        elif root.exists():
            files.extend(path.resolve() for path in root.rglob("smoke-result.json"))
    return sorted(set(files))


def summarize_result(path: Path, *, slow_threshold_ms: int) -> dict[str, Any]:
    data = load_json(path)
    diag_dir = path.parent
    timings = data.get("timings_ms", {})
    if not isinstance(timings, dict):
        timings = {}

    logcat_path = diag_dir / "logcat.txt"
    logcat_text = ""
    if logcat_path.exists():
        logcat_text = logcat_path.read_text(encoding="utf-8", errors="replace")

    proxy_timings = parse_proxy_timings(logcat_text)
    package = str(data.get("package", ""))
    return {
        "id": diag_dir.name,
        "diagnostics_dir": str(diag_dir),
        "ok": bool(data.get("ok", False)),
        "package": package,
        "activity": str(data.get("activity", "")),
        "apk": str(data.get("apk", "")),
        "error": str(data.get("error", "")),
        "timings_ms": timings,
        "slow_stages": slow_items(timings, slow_threshold_ms),
        "proxy_timings_ms": proxy_timings,
        "proxy_slow_stages": slow_items(proxy_timings, slow_threshold_ms),
        "signals": extract_log_signals(logcat_text, package),
    }


def build_summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    failed = [entry for entry in entries if not entry.get("ok")]
    signaled = [entry for entry in entries if entry.get("signals")]
    slow = [
        entry
        for entry in entries
        if entry.get("slow_stages") or entry.get("proxy_slow_stages")
    ]
    return {
        "total": len(entries),
        "passed": len(entries) - len(failed),
        "failed": len(failed),
        "with_runtime_signals": len(signaled),
        "with_slow_stages": len(slow),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    entries = payload.get("entries", [])
    if not isinstance(entries, list):
        entries = []

    lines = [
        "# Enko Smoke Diagnostics Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
    ]
    totals = payload.get("summary", {})
    if isinstance(totals, dict):
        for key in ("total", "passed", "failed", "with_runtime_signals", "with_slow_stages"):
            lines.append(f"| {key} | {totals.get(key, 0)} |")

    lines.extend(
        [
            "",
            "| Entry | Status | Total ms | Slow smoke stages | Slow shell stages | Signals |",
            "| --- | --- | ---: | --- | --- | --- |",
        ]
    )
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        status = "PASS" if entry.get("ok") else "FAIL"
        timings = entry.get("timings_ms")
        total_ms = timings.get("total", "") if isinstance(timings, dict) else ""
        slow_smoke = format_stage_map(entry.get("slow_stages"))
        slow_shell = format_stage_map(entry.get("proxy_slow_stages"))
        signals = entry.get("signals")
        signal_count = len(signals) if isinstance(signals, list) else 0
        lines.append(
            f"| {entry.get('id', '')} | {status} | {total_ms} | "
            f"{slow_smoke} | {slow_shell} | {signal_count} |"
        )

    return "\n".join(lines) + "\n"


def format_stage_map(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return "-"
    return ", ".join(f"{key}={val}ms" for key, val in sorted(value.items()))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Summarize android_semantic_smoke diagnostics into JSON and Markdown."
    )
    parser.add_argument(
        "--diagnostics-dir",
        action="append",
        default=[],
        help="Diagnostics directory or smoke-result.json path. Defaults to semantic-catalog diagnostics.",
    )
    parser.add_argument("--json-out", default=str(DEFAULT_JSON_OUT))
    parser.add_argument("--markdown-out", default=str(DEFAULT_MARKDOWN_OUT))
    parser.add_argument("--slow-threshold-ms", type=int, default=2000)
    parser.add_argument("--print-json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    roots = [Path(item).resolve() for item in args.diagnostics_dir]
    if not roots:
        roots = [DEFAULT_DIAGNOSTICS_DIR.resolve()]

    result_files = find_result_files(roots)
    entries = [
        summarize_result(path, slow_threshold_ms=args.slow_threshold_ms)
        for path in result_files
    ]
    payload = {
        "diagnostics_roots": [str(root) for root in roots],
        "summary": build_summary(entries),
        "entries": entries,
    }

    json_text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    write_text(Path(args.json_out).resolve(), json_text)
    write_text(Path(args.markdown_out).resolve(), render_markdown(payload))
    if args.print_json:
        sys.stdout.write(json_text)
    else:
        print(f"[smoke-diagnostics] entries={len(entries)} json={Path(args.json_out).resolve()}")
        print(f"[smoke-diagnostics] markdown={Path(args.markdown_out).resolve()}")
    return 1 if any(not entry.get("ok") for entry in entries) else 0


if __name__ == "__main__":
    raise SystemExit(main())
