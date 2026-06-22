#!/usr/bin/env python3
"""Build and validate release metadata manifests for hardening jobs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHA256_RE = re.compile(r"[0-9A-Fa-f]{64}$")
REQUIRED_KEYS = (
    "engine_version",
    "rules_version",
    "policy_version",
    "map_version",
    "config_schema_version",
)


class ReleaseMetaError(Exception):
    pass


def ensure_file(path: Path, label: str) -> None:
    if not path.exists() or not path.is_file():
        raise ReleaseMetaError(f"{label} not found: {path}")


def normalize_version(value: str, key: str) -> str:
    text = (value or "").strip()
    if not text or not VERSION_RE.fullmatch(text):
        raise ReleaseMetaError(
            f"invalid {key}: {text!r} (allowed: letters/digits/._-, max 64 chars)"
        )
    return text


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().upper()


def manifest_path_text(path: Path, base_dir: Path, *, absolute: bool = False) -> str:
    resolved = path.resolve()
    if absolute:
        return str(resolved)
    try:
        return os.path.relpath(resolved, base_dir.resolve()).replace("\\", "/")
    except ValueError:
        return str(resolved)


def load_json_object(path: Path, label: str) -> dict[str, object]:
    ensure_file(path, label)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ReleaseMetaError(f"invalid JSON in {label}: {path}") from e
    if not isinstance(payload, dict):
        raise ReleaseMetaError(f"{label} root must be a JSON object: {path}")
    return payload


def build_manifest(args: argparse.Namespace) -> int:
    engine_path = Path(args.engine_manifest).resolve()
    rules_path = Path(args.rules_file).resolve()
    policy_path = Path(args.policy_file).resolve()
    map_path = Path(args.protection_map).resolve()
    output_path = Path(args.output).resolve()
    manifest_base = output_path.parent

    engine = load_json_object(engine_path, "--engine-manifest")
    rules = load_json_object(rules_path, "--rules-file")
    policy = load_json_object(policy_path, "--policy-file")
    ensure_file(map_path, "--protection-map")

    engine_version = normalize_version(str(engine.get("engine_version", "")), "engine_version")
    config_schema_version = normalize_version(
        str(engine.get("config_schema_version", "")),
        "config_schema_version",
    )
    rules_version = normalize_version(str(rules.get("rules_version", "")), "rules_version")
    policy_version = normalize_version(str(policy.get("policy_version", "")), "policy_version")

    map_version_raw = (args.map_version or "").strip() or map_path.stem
    map_version = normalize_version(map_version_raw, "map_version")

    manifest: dict[str, object] = {
        "engine_version": engine_version,
        "rules_version": rules_version,
        "policy_version": policy_version,
        "map_version": map_version,
        "config_schema_version": config_schema_version,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": {
            "engine_manifest": {
                "path": manifest_path_text(engine_path, manifest_base, absolute=args.absolute_paths),
                "sha256": sha256_file(engine_path),
            },
            "rules": {
                "path": manifest_path_text(rules_path, manifest_base, absolute=args.absolute_paths),
                "sha256": sha256_file(rules_path),
            },
            "policy": {
                "path": manifest_path_text(policy_path, manifest_base, absolute=args.absolute_paths),
                "sha256": sha256_file(policy_path),
            },
            "protection_map": {
                "path": manifest_path_text(map_path, manifest_base, absolute=args.absolute_paths),
                "sha256": sha256_file(map_path),
            },
        },
    }

    if args.presets_file:
        presets_path = Path(args.presets_file).resolve()
        presets = load_json_object(presets_path, "--presets-file")
        preset_version_raw = (args.preset_version or "").strip()
        if not preset_version_raw:
            preset_version_raw = str(presets.get("preset_version", "")).strip()
        if preset_version_raw:
            manifest["preset_version"] = normalize_version(preset_version_raw, "preset_version")
        files = manifest["files"]
        if isinstance(files, dict):
            files["presets"] = {
                "path": manifest_path_text(presets_path, manifest_base, absolute=args.absolute_paths),
                "sha256": sha256_file(presets_path),
            }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(manifest, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        "[ok] release manifest built: "
        f"{output_path} "
        f"(engine={engine_version}, rules={rules_version}, "
        f"policy={policy_version}, map={map_version}, schema={config_schema_version})"
    )
    return 0


def validate_manifest(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    payload = load_json_object(manifest_path, "--manifest")

    versions: dict[str, str] = {}
    for key in REQUIRED_KEYS:
        versions[key] = normalize_version(str(payload.get(key, "")), key)

    files = payload.get("files")
    if not isinstance(files, dict) or not files:
        raise ReleaseMetaError("manifest.files must be a non-empty object")

    for name, meta in files.items():
        if not isinstance(name, str) or not isinstance(meta, dict):
            raise ReleaseMetaError("manifest.files entries must be objects")
        path_text = str(meta.get("path", "")).strip()
        sha_text = str(meta.get("sha256", "")).strip().upper()
        if not path_text:
            raise ReleaseMetaError(f"manifest.files[{name}].path is empty")
        if not SHA256_RE.fullmatch(sha_text):
            raise ReleaseMetaError(f"manifest.files[{name}].sha256 must be 64 hex chars")
        if args.check_files:
            data_path = Path(path_text)
            if not data_path.is_absolute():
                data_path = (manifest_path.parent / data_path).resolve()
            ensure_file(data_path, f"manifest.files[{name}].path")
            actual = sha256_file(data_path)
            if actual != sha_text:
                raise ReleaseMetaError(
                    f"sha256 mismatch for {name}: expected {sha_text}, got {actual}"
                )

    print(
        "[ok] release manifest valid: "
        f"{manifest_path} "
        f"(engine={versions['engine_version']}, rules={versions['rules_version']}, "
        f"policy={versions['policy_version']}, map={versions['map_version']}, "
        f"schema={versions['config_schema_version']})"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build/validate release metadata manifests for hardening."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="build release manifest JSON")
    p_build.add_argument("--engine-manifest", required=True, help="engine manifest JSON path")
    p_build.add_argument("--rules-file", required=True, help="rules JSON path")
    p_build.add_argument("--policy-file", required=True, help="policy JSON path")
    p_build.add_argument("--protection-map", required=True, help="protection-map file path")
    p_build.add_argument("--map-version", default="", help="explicit map version (optional)")
    p_build.add_argument("--presets-file", default="", help="optional presets JSON path")
    p_build.add_argument("--preset-version", default="", help="explicit preset version (optional)")
    p_build.add_argument("--output", required=True, help="output manifest JSON path")
    p_build.add_argument(
        "--absolute-paths",
        action="store_true",
        help="write absolute file paths instead of portable paths relative to the manifest",
    )
    p_build.set_defaults(fn=build_manifest)

    p_validate = sub.add_parser("validate", help="validate release manifest JSON")
    p_validate.add_argument("--manifest", required=True, help="manifest JSON path")
    p_validate.add_argument(
        "--check-files",
        action="store_true",
        help="also verify each referenced file exists and sha256 matches",
    )
    p_validate.set_defaults(fn=validate_manifest)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.fn(args))
    except ReleaseMetaError as e:
        print(f"[error] {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[error] unexpected: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
