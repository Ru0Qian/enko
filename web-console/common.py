"""Shared utilities for Enko Web Console servers (dev and production).

This module contains all shared state, path utilities, environment discovery,
command building, job management, and job execution logic used by both
server.py (dev) and server_prod.py (production).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
WEB_ROOT = Path(__file__).resolve().parent
REPO_ROOT = WEB_ROOT.parent
JOB_ROOT = WEB_ROOT / ".job-cache"
JOB_ROOT.mkdir(parents=True, exist_ok=True)
UPLOAD_ROOT = JOB_ROOT / "uploads"
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
JOB_STATE_FILENAME = "job.json"
MAX_EMBEDDED_REPORT_BYTES = 2_000_000

# ---------------------------------------------------------------------------
# Shared mutable state
# ---------------------------------------------------------------------------
JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def job_dir_for(job_id: str) -> Path:
    return JOB_ROOT / job_id


def job_state_path(job_id: str) -> Path:
    return job_dir_for(job_id) / JOB_STATE_FILENAME


def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _safe_read_json(path: Path) -> dict[str, Any] | None:
    try:
        if not path.exists() or path.stat().st_size > MAX_EMBEDDED_REPORT_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _persist_job_unlocked(job_id: str, job: dict[str, Any]) -> None:
    try:
        job_dir_for(job_id).mkdir(parents=True, exist_ok=True)
        path = job_state_path(job_id)
        tmp_path = path.with_suffix(".json.tmp")
        tmp_path.write_text(
            json.dumps(_json_clone(job), ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        tmp_path.replace(path)
    except Exception:
        # Persistence is a UI resilience layer. Do not let disk hiccups kill a build.
        pass


def _attach_artifact_details(job: dict[str, Any]) -> dict[str, Any]:
    output_apk = str(job.get("output_apk", "") or "")
    report_json = str(job.get("report_json", "") or "")
    job["output_exists"] = bool(output_apk and Path(output_apk).exists())
    job["report_exists"] = bool(report_json and Path(report_json).exists())

    if job["report_exists"] and not isinstance(job.get("report"), dict):
        report = _safe_read_json(Path(report_json))
        if report is not None:
            job["report"] = report
            job["report_score"] = report.get("score", job.get("report_score"))
            job["report_max_score"] = report.get("max_score", job.get("report_max_score"))
            job["report_grade"] = report.get("grade", job.get("report_grade"))
            job["report_compiled"] = report.get("compiled", job.get("report_compiled"))

    return job


def normalize_path(path_text: str) -> str:
    if not path_text:
        return ""
    return str(Path(path_text).expanduser().resolve())


def ensure_parent(path_text: str) -> None:
    if not path_text:
        return
    Path(path_text).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def path_exists(path_text: str) -> bool:
    return bool(path_text) and Path(path_text).expanduser().exists()


def looks_like_placeholder(path_text: str) -> bool:
    lowered = (path_text or "").strip().lower()
    return not lowered or "your-version" in lowered or lowered.endswith("\\ndk")


def version_key(path: Path) -> tuple[int, ...]:
    parts = []
    for part in path.name.replace("-", ".").split("."):
        if part.isdigit():
            parts.append(int(part))
        else:
            parts.append(-1)
    return tuple(parts)


# ---------------------------------------------------------------------------
# Environment discovery
# ---------------------------------------------------------------------------

def candidate_sdk_roots() -> list[Path]:
    roots: list[Path] = []
    candidates = [
        os.environ.get("ANDROID_SDK_ROOT", ""),
        os.environ.get("ANDROID_HOME", ""),
    ]
    if os.name == "nt":
        candidates += [
            r"D:\Env\tool\Android-Sdk",
            r"D:\Android\Sdk",
            str(Path.home() / "AppData" / "Local" / "Android" / "Sdk"),
        ]
    else:
        candidates += [
            "/opt/android-sdk",
            str(Path.home() / "Android" / "Sdk"),
        ]
    for value in candidates:
        if not value:
            continue
        path = Path(value).expanduser()
        if path.exists() and path not in roots:
            roots.append(path)
    return roots


def find_latest_directory(parent: Path) -> Path | None:
    if not parent.exists():
        return None
    candidates = [item for item in parent.iterdir() if item.is_dir()]
    if not candidates:
        return None
    return sorted(candidates, key=version_key, reverse=True)[0]


def discover_environment_defaults() -> dict[str, str]:
    defaults = {
        "sdk_root": "",
        "build_tools": "",
        "ndk": "",
        "apktool": "",
        "zipalign": "",
        "apksigner": "",
    }

    repo_apktool_bat = REPO_ROOT / "tools" / "apktool.bat"
    repo_apktool_sh = REPO_ROOT / "tools" / "apktool"
    if os.name != "nt" and repo_apktool_sh.exists():
        defaults["apktool"] = str(repo_apktool_sh)
    elif os.name == "nt" and repo_apktool_bat.exists():
        defaults["apktool"] = str(repo_apktool_bat)
    elif repo_apktool_sh.exists():
        defaults["apktool"] = str(repo_apktool_sh)
    else:
        apktool_path = shutil.which("apktool") or shutil.which("apktool.bat")
        if apktool_path:
            defaults["apktool"] = apktool_path

    for sdk_root in candidate_sdk_roots():
        build_tools_dir = find_latest_directory(sdk_root / "build-tools")
        ndk_dir = find_latest_directory(sdk_root / "ndk")

        if not defaults["sdk_root"]:
            defaults["sdk_root"] = str(sdk_root)
        if build_tools_dir and not defaults["build_tools"]:
            defaults["build_tools"] = str(build_tools_dir)
            if os.name == "nt":
                zipalign = build_tools_dir / "zipalign.exe"
                apksigner = build_tools_dir / "apksigner.bat"
            else:
                zipalign = build_tools_dir / "zipalign"
                apksigner = build_tools_dir / "apksigner"
            if zipalign.exists():
                defaults["zipalign"] = str(zipalign)
            if apksigner.exists():
                defaults["apksigner"] = str(apksigner)
        if ndk_dir and not defaults["ndk"]:
            defaults["ndk"] = str(ndk_dir)

        if defaults["zipalign"] and defaults["apksigner"] and defaults["ndk"]:
            break

    if not defaults["zipalign"]:
        _zipalign = shutil.which("zipalign")
        if _zipalign:
            defaults["zipalign"] = _zipalign
    if not defaults["apksigner"]:
        _apksigner = shutil.which("apksigner") or shutil.which("apksigner.bat")
        if _apksigner:
            defaults["apksigner"] = _apksigner

    return defaults


# ---------------------------------------------------------------------------
# Protection map
# ---------------------------------------------------------------------------

def filter_protection_map(source: Path, destination: Path, enabled: dict[str, bool]) -> tuple[Path, dict[str, int]]:
    phase_map = {1: "extract", 2: "vmp_dex", 3: "dex2c"}
    kept = {"extract": 0, "vmp_dex": 0, "dex2c": 0}
    output_lines: list[str] = [
        "# Generated by Enko Web Console",
        f"# enabled phases: {', '.join(name for name, active in enabled.items() if active)}",
    ]

    for raw_line in source.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            output_lines.append(raw_line)
            continue

        parts = line.rsplit(None, 1)
        if len(parts) != 2:
            output_lines.append(raw_line)
            continue

        try:
            level = int(parts[1])
        except ValueError:
            output_lines.append(raw_line)
            continue

        phase = phase_map.get(level)
        if phase is None:
            output_lines.append(raw_line)
            continue

        if enabled.get(phase, False):
            kept[phase] += 1
            output_lines.append(raw_line)

    destination.write_text("\n".join(output_lines) + "\n", encoding="utf-8")
    return destination, kept


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def max_reachable_security_score(config: dict[str, Any]) -> int:
    score = 85
    if not config.get("protectDexPages", True):
        score -= 5
    if config.get("signingEnabled") or str(config.get("signCertSha256", "")).strip():
        score += 10
    if config.get("commercialMode"):
        score += 15
    return min(score, 100)


# ---------------------------------------------------------------------------
# Command building
# ---------------------------------------------------------------------------

def make_command_preview(args: list[str]) -> str:
    hidden_value_flags = {"--ks-pass", "--key-pass"}
    preview: list[str] = []
    skip_next = False

    for index, part in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if part in hidden_value_flags and index + 1 < len(args):
            preview.append(part)
            preview.append("***")
            skip_next = True
        else:
            preview.append(part)

    return subprocess.list2cmdline(preview)


def build_command(config: dict[str, Any], job_dir: Path) -> tuple[list[str], str, dict[str, Any]]:
    packer = REPO_ROOT / "packer" / "harden_apk.py"
    if not packer.exists():
        raise FileNotFoundError(f"missing packer script: {packer}")

    defaults = discover_environment_defaults()

    input_apk = str(config.get("inputApk", "")).strip()
    shell_apk = str(config.get("shellApk", "")).strip()
    output_apk = str(config.get("outputApk", "")).strip()
    protection_map = str(config.get("protectionMap", "")).strip()
    report_json = str(config.get("reportJsonPath", "")).strip()
    release_manifest = str(config.get("releaseManifestPath", "")).strip()

    if not input_apk:
        raise ValueError("inputApk is required")
    if not shell_apk:
        raise ValueError("shellApk is required")
    if not output_apk:
        raise ValueError("outputApk is required")
    args: list[str] = [
        sys.executable,
        "-u",
        str(packer),
        "--input-apk",
        input_apk,
        "--shell-apk",
        shell_apk,
        "--output-apk",
        output_apk,
        "--risk-policy",
        str(config.get("riskPolicy", "block")),
        "--risk-profile",
        str(config.get("riskProfile", "strict")),
    ]

    args.append("--block-proxy-vpn" if config.get("blockProxyVpn", True) else "--allow-proxy-vpn")
    args.append("--detect-root" if config.get("detectRoot", True) else "--disable-root-check")
    args.append("--detect-emulator" if config.get("detectEmulator", True) else "--disable-emulator-check")
    args.append("--protect-dex-pages" if config.get("protectDexPages", True) else "--no-protect-dex-pages")
    args.append("--per-apk-key" if config.get("perApkKey", True) else "--no-per-apk-key")
    extract_on_demand = bool(
        config.get("extractOnDemand", str(config.get("riskProfile", "strict")) != "compat")
    )
    args.append("--extract-on-demand" if extract_on_demand else "--extract-bulk-restore")
    auto_protect_profile = str(config.get("autoProtectProfile", "balanced") or "balanced")
    if auto_protect_profile not in {"compat", "balanced", "strong", "extreme"}:
        raise ValueError(f"invalid auto-protect profile: {auto_protect_profile}")
    args.extend(["--auto-protect-profile", auto_protect_profile])

    if config.get("flutterMode"):
        args.append("--flutter-mode")
    if config.get("commercialMode"):
        args.append("--commercial-mode")

    phase_flags = {
        "extract": bool(config.get("featureExtract", True)),
        "vmp_dex": bool(config.get("featureVmpDex", True)),
        "dex2c": bool(config.get("featureDex2c", True)),
    }
    if not any(phase_flags.values()):
        raise ValueError("at least one method-protection phase must stay enabled")

    phase_summary = {
        "extract": phase_flags["extract"],
        "vmpDex": phase_flags["vmp_dex"],
        "dex2c": phase_flags["dex2c"],
        "vmpShellDex": bool(config.get("featureVmpShellDex", False)),
        "polymorphicShell": bool(config.get("featurePolymorphicShell", False)),
        "aiDecoy": bool(config.get("featureAiDecoy", False) or config.get("commercialMode", False)),
        "vmpObfuscationPreset": str(config.get("vmpObfuscationPreset", "light") or "light"),
        "vmpVmTier": str(config.get("vmpVmTier", "auto") or "auto"),
        "extractOnDemand": extract_on_demand,
        "autoProtectProfile": auto_protect_profile,
        "dex2cOllvm": bool(config.get("dex2cOllvm", True)),
        "dex2cOllvmRequired": bool(config.get("dex2cOllvmRequired", False)),
        "signingEnabled": bool(config.get("signingEnabled", False)),
        "commercialMode": bool(config.get("commercialMode", False)),
        "perApkKey": bool(config.get("perApkKey", True)),
        "protectDexPages": bool(config.get("protectDexPages", True)),
        "releaseManifestEnabled": bool(config.get("releaseManifestEnabled", False)),
    }

    if protection_map:
        source_map = Path(protection_map).expanduser().resolve()
        final_map = source_map
        filtered_counts: dict[str, int] | None = None
        if not all(phase_flags.values()):
            filtered_map = job_dir / "filtered-protection-map.txt"
            final_map, filtered_counts = filter_protection_map(source_map, filtered_map, phase_flags)
        args.extend(["--protection-map", str(final_map)])
    else:
        filtered_counts = None

    if phase_flags["vmp_dex"] or config.get("featureVmpShellDex"):
        preset = str(config.get("vmpObfuscationPreset", "light") or "light")
        if preset not in {"stable", "light", "medium"}:
            raise ValueError(f"invalid VMP obfuscation preset: {preset}")
        args.extend(["--vmp-dex-obfuscation-preset", preset])
        vm_tier = str(config.get("vmpVmTier", "auto") or "auto")
        if vm_tier not in {"auto", "compat", "light", "strong"}:
            raise ValueError(f"invalid VMP VM tier: {vm_tier}")
        args.extend(["--vmp-vm-tier", vm_tier])

    configured_ndk = str(config.get("ndkPath", "")).strip()
    resolved_ndk = configured_ndk if configured_ndk and not looks_like_placeholder(configured_ndk) else defaults["ndk"]
    if resolved_ndk and path_exists(resolved_ndk):
        args.extend(["--ndk-path", normalize_path(resolved_ndk)])
    elif phase_flags["vmp_dex"] or phase_flags["dex2c"] or config.get("featureVmpShellDex"):
        raise FileNotFoundError("NDK not found. Set a valid NDK path or install Android NDK.")

    if phase_flags["extract"] and int(config.get("minExtract", 0) or 0) > 0:
        args.extend(["--min-extract-count", str(int(config["minExtract"]))])
    if phase_flags["vmp_dex"] and int(config.get("minVmp", 0) or 0) > 0:
        args.extend(["--min-vmp-dex-count", str(int(config["minVmp"]))])
    if phase_flags["dex2c"] and int(config.get("minDex2c", 0) or 0) > 0:
        args.extend(["--min-dex2c-count", str(int(config["minDex2c"]))])
    requested_min_score = int(config.get("minScore", 0) or 0)
    effective_min_score = min(requested_min_score, max_reachable_security_score(config))
    if effective_min_score > 0:
        args.extend(["--min-security-score", str(effective_min_score)])

    if report_json:
        ensure_parent(report_json)
        args.extend(["--report-json", report_json])

    if config.get("releaseManifestEnabled"):
        manifest = Path(release_manifest).expanduser() if release_manifest else REPO_ROOT / "release" / "release_manifest.json"
        if not manifest.is_absolute():
            manifest = (REPO_ROOT / manifest).resolve()
        else:
            manifest = manifest.resolve()
        if not manifest.exists():
            raise FileNotFoundError(f"release manifest not found: {manifest}")
        args.extend(["--release-manifest", str(manifest)])

    if config.get("featureVmpShellDex"):
        args.append("--vmp-shell-dex")
    if config.get("featurePolymorphicShell"):
        args.append("--polymorphic-shell")
    # AI decoy (P5-7). Commercial mode auto-enables in the packer, so we only
    # append the flag when the UI explicitly toggles it on outside that case.
    if config.get("featureAiDecoy") and not config.get("commercialMode"):
        args.append("--ai-decoy")

    if phase_flags["dex2c"]:
        dex2c_ollvm = bool(config.get("dex2cOllvm", True))
        args.append("--dex2c-ollvm" if dex2c_ollvm else "--no-dex2c-ollvm")
        ollvm_clang = str(config.get("dex2cOllvmClang", "")).strip()
        if dex2c_ollvm and ollvm_clang:
            args.extend(["--dex2c-ollvm-clang", ollvm_clang])
        if dex2c_ollvm and bool(config.get("dex2cOllvmRequired", False)):
            args.append("--dex2c-ollvm-required")

    sign_cert_sha256 = str(config.get("signCertSha256", "")).strip()
    if sign_cert_sha256:
        args.extend(["--sign-cert-sha256", sign_cert_sha256])

    if config.get("signingEnabled"):
        keystore = str(config.get("keystorePath", "")).strip()
        key_alias = str(config.get("keyAlias", "")).strip()
        if not keystore or not key_alias:
            raise ValueError("signingEnabled requires keystorePath and keyAlias")
        args.extend(
            [
                "--sign",
                "--keystore",
                keystore,
                "--ks-pass",
                str(config.get("ksPass", "")),
                "--key-alias",
                key_alias,
                "--key-pass",
                str(config.get("keyPass", "")),
            ]
        )
    else:
        args.append("--skip-sign")

    target_abis = str(config.get("targetAbis", "")).strip()
    if target_abis:
        args.extend(["--target-abis", target_abis])

    resolved_tools = {}
    if defaults["apktool"] and path_exists(defaults["apktool"]):
        resolved_tools["apktool"] = normalize_path(defaults["apktool"])
        args.extend(["--apktool", resolved_tools["apktool"]])
    if defaults["zipalign"] and path_exists(defaults["zipalign"]):
        resolved_tools["zipalign"] = normalize_path(defaults["zipalign"])
        args.extend(["--zipalign", resolved_tools["zipalign"]])
    else:
        raise FileNotFoundError("zipalign not found. Install Android build-tools or add zipalign to PATH.")
    if defaults["apksigner"] and path_exists(defaults["apksigner"]):
        resolved_tools["apksigner"] = normalize_path(defaults["apksigner"])
        args.extend(["--apksigner", resolved_tools["apksigner"]])
    elif config.get("signingEnabled"):
        raise FileNotFoundError("apksigner not found. Install Android build-tools or add apksigner to PATH.")

    ensure_parent(output_apk)

    preview = make_command_preview(args)
    metadata = {
        "input_apk": input_apk,
        "shell_apk": shell_apk,
        "protection_map": protection_map,
        "features": phase_summary,
        "filtered_counts": filtered_counts,
        "output_apk": output_apk,
        "report_json": report_json,
        "min_score_requested": requested_min_score,
        "min_score_effective": effective_min_score,
        "command_preview": preview,
        "resolved_tools": resolved_tools,
        "resolved_ndk": normalize_path(resolved_ndk) if resolved_ndk and path_exists(resolved_ndk) else "",
    }
    return args, preview, metadata


# ---------------------------------------------------------------------------
# Job state management
# ---------------------------------------------------------------------------

def append_job_log(job_id: str, line: str) -> None:
    with JOBS_LOCK:
        job = JOBS[job_id]
        log = job.setdefault("log", [])
        log.append(line.rstrip())
        if len(log) > 4000:
            del log[: len(log) - 4000]
        _persist_job_unlocked(job_id, job)


def update_job(job_id: str, **updates: Any) -> None:
    with JOBS_LOCK:
        JOBS[job_id].update(updates)
        _persist_job_unlocked(job_id, JOBS[job_id])


def snapshot_job(job_id: str) -> dict[str, Any]:
    with JOBS_LOCK:
        result: dict[str, Any] = _json_clone(JOBS[job_id])
    return _attach_artifact_details(result)


def delete_job_snapshot(job_id: str) -> None:
    try:
        job_state_path(job_id).unlink(missing_ok=True)
    except Exception:
        pass


def load_persisted_jobs(limit: int = 200) -> int:
    loaded = 0
    candidates = sorted(
        JOB_ROOT.glob(f"*/{JOB_STATE_FILENAME}"),
        key=lambda item: item.stat().st_mtime if item.exists() else 0,
        reverse=True,
    )
    for path in candidates[:limit]:
        data = _safe_read_json(path)
        if not data or not data.get("id"):
            continue
        job_id = str(data["id"])
        with JOBS_LOCK:
            if job_id in JOBS:
                continue
            status = data.get("status")
            if status in {"running", "queued"}:
                data["status"] = "failed"
                data["returncode"] = -1
                data["finished_at"] = data.get("finished_at") or now_iso()
                data["error"] = data.get("error") or "服务重启导致任务中断"
                data["progress_label"] = "服务重启后标记为失败"
                log = data.setdefault("log", [])
                if isinstance(log, list):
                    log.append("[web-console] task interrupted because the web service restarted")
            JOBS[job_id] = data
            _persist_job_unlocked(job_id, data)
            loaded += 1
    return loaded


# ---------------------------------------------------------------------------
# Job execution
# ---------------------------------------------------------------------------

def find_default_shell_apk() -> Path | None:
    """Locate the pre-built shell APK in the repository."""
    candidates = [
        REPO_ROOT / "shell-app" / "app" / "build" / "outputs" / "apk" / "release" / "app-release-unsigned.apk",
        REPO_ROOT / "shell-app" / "app" / "build" / "outputs" / "apk" / "release" / "app-release.apk",
        REPO_ROOT / "shell-app" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def run_job(job_id: str, command: list[str]) -> None:
    update_job(job_id, status="running", started_at=now_iso(), returncode=None)
    append_job_log(job_id, f"[web-console] cwd={REPO_ROOT}")
    append_job_log(job_id, f"[web-console] command={make_command_preview(command)}")

    process = subprocess.Popen(
        command,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    assert process.stdout is not None
    for line in process.stdout:
        append_job_log(job_id, line)

    process.wait()
    final_status = "succeeded" if process.returncode == 0 else "failed"
    extras: dict[str, Any] = {}
    # Try to read report.json for score/grade when job succeeds
    with JOBS_LOCK:
        report_path = JOBS.get(job_id, {}).get("report_json", "")
    if final_status == "succeeded" and report_path:
        try:
            rdata = json.loads(Path(report_path).read_text(encoding="utf-8"))
            extras["report"] = rdata
            extras["report_score"] = rdata.get("score")
            extras["report_max_score"] = rdata.get("max_score")
            extras["report_grade"] = rdata.get("grade")
            extras["report_compiled"] = rdata.get("compiled")
        except Exception:
            pass
    update_job(
        job_id,
        status=final_status,
        returncode=process.returncode,
        finished_at=now_iso(),
        **extras,
    )


def _run_job_safe(job_id: str, command: list[str]) -> None:
    try:
        run_job(job_id, command)
    except Exception as exc:  # pragma: no cover
        append_job_log(job_id, f"[web-console] fatal: {exc}")
        update_job(
            job_id,
            status="failed",
            error=str(exc),
            returncode=-1,
            finished_at=now_iso(),
        )


def create_job(config: dict[str, Any]) -> dict[str, Any]:
    job_id = uuid.uuid4().hex[:12]
    job_dir = JOB_ROOT / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    # Auto-fill shell APK if not provided (commercial mode)
    if not str(config.get("shellApk", "")).strip():
        default_shell = find_default_shell_apk()
        if default_shell:
            config["shellApk"] = str(default_shell)

    # Auto-generate output path if not provided
    if not str(config.get("outputApk", "")).strip():
        input_name = Path(str(config.get("inputApk", "app.apk"))).stem
        config["outputApk"] = str(job_dir / f"{input_name}-hardened.apk")

    # Auto-generate report path
    if not str(config.get("reportJsonPath", "")).strip():
        config["reportJsonPath"] = str(job_dir / "report.json")

    command, preview, metadata = build_command(config, job_dir)
    job = {
        "id": job_id,
        "status": "queued",
        "created_at": now_iso(),
        "started_at": None,
        "finished_at": None,
        "returncode": None,
        "log": ["[web-console] task queued"],
        "error": None,
        "progress": 0,
        "progress_label": "排队中",
        "command_preview": preview,
        **metadata,
    }

    with JOBS_LOCK:
        JOBS[job_id] = job
        _persist_job_unlocked(job_id, job)

    thread = threading.Thread(target=_run_job_safe, args=(job_id, command), daemon=True)
    thread.start()
    return snapshot_job(job_id)


load_persisted_jobs()
