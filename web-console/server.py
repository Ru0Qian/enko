from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from common import (
    JOBS,
    JOBS_LOCK,
    JOB_ROOT,
    REPO_ROOT,
    UPLOAD_ROOT,
    WEB_ROOT,
    _run_job_safe,
    append_job_log,
    build_command,
    create_job,
    delete_job_snapshot,
    discover_environment_defaults,
    find_default_shell_apk,
    make_command_preview,
    now_iso,
    snapshot_job,
    update_job,
)

# --- Rate limiter -----------------------------------------------------------
_RATE_WINDOW = 60          # seconds
_RATE_MAX_REQUESTS = 30    # max requests per IP within the window
_rate_buckets: dict[str, list[float]] = {}
_rate_lock = threading.Lock()
_DEV_TOKEN = "dev-token"


def _check_rate_limit(ip: str) -> float | None:
    """Return None if within limit, else seconds until next allowed request."""
    import time
    now = time.monotonic()
    with _rate_lock:
        bucket = _rate_buckets.setdefault(ip, [])
        # prune expired entries
        cutoff = now - _RATE_WINDOW
        bucket[:] = [t for t in bucket if t > cutoff]
        if len(bucket) >= _RATE_MAX_REQUESTS:
            retry_after = bucket[0] - cutoff
            return max(retry_after, 1.0)
        bucket.append(now)
        return None


# HTTP helpers (dev server specific — depend on SimpleHTTPRequestHandler)

def send_json(handler: SimpleHTTPRequestHandler, payload: dict[str, Any], status: int = HTTPStatus.OK) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def send_error(handler: SimpleHTTPRequestHandler, message: str, status: int = HTTPStatus.BAD_REQUEST,
               error_code: str | None = None) -> None:
    payload: dict[str, Any] = {"error": message, "detail": message}
    if error_code:
        payload["error_code"] = error_code
    send_json(handler, payload, status=status)


def read_json(handler: SimpleHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length)
    result: dict[str, Any] = json.loads(raw.decode("utf-8"))
    return result


def list_job_snapshots() -> list[dict[str, Any]]:
    with JOBS_LOCK:
        job_ids = list(JOBS.keys())
    jobs = [snapshot_job(jid) for jid in job_ids]
    jobs.sort(key=lambda j: j.get("created_at") or "", reverse=True)
    return jobs


def build_stats_payload() -> dict[str, Any]:
    jobs = list_job_snapshots()
    total = len(jobs)
    succeeded = sum(1 for job in jobs if job.get("status") == "succeeded")
    failed = sum(1 for job in jobs if job.get("status") == "failed")
    running = sum(1 for job in jobs if job.get("status") in {"running", "queued"})
    today = time.strftime("%Y-%m-%d")
    today_jobs = [job for job in jobs if str(job.get("created_at", "")).startswith(today)]
    scores = [
        float(job["report_score"])
        for job in jobs
        if isinstance(job.get("report_score"), (int, float))
    ]
    grades: dict[str, int] = {}
    for job in jobs:
        grade = job.get("report_grade")
        if grade:
            grades[str(grade)] = grades.get(str(grade), 0) + 1
    return {
        "total_jobs": total,
        "succeeded": succeeded,
        "failed": failed,
        "running": running,
        "success_rate": (succeeded / (succeeded + failed)) if (succeeded + failed) else None,
        "avg_score": (sum(scores) / len(scores)) if scores else None,
        "today_jobs": len(today_jobs),
        "today_succeeded": sum(1 for job in today_jobs if job.get("status") == "succeeded"),
        "today_running": sum(1 for job in today_jobs if job.get("status") in {"running", "queued"}),
        "grade_distribution": grades,
        "recent_jobs": jobs[:8],
    }


def handle_upload(handler: SimpleHTTPRequestHandler) -> None:
    """Handle multipart file upload for APK files."""
    content_type = handler.headers.get("Content-Type", "")
    if "multipart/form-data" not in content_type:
        send_error(handler, "Content-Type must be multipart/form-data", error_code="INVALID_CONTENT_TYPE")
        return

    # Extract boundary
    boundary = None
    for segment in content_type.split(";"):
        segment = segment.strip()
        if segment.startswith("boundary="):
            boundary = segment[len("boundary="):]
            break
    if not boundary:
        send_error(handler, "missing boundary", error_code="MISSING_BOUNDARY")
        return

    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length)

    # Simple multipart parsing
    boundary_bytes = f"--{boundary}".encode()
    parts = raw.split(boundary_bytes)

    filename = "uploaded.apk"
    file_data = b""

    for part in parts:
        if b"Content-Disposition" not in part:
            continue
        header_end = part.find(b"\r\n\r\n")
        if header_end == -1:
            continue
        headers_raw = part[:header_end].decode("utf-8", errors="replace")
        body = part[header_end + 4:]
        if body.endswith(b"\r\n"):
            body = body[:-2]

        # Extract filename
        if 'filename="' in headers_raw:
            start = headers_raw.index('filename="') + len('filename="')
            end = headers_raw.index('"', start)
            fn = headers_raw[start:end]
            if fn:
                filename = Path(fn).name  # sanitize

        if b"name=\"file\"" in part or b"name=\"apk\"" in part or b'filename=' in part[:header_end]:
            file_data = body

    if not file_data:
        send_error(handler, "no file found in upload", error_code="MISSING_FILE")
        return

    # Save file with unique name
    unique_name = f"{uuid.uuid4().hex[:8]}_{filename}"
    save_path = UPLOAD_ROOT / unique_name
    save_path.write_bytes(file_data)

    send_json(handler, {
        "ok": True,
        "path": str(save_path),
        "filename": filename,
        "size": len(file_data),
    })


def handle_download(handler: SimpleHTTPRequestHandler, job_id: str) -> None:
    """Serve the output APK for a completed job."""
    with JOBS_LOCK:
        if job_id not in JOBS:
            send_error(handler, f"unknown job: {job_id}", status=HTTPStatus.NOT_FOUND, error_code="JOB_NOT_FOUND")
            return
        job = JOBS[job_id]

    output_apk = job.get("output_apk", "")
    if not output_apk or not Path(output_apk).exists():
        send_error(handler, "output APK not available", status=HTTPStatus.NOT_FOUND, error_code="OUTPUT_NOT_READY")
        return

    apk_path = Path(output_apk)
    apk_data = apk_path.read_bytes()
    handler.send_response(200)
    handler.send_header("Content-Type", "application/vnd.android.package-archive")
    handler.send_header("Content-Disposition", f'attachment; filename="{apk_path.name}"')
    handler.send_header("Content-Length", str(len(apk_data)))
    handler.end_headers()
    handler.wfile.write(apk_data)


PACKER_ROOT = REPO_ROOT / "packer"


def handle_analyze_methods(handler: SimpleHTTPRequestHandler) -> None:
    payload = read_json(handler)
    apk_path = Path(str(payload.get("apk_path", "")))
    if not apk_path.exists():
        send_error(handler, "APK 文件不存在", status=HTTPStatus.BAD_REQUEST, error_code="APK_NOT_FOUND")
        return

    flutter_mode = bool(payload.get("flutter_mode", False))
    include_packages = payload.get("include_packages", []) or []
    enabled_phases = payload.get("enabled_phases", {}) or {}
    selection_preset = str(payload.get("selection_preset", "balanced") or "balanced")

    try:
        if str(PACKER_ROOT) not in sys.path:
            sys.path.insert(0, str(PACKER_ROOT))
        from auto_protect_map import (
            FLUTTER_FRAMEWORK_PREFIXES,
            SYSTEM_PREFIXES,
            _infer_top_flutter_packages,
            _infer_top_packages,
            _in_selected_package,
            collect_methods_from_apk,
            pick_methods,
            recommend_level_for_method,
        )

        methods = collect_methods_from_apk(apk_path)
        exclude = list(SYSTEM_PREFIXES)
        if flutter_mode:
            for prefix in FLUTTER_FRAMEWORK_PREFIXES:
                if prefix not in exclude:
                    exclude.append(prefix)

        include = list(include_packages)
        if not include:
            include = (
                _infer_top_flutter_packages(methods, exclude_prefixes=exclude)
                if flutter_mode
                else _infer_top_packages(methods, topn=5, exclude_prefixes=exclude)
            )

        preset_counts = {
            "compat": {"extract": 8, "vmp": 14, "dex2c": 2},
            "balanced": {"extract": 12, "vmp": 28, "dex2c": 5},
            "strong": {"extract": 24, "vmp": 56, "dex2c": 8},
        }.get(selection_preset, {"extract": 12, "vmp": 28, "dex2c": 5})
        requested_counts = {
            "extract": int(payload.get("extract_count") if payload.get("extract_count") is not None else preset_counts["extract"]),
            "vmp": int(payload.get("vmp_count") if payload.get("vmp_count") is not None else preset_counts["vmp"]),
            "dex2c": int(payload.get("dex2c_count") if payload.get("dex2c_count") is not None else preset_counts["dex2c"]),
        }
        phase_enabled = {
            "extract": bool(enabled_phases.get("extract", True)),
            "vmp": bool(enabled_phases.get("vmp", True)),
            "dex2c": bool(enabled_phases.get("dex2c", True)),
        }
        for phase, active in phase_enabled.items():
            if not active:
                requested_counts[phase] = 0

        extract_sel, vmp_sel, d2c_sel = pick_methods(
            methods,
            include,
            exclude,
            vmp_count=max(0, requested_counts["vmp"]),
            dex2c_count=max(0, requested_counts["dex2c"]),
            extract_count=max(0, requested_counts["extract"]),
            min_score_vmp=15,
            min_score_dex2c=20,
            min_score_extract=8,
            flutter_mode=flutter_mode,
        )

        recommended: dict[str, dict[str, Any]] = {}
        for r in extract_sel:
            recommended[r.rec.spec] = {"level": 1, "label": "extract", "score": r.score, "reasons": r.reasons}
        for r in vmp_sel:
            recommended[r.rec.spec] = {"level": 2, "label": "vmp", "score": r.score, "reasons": r.reasons}
        for r in d2c_sel:
            recommended[r.rec.spec] = {"level": 3, "label": "dex2c", "score": r.score, "reasons": r.reasons}

        all_methods: list[dict[str, Any]] = []
        for m in methods:
            if m.class_desc.startswith(tuple(SYSTEM_PREFIXES)):
                continue
            in_scope = _in_selected_package(m.class_desc, include, exclude)
            best_level, best_label, best_score, best_reasons, phase_scores = recommend_level_for_method(
                m,
                flutter_mode=flutter_mode,
                enabled_phases=phase_enabled,
            )
            all_methods.append({
                "spec": m.spec,
                "class": m.class_desc,
                "method": m.method_name,
                "signature": m.signature,
                "code_bytes": m.code_bytes,
                "registers": m.registers_size,
                "outs": m.outs_size,
                "tries": m.tries_size,
                "package": m.package_name,
                "dex": m.dex_name,
                "in_scope": in_scope,
                "best_level": best_level,
                "best_label": best_label,
                "best_score": best_score,
                "best_reasons": best_reasons,
                "scores": {
                    phase: {"score": ranked.score, "reasons": ranked.reasons}
                    for phase, ranked in phase_scores.items()
                },
            })

        send_json(handler, {
            "ok": True,
            "total_methods": len(methods),
            "scoped_methods": sum(1 for m in all_methods if m["in_scope"]),
            "include_packages": include,
            "enabled_phases": phase_enabled,
            "selection_preset": selection_preset,
            "recommended": recommended,
            "all_methods": all_methods,
            "summary": {
                "extract": len(extract_sel),
                "vmp": len(vmp_sel),
                "dex2c": len(d2c_sel),
            },
        })
    except Exception as exc:
        send_error(handler, f"分析失败: {exc}", status=HTTPStatus.INTERNAL_SERVER_ERROR, error_code="ANALYZE_FAILED")


def handle_save_protection_map(handler: SimpleHTTPRequestHandler) -> None:
    payload = read_json(handler)
    map_content = str(payload.get("content", ""))
    if not map_content.strip():
        send_error(handler, "保护映射表内容为空", status=HTTPStatus.BAD_REQUEST, error_code="EMPTY_MAP")
        return
    if len(map_content) > 500_000:
        send_error(handler, "映射表过大（上限 500KB）", status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE, error_code="MAP_TOO_LARGE")
        return

    for i, line in enumerate(map_content.strip().splitlines(), 1):
        parts = line.strip().split()
        if len(parts) < 2:
            send_error(handler, f"第 {i} 行格式错误", status=HTTPStatus.BAD_REQUEST, error_code="INVALID_FORMAT")
            return
        if parts[-1] not in ("0", "1", "2", "3"):
            send_error(handler, f"第 {i} 行保护级别无效（应为 0-3）", status=HTTPStatus.BAD_REQUEST, error_code="INVALID_LEVEL")
            return

    out_dir = REPO_ROOT / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    map_path = out_dir / f"protection-map-{uuid.uuid4().hex[:8]}.txt"
    map_path.write_text(map_content, encoding="utf-8")
    send_json(handler, {"ok": True, "path": str(map_path)})


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        sys.stdout.write("[web-console] " + format % args + "\n")

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return
        if parsed.path == "/api/auth/check":
            send_json(
                self,
                {
                    "ok": True,
                    "username": "admin",
                    "tier": "pro",
                    "tier_limits": {"features": ["extract", "vmpDex", "dex2c"], "daily_limit": 0},
                },
            )
            return
        if parsed.path == "/api/health":
            default_shell = find_default_shell_apk()
            send_json(
                self,
                {
                    "ok": True,
                    "root": str(REPO_ROOT),
                    "defaults": discover_environment_defaults(),
                    "shellApkAvailable": default_shell is not None,
                    "defaultShellApk": str(default_shell) if default_shell else "",
                    "websocketAvailable": False,
                },
            )
            return
        if parsed.path == "/api/stats":
            send_json(self, build_stats_payload())
            return
        if parsed.path == "/api/admin/users":
            send_json(self, {"users": [{"username": "admin", "tier": "pro", "created_at": now_iso()}]})
            return
        if parsed.path == "/api/jobs":
            send_json(self, {"jobs": list_job_snapshots()})
            return
        if parsed.path.startswith("/api/jobs/") and parsed.path.endswith("/download"):
            job_id = parsed.path.split("/")[-2]
            handle_download(self, job_id)
            return
        if parsed.path.startswith("/api/jobs/"):
            job_id = parsed.path.rsplit("/", 1)[-1]
            with JOBS_LOCK:
                if job_id not in JOBS:
                    send_error(self, f"unknown job: {job_id}", status=HTTPStatus.NOT_FOUND, error_code="JOB_NOT_FOUND")
                    return
            send_json(self, {"job": snapshot_job(job_id)})
            return
        if parsed.path == "/react":
            self.send_response(HTTPStatus.MOVED_PERMANENTLY)
            self.send_header("Location", "/react/")
            self.end_headers()
            return
        if parsed.path.startswith("/react/"):
            rel_path = parsed.path[len("/react/"):] or "index.html"
            target = WEB_ROOT / "react-dist" / rel_path
            if target.is_dir():
                target = target / "index.html"
                rel_path = f"{rel_path.rstrip('/')}/index.html"
            self.path = f"/react-dist/{rel_path}" if target.is_file() else "/react-dist/index.html"
            return super().do_GET()
        if parsed.path in {"/", ""}:
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        # rate-limit mutating endpoints
        client_ip = self.client_address[0]
        retry_after = _check_rate_limit(client_ip)
        if retry_after is not None:
            import math
            ra = math.ceil(retry_after)
            self.send_response(HTTPStatus.TOO_MANY_REQUESTS)
            self.send_header("Retry-After", str(ra))
            self.send_header("Content-Type", "application/json; charset=utf-8")
            body = json.dumps({"error": "rate limit exceeded", "detail": "rate limit exceeded",
                               "error_code": "RATE_LIMITED", "retry_after": ra}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/upload":
            handle_upload(self)
            return
        if parsed.path == "/api/auth/login":
            payload = read_json(self)
            username = str(payload.get("username") or "admin")
            send_json(
                self,
                {
                    "token": _DEV_TOKEN,
                    "username": username,
                    "tier": "pro",
                    "tier_limits": {"features": ["extract", "vmpDex", "dex2c"], "daily_limit": 0},
                },
            )
            return
        if parsed.path == "/api/auth/change-password":
            send_json(self, {"ok": True})
            return
        if parsed.path in {"/api/admin/set-tier", "/api/admin/create-user"}:
            send_json(self, {"ok": True})
            return
        if parsed.path == "/api/analyze-methods":
            handle_analyze_methods(self)
            return
        if parsed.path == "/api/save-protection-map":
            handle_save_protection_map(self)
            return
        if parsed.path.startswith("/api/jobs/") and parsed.path.endswith("/download-token"):
            job_id = parsed.path.split("/")[-2]
            with JOBS_LOCK:
                if job_id not in JOBS:
                    send_error(self, f"unknown job: {job_id}", status=HTTPStatus.NOT_FOUND, error_code="JOB_NOT_FOUND")
                    return
                output_apk = JOBS[job_id].get("output_apk", "")
            if not output_apk or not Path(output_apk).exists():
                send_error(self, "output APK not available", status=HTTPStatus.NOT_FOUND, error_code="OUTPUT_NOT_READY")
                return
            send_json(self, {"token": _DEV_TOKEN})
            return
        if parsed.path != "/api/jobs":
            send_error(self, "unknown endpoint", status=HTTPStatus.NOT_FOUND, error_code="NOT_FOUND")
            return

        try:
            payload = read_json(self)
            job = create_job(payload)
            send_json(self, {"job": job}, status=HTTPStatus.CREATED)
        except Exception as exc:
            send_error(self, str(exc), error_code="JOB_CREATE_FAILED")

    def do_DELETE(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/admin/users/"):
            send_json(self, {"ok": True})
            return
        if not parsed.path.startswith("/api/jobs/"):
            send_error(self, "unknown endpoint", status=HTTPStatus.NOT_FOUND, error_code="NOT_FOUND")
            return
        job_id = parsed.path.rsplit("/", 1)[-1]
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                send_error(self, f"unknown job: {job_id}", status=HTTPStatus.NOT_FOUND, error_code="JOB_NOT_FOUND")
                return
            if job.get("status") in {"running", "queued"}:
                send_error(self, "cannot delete a running job", status=HTTPStatus.CONFLICT, error_code="JOB_RUNNING")
                return
            del JOBS[job_id]
        delete_job_snapshot(job_id)
        send_json(self, {"ok": True})


def main() -> None:
    host = "127.0.0.1"
    port = 8036
    print(f"[web-console] serving {WEB_ROOT} on http://{host}:{port}")
    server = ThreadingHTTPServer((host, port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
