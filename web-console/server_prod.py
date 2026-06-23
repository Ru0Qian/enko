"""Enko Web Console — FastAPI production server.

Security hardened, PostgreSQL-backed, WebSocket-enabled.

    uvicorn web-console.server_prod:app --host 0.0.0.0 --port 8036
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import asyncpg
from fastapi import (
    FastAPI, HTTPException, Request, Depends, status,
    UploadFile, File, WebSocket, WebSocketDisconnect, Query,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse

# Structured error helper
def api_error(status_code: int, detail: str, error_code: str = "", *, headers: dict | None = None):
    """Raise HTTPException with optional error_code for client-side handling."""
    raise HTTPException(
        status_code=status_code,
        detail={"message": detail, "error_code": error_code} if error_code else detail,
        headers=headers,
    )
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from starlette.websockets import WebSocketState

logger = logging.getLogger("enko")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
WEB_ROOT = Path(__file__).resolve().parent
REPO_ROOT = WEB_ROOT.parent
JOB_ROOT = WEB_ROOT / ".job-cache"
JOB_ROOT.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Import shared helpers from common module
# ---------------------------------------------------------------------------
sys.path.insert(0, str(WEB_ROOT))
from common import (  # noqa: E402
    JOBS, JOBS_LOCK, UPLOAD_ROOT,
    build_command, discover_environment_defaults, path_exists,
    find_default_shell_apk, make_command_preview, now_iso, snapshot_job, delete_job_snapshot,
    append_job_log as _orig_append_log, update_job as _orig_update_job,
    run_job as _orig_run_job, _run_job_safe as _orig_run_job_safe,
    create_job,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATABASE_URL = os.environ.get("ENKO_DATABASE_URL", "postgresql://enko:enko@localhost:5432/enko")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = int(os.environ.get("ENKO_JWT_EXPIRE_HOURS", "24"))
ADMIN_USER = os.environ.get("ENKO_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ENKO_ADMIN_PASS", "")
if not ADMIN_PASS:
    ADMIN_PASS = secrets.token_urlsafe(16)
    logger.warning(
        "ENKO_ADMIN_PASS not set — generated temporary password: %s  "
        "Set ENKO_ADMIN_PASS environment variable for persistent credentials.",
        ADMIN_PASS,
    )
MAX_CONCURRENT = int(os.environ.get("ENKO_MAX_CONCURRENT_JOBS", "3"))
UPLOAD_TTL_HOURS = int(os.environ.get("ENKO_UPLOAD_TTL_HOURS", "24"))
JOB_TTL_DAYS = int(os.environ.get("ENKO_JOB_TTL_DAYS", "7"))
PRODUCTION = os.environ.get("ENKO_PRODUCTION", "").lower() in ("true", "1", "yes")
PUBLIC_API_REDACTION = os.environ.get("ENKO_PUBLIC_API_REDACTION", "true").lower() not in ("0", "false", "no")
ENABLE_PUBLIC_DOCS = os.environ.get("ENKO_ENABLE_PUBLIC_DOCS", "").lower() in ("1", "true", "yes")
MONITOR_TOKEN = os.environ.get("ENKO_MONITOR_TOKEN", "")

# ---------------------------------------------------------------------------
# Tier definitions — feature gates per user tier
# ---------------------------------------------------------------------------
TIER_LIMITS: dict[str, dict[str, Any]] = {
    "free": {
        "max_concurrent": 1,
        "daily_limit": 3,
        "features": ["extract"],
        "risk_policies": ["log"],
        "risk_profiles": ["compat"],
        "allow_signing": False,
        "allow_per_apk_key": False,
        "allow_commercial_mode": False,
        "allow_analyze_methods": False,
        "allow_vmp_shell_dex": False,
        "allow_polymorphic_shell": False,
        "allow_release_manifest": False,
        "allow_native_gate": False,
    },
    "pro": {
        "max_concurrent": 3,
        "daily_limit": 0,  # 0 = unlimited
        "features": ["extract", "vmpDex", "dex2c"],
        "risk_policies": ["log", "block", "exit"],
        "risk_profiles": ["compat", "balanced", "strict"],
        "allow_signing": True,
        "allow_per_apk_key": True,
        "allow_commercial_mode": True,
        "allow_analyze_methods": True,
        "allow_vmp_shell_dex": True,
        "allow_polymorphic_shell": True,
        "allow_release_manifest": True,
        "allow_native_gate": True,
    },
}

# CORS: explicit origins in production; warn on wildcard
_cors_env = os.environ.get("ENKO_CORS_ORIGINS", "")
CORS_ORIGINS: list[str] = (
    [o.strip() for o in _cors_env.split(",") if o.strip()]
    if _cors_env
    else ([] if PUBLIC_API_REDACTION else ["*"])
)
if CORS_ORIGINS == ["*"]:
    logger.warning(
        "CORS allow_origins=['*'] — set ENKO_CORS_ORIGINS for production "
        "(e.g. ENKO_CORS_ORIGINS=https://console.example.com)"
    )
ALLOWED_ORIGIN_HOSTS = {
    parsed.netloc or origin
    for origin in CORS_ORIGINS
    for parsed in [urlparse(origin)]
    if origin != "*"
}

# JWT secret: auto-generate if placeholder
_jwt_secret_raw = os.environ.get("ENKO_JWT_SECRET", "CHANGE_ME_TO_A_RANDOM_64_CHAR_HEX_STRING")
JWT_SECRET_FILE = Path("/etc/enko/.jwt_secret")

def _resolve_jwt_secret() -> str:
    if _jwt_secret_raw != "CHANGE_ME_TO_A_RANDOM_64_CHAR_HEX_STRING":
        return _jwt_secret_raw
    if JWT_SECRET_FILE.exists():
        stored = JWT_SECRET_FILE.read_text().strip()
        if stored:
            return stored
    generated = secrets.token_hex(32)
    logger.warning("JWT secret was placeholder — auto-generated. Persisting to %s", JWT_SECRET_FILE)
    try:
        JWT_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        JWT_SECRET_FILE.write_text(generated)
    except OSError:
        logger.warning("Could not persist JWT secret to %s — it will change on restart", JWT_SECRET_FILE)
    return generated

JWT_SECRET = _resolve_jwt_secret()

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------------------------------------------------------------------
# Rate limiter (login + upload)
# ---------------------------------------------------------------------------
_login_attempts: dict[str, list[float]] = defaultdict(list)
_upload_attempts: dict[str, list[float]] = defaultdict(list)
_RATE_WINDOW = 60
_RATE_MAX = 5
_UPLOAD_RATE_WINDOW = 3600  # 1 hour
_UPLOAD_RATE_MAX = 30       # 30 uploads/hour per IP

def _public_path_label(value: Any) -> str:
    if not value:
        return ""
    try:
        return Path(str(value)).name or "artifact"
    except Exception:
        return "artifact"

_PUBLIC_UPLOAD_PREFIX = "enko://upload/"
_PUBLIC_MAP_PREFIX = "enko://map/"
_PUBLIC_SHELL_DEFAULT = "enko://shell/default"

def _safe_child_path(root: Path, name: str) -> Path:
    root_resolved = root.resolve()
    candidate = (root_resolved / Path(name).name).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"message": "文件凭证无效，请重新上传。", "error_code": "INVALID_FILE_REF"},
        )
    return candidate

def _public_file_ref(prefix: str, path: Path) -> str:
    return f"{prefix}{Path(path).name}"

def _resolve_public_ref(value: Any, *, expected: str) -> str:
    text = str(value or "").strip()
    if not text or not PUBLIC_API_REDACTION:
        return text

    if expected == "upload" and text.startswith(_PUBLIC_UPLOAD_PREFIX):
        path = _safe_child_path(UPLOAD_ROOT, text[len(_PUBLIC_UPLOAD_PREFIX):])
        if not path.exists():
            raise HTTPException(status_code=400, detail={"message": "APK 文件不存在，请重新上传。", "error_code": "APK_NOT_FOUND"})
        return str(path)

    if expected == "map" and text.startswith(_PUBLIC_MAP_PREFIX):
        path = _safe_child_path(REPO_ROOT / "output", text[len(_PUBLIC_MAP_PREFIX):])
        if not path.exists():
            raise HTTPException(status_code=400, detail={"message": "保护映射不存在，请重新生成。", "error_code": "MAP_NOT_FOUND"})
        return str(path)

    if expected == "shell" and text == _PUBLIC_SHELL_DEFAULT:
        default_shell = find_default_shell_apk()
        return str(default_shell) if default_shell else ""

    if text.startswith("enko://"):
        raise HTTPException(
            status_code=400,
            detail={"message": "文件凭证类型不匹配，请重新上传。", "error_code": "INVALID_FILE_REF"},
        )

    raise HTTPException(
        status_code=400,
        detail={"message": "公开接口不接受服务器路径，请通过控制台上传文件。", "error_code": "RAW_PATH_REJECTED"},
    )

def _normalize_public_job_config(config: dict[str, Any]) -> dict[str, Any]:
    if not PUBLIC_API_REDACTION:
        return config

    safe = dict(config)
    safe["inputApk"] = _resolve_public_ref(safe.get("inputApk"), expected="upload")
    if safe.get("protectionMap"):
        safe["protectionMap"] = _resolve_public_ref(safe.get("protectionMap"), expected="map")

    # Public users should not be able to point the build process at arbitrary
    # server files. These fields are generated or discovered inside the server.
    safe["shellApk"] = ""
    safe["outputApk"] = ""
    safe["reportJsonPath"] = ""
    safe["ndkPath"] = "<auto-detected>"
    safe["dex2cOllvmClang"] = ""
    safe["releaseManifestPath"] = ""
    safe["keystorePath"] = ""
    safe["ksPass"] = ""
    safe["keyPass"] = ""

    if safe.get("signingEnabled"):
        raise HTTPException(
            status_code=400,
            detail={"message": "公开版暂不支持路径式签名证书，请使用服务端托管签名方案。", "error_code": "PUBLIC_SIGNING_DISABLED"},
        )

    return safe

_PUBLIC_GENERIC_ERROR = "任务失败，请检查输入文件或联系支持。"
_PATH_TEXT_RE = re.compile(r"([A-Za-z]:[\\/][^\s\"']+|/(?:[^/\s\"']+/)+[^\s\"']+)")
_SENSITIVE_REPORT_KEY_PARTS = (
    "path",
    "apk",
    "keystore",
    "tool",
    "command",
    "cmd",
    "cwd",
    "manifest",
)

def _redact_public_text(value: str) -> str:
    text = value
    for raw in (str(REPO_ROOT), str(WEB_ROOT), str(JOB_ROOT), str(UPLOAD_ROOT)):
        if raw:
            text = text.replace(raw, "[redacted-path]")
    text = _PATH_TEXT_RE.sub("[redacted-path]", text)
    return text

def _public_report_snapshot(value: Any) -> Any:
    if not PUBLIC_API_REDACTION:
        return value
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            lower = str(key).lower()
            if any(part in lower for part in _SENSITIVE_REPORT_KEY_PARTS):
                continue
            result[str(key)] = _public_report_snapshot(item)
        return result
    if isinstance(value, list):
        return [_public_report_snapshot(item) for item in value]
    if isinstance(value, str):
        return _redact_public_text(value)
    return value

def _job_owner(job: dict[str, Any]) -> str:
    return str(job.get("owner") or job.get("_username") or "").strip()

def _can_access_job(job: dict[str, Any], username: str) -> bool:
    if username == ADMIN_USER:
        return True
    owner = _job_owner(job)
    return bool(owner and owner == username)

def _require_job_access(job_id: str, username: str) -> dict[str, Any]:
    with JOBS_LOCK:
        if job_id not in JOBS:
            raise HTTPException(status_code=404, detail=f"unknown job: {job_id}")
        job = JOBS[job_id]
        if not _can_access_job(job, username):
            raise HTTPException(status_code=404, detail=f"unknown job: {job_id}")
        return dict(job)

def public_job_snapshot(job: dict[str, Any]) -> dict[str, Any]:
    """Return a public-safe job payload without server paths, commands, or logs."""
    if not PUBLIC_API_REDACTION:
        return job
    allowed = {
        "id",
        "status",
        "created_at",
        "started_at",
        "finished_at",
        "returncode",
        "return_code",
        "progress",
        "progress_label",
        "error",
        "report_score",
        "report_max_score",
        "report_grade",
        "report_compiled",
        "features",
        "filtered_counts",
        "min_score_requested",
        "min_score_effective",
        "output_exists",
        "report_exists",
        "report",
    }
    result = {key: value for key, value in job.items() if key in allowed}
    if "input_apk" in job:
        result["input_apk"] = _public_path_label(job.get("input_apk"))
    if "output_apk" in job:
        result["output_apk"] = _public_path_label(job.get("output_apk"))
    if "report_json" in job:
        result["report_json"] = _public_path_label(job.get("report_json"))
    if "report" in result:
        result["report"] = _public_report_snapshot(result.get("report"))
    if "report_compiled" in result:
        result["report_compiled"] = _public_report_snapshot(result.get("report_compiled"))
    if result.get("error"):
        result["error"] = _PUBLIC_GENERIC_ERROR
    return result

def _check_rate_limit(ip: str) -> None:
    now = time.monotonic()
    attempts = _login_attempts[ip]
    _login_attempts[ip] = [t for t in attempts if now - t < _RATE_WINDOW]
    if len(_login_attempts[ip]) >= _RATE_MAX:
        oldest = min(_login_attempts[ip])
        retry_after = int(_RATE_WINDOW - (now - oldest)) + 1
        raise HTTPException(
            status_code=429,
            detail={"message": f"登录尝试过多，请 {retry_after} 秒后重试", "error_code": "RATE_LIMITED", "retry_after": retry_after},
            headers={"Retry-After": str(retry_after)},
        )
    _login_attempts[ip].append(now)

def _check_upload_rate_limit(ip: str) -> None:
    now = time.monotonic()
    attempts = _upload_attempts[ip]
    _upload_attempts[ip] = [t for t in attempts if now - t < _UPLOAD_RATE_WINDOW]
    if len(_upload_attempts[ip]) >= _UPLOAD_RATE_MAX:
        raise HTTPException(
            status_code=429,
            detail={"message": "上传频率过高，请稍后再试", "error_code": "UPLOAD_RATE_LIMITED"},
            headers={"Retry-After": "60"},
        )
    _upload_attempts[ip].append(now)

# ---------------------------------------------------------------------------
# Simple Prometheus-style metrics (no external dependency)
# ---------------------------------------------------------------------------
import collections as _collections
_metrics_requests = _collections.Counter()    # {(method, path, status): count}
_metrics_jobs = _collections.Counter()        # {status: count}
_metrics_job_durations: list[float] = []      # last 500 job durations
_METRICS_MAX_DURATIONS = 500

def _record_request(method: str, path: str, status: int):
    """Record HTTP request for metrics."""
    # Normalize path to avoid cardinality explosion
    base = path.split("?")[0]
    if base.startswith("/api/jobs/") and len(base) > 15:
        base = "/api/jobs/:id"
    _metrics_requests[(method, base, status)] += 1

def _record_job(status: str, duration_secs: float | None = None):
    _metrics_jobs[status] += 1
    if duration_secs is not None:
        _metrics_job_durations.append(duration_secs)
        if len(_metrics_job_durations) > _METRICS_MAX_DURATIONS:
            del _metrics_job_durations[:100]

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
_db_pool: asyncpg.Pool | None = None

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    tier TEXT NOT NULL DEFAULT 'free',
    daily_job_limit INTEGER NOT NULL DEFAULT 3,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ
);
-- Migration: add tier column if missing (for existing DBs)
DO $$ BEGIN
    ALTER TABLE users ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT 'free';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_job_limit INTEGER NOT NULL DEFAULT 3;
EXCEPTION WHEN others THEN NULL;
END $$;
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'queued',
    config JSONB,
    command_preview TEXT,
    output_apk TEXT,
    report_json TEXT,
    report_score INTEGER,
    report_max_score INTEGER,
    report_grade TEXT,
    report_compiled JSONB,
    features JSONB,
    resolved_tools JSONB,
    resolved_ndk TEXT,
    filtered_counts JSONB,
    min_score_requested INTEGER,
    min_score_effective INTEGER,
    error TEXT,
    returncode INTEGER,
    progress INTEGER DEFAULT 0,
    progress_label TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS job_logs (
    id SERIAL PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    line TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_job_logs_job_id ON job_logs(job_id);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_status_created ON jobs(status, created_at);
"""

async def _init_db() -> asyncpg.Pool:
    global _db_pool
    max_attempts = 5
    for attempt in range(1, max_attempts + 1):
        try:
            _db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
            async with _db_pool.acquire() as conn:
                await conn.execute(_SCHEMA_SQL)
            logger.info("Database connected (attempt %d)", attempt)
            return _db_pool
        except Exception as exc:
            wait = min(2 ** attempt, 30)
            logger.warning("DB connect failed (attempt %d/%d): %s — retry in %ds", attempt, max_attempts, exc, wait)
            if attempt < max_attempts:
                await asyncio.sleep(wait)
            else:
                logger.error("Database unavailable after %d attempts", max_attempts)
                raise

async def db_ensure_admin() -> None:
    """Insert default admin user if not exists — admin always gets 'pro' tier."""
    assert _db_pool
    async with _db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT username FROM users WHERE username=$1", ADMIN_USER)
        if not row:
            hashed = pwd_ctx.hash(ADMIN_PASS)
            await conn.execute(
                "INSERT INTO users (username, password_hash, tier) VALUES ($1, $2, 'pro')",
                ADMIN_USER, hashed,
            )
            logger.info("Created default admin user '%s' (tier=pro)", ADMIN_USER)
            if not os.environ.get("ENKO_ADMIN_PASS"):
                logger.warning("⚠ Auto-generated admin password — set ENKO_ADMIN_PASS for production")
        else:
            # Ensure admin always has pro tier
            await conn.execute("UPDATE users SET tier='pro' WHERE username=$1 AND tier != 'pro'", ADMIN_USER)

async def db_verify_password(username: str, password: str) -> bool:
    assert _db_pool
    async with _db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT password_hash FROM users WHERE username=$1", username)
    if not row:
        return False
    return pwd_ctx.verify(password, row["password_hash"])

async def db_change_password(username: str, new_password: str) -> None:
    assert _db_pool
    hashed = pwd_ctx.hash(new_password)
    async with _db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET password_hash=$1, updated_at=NOW() WHERE username=$2",
            hashed, username,
        )

async def db_get_user_tier(username: str) -> str:
    """Return user tier ('free' or 'pro'). Defaults to 'free'."""
    if not _db_pool:
        return "pro" if username == ADMIN_USER else "free"
    async with _db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT tier FROM users WHERE username=$1", username)
    return row["tier"] if row else "free"

async def db_set_user_tier(username: str, tier: str) -> bool:
    """Set user tier. Returns False if user not found."""
    assert _db_pool
    async with _db_pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE users SET tier=$1, updated_at=NOW() WHERE username=$2", tier, username,
        )
    return result != "UPDATE 0"

async def db_get_user_daily_jobs(username: str) -> int:
    """Count how many jobs the user submitted today."""
    if not _db_pool:
        return 0
    async with _db_pool.acquire() as conn:
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM jobs WHERE config->>'_username'=$1 AND created_at >= $2",
            username, today,
        )
    return count or 0

async def db_list_users() -> list[dict[str, Any]]:
    """List all users (for admin panel)."""
    if not _db_pool:
        return []
    async with _db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT username, tier, created_at, updated_at FROM users ORDER BY created_at"
        )
    return [dict(r) for r in rows]

def check_tier_permission(tier: str, config: dict[str, Any]) -> str | None:
    """Check if the user's tier allows the requested config. Returns error message or None."""
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

    # Check features (frontend sends top-level featureVmpDex / featureDex2c)
    if config.get("featureVmpDex") and "vmpDex" not in limits["features"]:
        return "VMP 保护为专业版功能，请升级后使用"
    if config.get("featureDex2c") and "dex2c" not in limits["features"]:
        return "DEX2C 为专业版功能，请升级后使用"

    # Check risk policy
    risk_policy = config.get("riskPolicy", "log")
    if risk_policy not in limits["risk_policies"]:
        return f"风险策略 '{risk_policy}' 为专业版功能"

    # Check risk profile
    risk_profile = config.get("riskProfile", "compat")
    if risk_profile not in limits["risk_profiles"]:
        return f"风险等级 '{risk_profile}' 为专业版功能"

    # Check signing
    if config.get("signingEnabled") and not limits["allow_signing"]:
        return "加固端重签名为专业版功能"

    # Check commercial mode
    if config.get("commercialMode") and not limits["allow_commercial_mode"]:
        return "商业模式为专业版功能"

    # Check per-APK key
    if config.get("perApkKey") and not limits["allow_per_apk_key"]:
        return "独立密钥为专业版功能"

    # Check VMP shell DEX
    if (config.get("featureVmpShellDex") or config.get("vmpShellDex")) and not limits["allow_vmp_shell_dex"]:
        return "VMP Shell 保护为专业版功能"

    # Check polymorphic shell
    if (config.get("featurePolymorphicShell") or config.get("polymorphicShell")) and not limits["allow_polymorphic_shell"]:
        return "多态壳为专业版功能"

    # Check release manifest
    if config.get("releaseManifestEnabled") and not limits["allow_release_manifest"]:
        return "发布清单为专业版功能"

    return None

def _sanitize_config(config: dict[str, Any]) -> dict[str, Any]:
    """Remove signing secrets before DB storage."""
    safe = {k: v for k, v in config.items() if k not in ("ksPass", "keyPass")}
    return safe

async def db_insert_job(job: dict[str, Any], config: dict[str, Any]) -> None:
    assert _db_pool
    async with _db_pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO jobs (id, status, config, command_preview, output_apk, report_json,
               features, resolved_tools, resolved_ndk, filtered_counts,
               min_score_requested, min_score_effective, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)""",
            job["id"], job["status"], json.dumps(_sanitize_config(config)),
            job.get("command_preview", ""), job.get("output_apk", ""),
            job.get("report_json", ""),
            json.dumps(job.get("features", {})),
            json.dumps(job.get("resolved_tools", {})),
            job.get("resolved_ndk", ""),
            json.dumps(job.get("filtered_counts")),
            job.get("min_score_requested", 0), job.get("min_score_effective", 0),
            datetime.fromisoformat(job["created_at"]) if job.get("created_at") else datetime.now(timezone.utc),
        )

async def db_update_job(job_id: str, **kw: Any) -> None:
    if not _db_pool:
        return
    sets, vals, idx = [], [], 1
    col_map = {
        "status": "status", "returncode": "returncode", "error": "error",
        "started_at": "started_at", "finished_at": "finished_at",
        "report_score": "report_score", "report_max_score": "report_max_score",
        "report_grade": "report_grade", "report_compiled": "report_compiled",
        "progress": "progress", "progress_label": "progress_label",
    }
    for key, col in col_map.items():
        if key in kw:
            v = kw[key]
            if key in ("started_at", "finished_at") and isinstance(v, str):
                v = datetime.fromisoformat(v)
            if key == "report_compiled" and not isinstance(v, str):
                v = json.dumps(v) if v else None
            sets.append(f"{col}=${idx}")
            vals.append(v)
            idx += 1
    if not sets:
        return
    vals.append(job_id)
    sql = f"UPDATE jobs SET {', '.join(sets)} WHERE id=${idx}"
    try:
        async with _db_pool.acquire() as conn:
            await conn.execute(sql, *vals)
        if "status" in kw:
            invalidate_stats_cache()
    except Exception:
        logger.exception("db_update_job failed for %s", job_id)

async def db_append_log(job_id: str, line: str) -> None:
    if not _db_pool:
        return
    _log_buffer.setdefault(job_id, []).append(line)
    if len(_log_buffer[job_id]) >= _LOG_BATCH_SIZE:
        await _flush_log_buffer(job_id)

_log_buffer: dict[str, list[str]] = {}
_LOG_BATCH_SIZE = 50

async def _flush_log_buffer(job_id: str) -> None:
    lines = _log_buffer.pop(job_id, [])
    if not lines or not _db_pool:
        return
    try:
        async with _db_pool.acquire() as conn:
            await conn.executemany(
                "INSERT INTO job_logs (job_id, line) VALUES ($1, $2)",
                [(job_id, l) for l in lines],
            )
    except Exception:
        pass

async def flush_all_log_buffers() -> None:
    for job_id in list(_log_buffer.keys()):
        await _flush_log_buffer(job_id)

async def _load_jobs_from_db() -> None:
    """Load recent jobs from DB into memory on startup so dashboard survives restarts."""
    if not _db_pool:
        return
    try:
        async with _db_pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, status, config, command_preview, output_apk, report_json,
                       report_score, report_max_score, report_grade, report_compiled,
                       features, resolved_tools, resolved_ndk, filtered_counts,
                       min_score_requested, min_score_effective,
                       error, returncode, progress, progress_label,
                       created_at, started_at, finished_at
                FROM jobs ORDER BY created_at DESC LIMIT 100
            """)
            loaded = 0
            for row in rows:
                job_id = row["id"]
                with JOBS_LOCK:
                    if job_id in JOBS:
                        continue
                status = row["status"]
                # Mark stale running/queued jobs as failed (process died on restart)
                if status in ("running", "queued"):
                    status = "failed"
                    await conn.execute(
                        "UPDATE jobs SET status='failed', error='服务重启导致任务中断', finished_at=NOW() WHERE id=$1",
                        job_id,
                    )
                def _parse_json(val: str | None) -> Any:
                    if not val:
                        return None
                    try:
                        return json.loads(val)
                    except Exception:
                        return None
                stored_config = _parse_json(row["config"]) if isinstance(row["config"], str) else (row["config"] or {})
                owner = str(stored_config.get("_username", "")).strip() if isinstance(stored_config, dict) else ""
                job = {
                    "id": job_id,
                    "owner": owner,
                    "status": status,
                    "command_preview": row["command_preview"] or "",
                    "output_apk": row["output_apk"] or "",
                    "report_json": row["report_json"] or "",
                    "report_score": row["report_score"],
                    "report_max_score": row["report_max_score"],
                    "report_grade": row["report_grade"],
                    "report_compiled": _parse_json(row["report_compiled"]) if isinstance(row["report_compiled"], str) else row["report_compiled"],
                    "features": _parse_json(row["features"]) if isinstance(row["features"], str) else (row["features"] or {}),
                    "resolved_tools": _parse_json(row["resolved_tools"]) if isinstance(row["resolved_tools"], str) else (row["resolved_tools"] or {}),
                    "resolved_ndk": row["resolved_ndk"] or "",
                    "filtered_counts": _parse_json(row["filtered_counts"]) if isinstance(row["filtered_counts"], str) else row["filtered_counts"],
                    "min_score_requested": row["min_score_requested"] or 0,
                    "min_score_effective": row["min_score_effective"] or 0,
                    "error": row["error"] if status != "failed" or row["error"] else "服务重启导致任务中断",
                    "returncode": row["returncode"],
                    "progress": row["progress"] or 0,
                    "progress_label": row["progress_label"] or "",
                    "log": [],  # logs loaded lazily on get_job
                    "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                    "started_at": row["started_at"].isoformat() if row["started_at"] else None,
                    "finished_at": row["finished_at"].isoformat() if row["finished_at"] else None,
                }
                with JOBS_LOCK:
                    JOBS[job_id] = job
                loaded += 1
            logger.info("Loaded %d jobs from database", loaded)
    except Exception:
        logger.exception("Failed to load jobs from database")

# ---------------------------------------------------------------------------
# Stats cache — avoid expensive COUNT(*) on every request
# ---------------------------------------------------------------------------
_stats_cache: dict[str, dict[str, Any]] = {}
_stats_cache_time: dict[str, float] = {}
_STATS_CACHE_TTL = 60  # seconds

async def db_get_stats(username: str = "") -> dict[str, Any]:
    global _stats_cache, _stats_cache_time
    now = time.monotonic()
    cache_key = "__admin__" if username == ADMIN_USER else username
    if cache_key in _stats_cache and (now - _stats_cache_time.get(cache_key, 0.0)) < _STATS_CACHE_TTL:
        return _stats_cache[cache_key]
    assert _db_pool
    async with _db_pool.acquire() as conn:
        owner_clause = "" if username == ADMIN_USER else "config->>'_username'=$1"

        def where_clause(extra: str = "") -> str:
            clauses = [clause for clause in (owner_clause, extra) if clause]
            return f" WHERE {' AND '.join(clauses)}" if clauses else ""

        def args(*extra: Any) -> tuple[Any, ...]:
            return (() if username == ADMIN_USER else (username,)) + extra

        today_param = "$1" if username == ADMIN_USER else "$2"
        succeeded_filter = "status='succeeded'"
        failed_filter = "status='failed'"
        today_filter = f"created_at >= {today_param}"
        today_succeeded_filter = f"status='succeeded' AND created_at >= {today_param}"
        today_running_filter = f"status='running' AND created_at >= {today_param}"
        total = await conn.fetchval(f"SELECT COUNT(*) FROM jobs{where_clause()}", *args())
        succeeded = await conn.fetchval(f"SELECT COUNT(*) FROM jobs{where_clause(succeeded_filter)}", *args())
        failed = await conn.fetchval(f"SELECT COUNT(*) FROM jobs{where_clause(failed_filter)}", *args())
        avg_score = await conn.fetchval(f"SELECT AVG(report_score) FROM jobs{where_clause('report_score IS NOT NULL')}", *args())
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        today_jobs = await conn.fetchval(f"SELECT COUNT(*) FROM jobs{where_clause(today_filter)}", *args(today))
        today_succeeded = await conn.fetchval(f"SELECT COUNT(*) FROM jobs{where_clause(today_succeeded_filter)}", *args(today))
        today_running = await conn.fetchval(f"SELECT COUNT(*) FROM jobs{where_clause(today_running_filter)}", *args(today))
        grades = await conn.fetch(
            f"SELECT report_grade, COUNT(*) as cnt FROM jobs{where_clause('report_grade IS NOT NULL')} GROUP BY report_grade",
            *args(),
        )
        grade_dist = {r["report_grade"]: r["cnt"] for r in grades}
        recent = await conn.fetch(
            f"SELECT id, status, report_score, report_grade, created_at, finished_at FROM jobs{where_clause()} ORDER BY created_at DESC LIMIT 10",
            *args(),
        )
        recent_list = [
            {
                "id": r["id"], "status": r["status"],
                "score": r["report_score"], "grade": r["report_grade"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "finished_at": r["finished_at"].isoformat() if r["finished_at"] else None,
            }
            for r in recent
        ]
    success_rate = (succeeded / total) if total > 0 else 0
    result = {
        "total_jobs": total, "succeeded": succeeded, "failed": failed,
        "avg_score": round(float(avg_score), 1) if avg_score else None,
        "today_jobs": today_jobs, "today_succeeded": today_succeeded, "today_running": today_running,
        "success_rate": round(success_rate, 3),
        "grade_distribution": grade_dist,
        "recent_jobs": recent_list,
    }
    _stats_cache[cache_key] = result
    _stats_cache_time[cache_key] = now
    return result


def invalidate_stats_cache() -> None:
    _stats_cache_time.clear()

# ---------------------------------------------------------------------------
# WebSocket hub — broadcast job updates
# ---------------------------------------------------------------------------
_ws_clients: dict[str, set[WebSocket]] = defaultdict(set)

async def ws_broadcast(job_id: str, msg: dict[str, Any]) -> None:
    clients = _ws_clients.get(job_id, set()).copy()
    data = json.dumps(msg, ensure_ascii=False)
    for ws in clients:
        try:
            if ws.client_state == WebSocketState.CONNECTED:
                await ws.send_text(data)
        except Exception:
            _ws_clients[job_id].discard(ws)

# ---------------------------------------------------------------------------
# Progress detection from log lines
# ---------------------------------------------------------------------------
_PROGRESS_PATTERNS: list[tuple[str, int, str]] = [
    (r"apktool\s+d|decode", 10, "APK 解包"),
    (r"protection.?map|filtering", 20, "方法筛选"),
    (r"extract", 35, "方法抽取"),
    (r"vmp.*dex|vmp_dex", 50, "VMP 编译"),
    (r"dex2c", 65, "DEX2C 转换"),
    (r"apktool\s+b|repack", 75, "重新打包"),
    (r"zipalign", 85, "对齐优化"),
    (r"apksigner|sign", 90, "签名处理"),
    (r"report", 95, "生成报告"),
]

def detect_progress(line: str) -> tuple[int, str] | None:
    low = line.lower()
    for pattern, pct, label in _PROGRESS_PATTERNS:
        if re.search(pattern, low):
            return pct, label
    return None

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Server integration layer
#
# The production server extends the dev server (server.py) by wrapping its
# core functions with DB persistence, WebSocket broadcasting, and progress
# detection. This uses module-level patching — the dev server calls
# `append_job_log()` and `update_job()` which are replaced here with
# enhanced versions that also write to PostgreSQL and broadcast via WS.
# ---------------------------------------------------------------------------
_running_count = 0
_running_lock = threading.Lock()
_event_loop: asyncio.AbstractEventLoop | None = None

def _fire_async(coro: Any) -> None:
    loop = _event_loop
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(coro, loop)

def append_job_log_enhanced(job_id: str, line: str) -> None:
    _orig_append_log(job_id, line)
    _fire_async(db_append_log(job_id, line))
    progress = detect_progress(line)
    if progress:
        pct, label = progress
        _orig_update_job(job_id, progress=pct, progress_label=label)
        _fire_async(db_update_job(job_id, progress=pct, progress_label=label))
        _fire_async(ws_broadcast(job_id, {"type": "status", "progress": pct, "progress_label": label}))
    elif not PUBLIC_API_REDACTION:
        _fire_async(ws_broadcast(job_id, {"type": "log", "line": line}))

def update_job_enhanced(job_id: str, **updates: Any) -> None:
    _orig_update_job(job_id, **updates)
    _fire_async(db_update_job(job_id, **updates))
    public_updates = {k: v for k, v in updates.items() if k != "log"}
    if PUBLIC_API_REDACTION and public_updates.get("error"):
        public_updates["error"] = _PUBLIC_GENERIC_ERROR
    _fire_async(ws_broadcast(job_id, {"type": "status", **public_updates}))

import common as _common_mod  # noqa: E402
_common_mod.append_job_log = append_job_log_enhanced
_common_mod.update_job = update_job_enhanced

def create_job_with_db(config: dict[str, Any], username: str = "", tier: str = "free") -> dict[str, Any]:
    """Wraps server.create_job with tier-based gating and DB persistence."""
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

    # Tier feature gate
    tier_err = check_tier_permission(tier, config)
    if tier_err:
        raise HTTPException(status_code=403, detail={"message": tier_err, "error_code": "TIER_RESTRICTED"})

    # Tier concurrent limit
    max_conc = limits["max_concurrent"]
    global _running_count
    with _running_lock:
        if _running_count >= max_conc:
            raise HTTPException(
                status_code=429,
                detail={"message": f"当前等级最多 {max_conc} 个并发任务，请稍后重试", "error_code": "JOB_LIMIT"},
                headers={"Retry-After": "30"},
            )
        _running_count += 1

    # Tag config with username for daily limit tracking
    config["_username"] = username

    job_created = False
    try:
        from common import create_job as _orig_create_job
        job = _orig_create_job(config)
        job_created = True
        job["owner"] = username
        _orig_update_job(job["id"], owner=username)
        _fire_async(db_insert_job(job, config))
        return job
    except Exception:
        if not job_created:
            with _running_lock:
                _running_count = max(0, _running_count - 1)
        raise

# Patch the run_job_safe to decrement counter on finish
_orig_safe = _common_mod._run_job_safe

def _run_job_safe_counted(job_id: str, command: list[str]) -> None:
    _start = time.time()
    try:
        _orig_safe(job_id, command)
    finally:
        duration = time.time() - _start
        global _running_count
        with _running_lock:
            _running_count = max(0, _running_count - 1)
        # Sync final state to DB
        with JOBS_LOCK:
            if job_id in JOBS:
                j = JOBS[job_id]
                final_status = j.get("status", "failed")
                _record_job(final_status, duration)
                _fire_async(db_update_job(
                    job_id, status=final_status,
                    returncode=j.get("returncode"), finished_at=j.get("finished_at"),
                    report_score=j.get("report_score"), report_max_score=j.get("report_max_score"),
                    report_grade=j.get("report_grade"), report_compiled=j.get("report_compiled"),
                    error=j.get("error"), progress=100, progress_label="完成",
                ))
        _fire_async(flush_all_log_buffers())
        _fire_async(ws_broadcast(job_id, {"type": "finished"}))

_common_mod._run_job_safe = _run_job_safe_counted

# ---------------------------------------------------------------------------
# Cleanup background task
# ---------------------------------------------------------------------------
async def _cleanup_loop() -> None:
    while True:
        await asyncio.sleep(3600)
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=UPLOAD_TTL_HOURS)
            if UPLOAD_ROOT.exists():
                for f in UPLOAD_ROOT.iterdir():
                    if f.is_file():
                        mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
                        if mtime < cutoff:
                            f.unlink(missing_ok=True)
            job_cutoff = datetime.now(timezone.utc) - timedelta(days=JOB_TTL_DAYS)
            if JOB_ROOT.exists():
                for d in JOB_ROOT.iterdir():
                    if d.is_dir() and d.name != "uploads":
                        mtime = datetime.fromtimestamp(d.stat().st_mtime, tz=timezone.utc)
                        if mtime < job_cutoff:
                            shutil.rmtree(d, ignore_errors=True)
        except Exception:
            logger.exception("cleanup error")

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[override]
    global _event_loop
    _event_loop = asyncio.get_running_loop()
    try:
        await _init_db()
        await db_ensure_admin()
        await _load_jobs_from_db()
        logger.info("PostgreSQL connected")
    except Exception:
        logger.warning("PostgreSQL unavailable — falling back to memory-only mode")
    asyncio.create_task(_cleanup_loop())
    if not os.environ.get("ENKO_ADMIN_PASS"):
        logger.warning("⚠ Auto-generated password in use — set ENKO_ADMIN_PASS env var")
    yield
    if _db_pool:
        await _db_pool.close()

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Enko Sentinel Console",
    docs_url=None if PUBLIC_API_REDACTION and not ENABLE_PUBLIC_DOCS else "/docs",
    redoc_url=None if PUBLIC_API_REDACTION and not ENABLE_PUBLIC_DOCS else "/redoc",
    openapi_url=None if PUBLIC_API_REDACTION and not ENABLE_PUBLIC_DOCS else "/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security headers middleware
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if PRODUCTION:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:"
        )
    return response

# CSRF protection: validate Origin header on state-changing requests
@app.middleware("http")
async def csrf_protection(request: Request, call_next):
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        origin = request.headers.get("origin", "")
        referer = request.headers.get("referer", "")
        host = request.headers.get("host", "")
        # Allow requests with no origin (same-site forms, curl, etc.)
        if origin and host:
            origin_host = urlparse(origin).netloc
            if origin_host and origin_host != host and origin_host not in ALLOWED_ORIGIN_HOSTS:
                logger.warning("CSRF blocked: origin=%s host=%s", origin, host)
                return JSONResponse(status_code=403, content={"detail": "Cross-origin request blocked"})
    return await call_next(request)

# Request metrics middleware
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    response = await call_next(request)
    _record_request(request.method, request.url.path, response.status_code)
    return response
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

def create_token(username: str) -> tuple[str, int]:
    expires_in = JWT_EXPIRE_HOURS * 3600
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    payload = {"sub": username, "exp": expire}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, expires_in

def verify_token(request: Request) -> str:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing token")
    token = auth_header[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub", "")
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired token")

def verify_token_from_qs(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub", "")
    except JWTError:
        return ""

def verify_monitor_access(request: Request) -> None:
    if not PUBLIC_API_REDACTION:
        return
    auth_header = request.headers.get("Authorization", "")
    if MONITOR_TOKEN and auth_header == f"Bearer {MONITOR_TOKEN}":
        return
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="monitor token required")

# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
@app.post("/api/auth/login")
async def login(body: LoginRequest, request: Request):
    _check_rate_limit(request.client.host if request.client else "unknown")
    ok = await db_verify_password(body.username, body.password) if _db_pool else (
        body.username == ADMIN_USER and pwd_ctx.verify(body.password, pwd_ctx.hash(ADMIN_PASS))
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="wrong username or password")
    tier = await db_get_user_tier(body.username)
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    token, expires_in = create_token(body.username)
    return {
        "token": token, "expires_in": expires_in, "username": body.username,
        "tier": tier, "tier_limits": limits, "is_admin": body.username == ADMIN_USER,
    }

@app.get("/api/auth/check")
async def auth_check(username: str = Depends(verify_token)):
    tier = await db_get_user_tier(username)
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    return {"ok": True, "username": username, "tier": tier, "tier_limits": limits, "is_admin": username == ADMIN_USER}

@app.post("/api/auth/change-password")
async def change_password(body: ChangePasswordRequest, username: str = Depends(verify_token)):
    if not _db_pool:
        raise HTTPException(status_code=503, detail="database unavailable")
    ok = await db_verify_password(username, body.old_password)
    if not ok:
        raise HTTPException(status_code=403, detail="current password is wrong")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="password must be at least 8 characters")
    await db_change_password(username, body.new_password)
    return {"ok": True, "message": "password changed"}

# ---------------------------------------------------------------------------
# Admin endpoints (admin-only)
# ---------------------------------------------------------------------------
class SetTierRequest(BaseModel):
    username: str
    tier: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    tier: str = "free"

async def _require_admin(username: str = Depends(verify_token)) -> str:
    if username != ADMIN_USER:
        raise HTTPException(status_code=403, detail="admin only")
    return username

@app.get("/api/admin/users")
async def admin_list_users(username: str = Depends(_require_admin)):
    users = await db_list_users()
    return {"users": users}

@app.post("/api/admin/set-tier")
async def admin_set_tier(body: SetTierRequest, username: str = Depends(_require_admin)):
    if body.tier not in TIER_LIMITS:
        raise HTTPException(status_code=400, detail=f"invalid tier: {body.tier}")
    ok = await db_set_user_tier(body.username, body.tier)
    if not ok:
        raise HTTPException(status_code=404, detail=f"user not found: {body.username}")
    return {"ok": True, "username": body.username, "tier": body.tier}

@app.post("/api/admin/create-user")
async def admin_create_user(body: CreateUserRequest, username: str = Depends(_require_admin)):
    if not _db_pool:
        raise HTTPException(status_code=503, detail="database unavailable")
    if body.tier not in TIER_LIMITS:
        raise HTTPException(status_code=400, detail=f"invalid tier: {body.tier}")
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="password must be at least 8 characters")
    async with _db_pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT username FROM users WHERE username=$1", body.username)
        if existing:
            raise HTTPException(status_code=409, detail=f"user already exists: {body.username}")
        hashed = pwd_ctx.hash(body.password)
        await conn.execute(
            "INSERT INTO users (username, password_hash, tier) VALUES ($1, $2, $3)",
            body.username, hashed, body.tier,
        )
    return {"ok": True, "username": body.username, "tier": body.tier}

@app.delete("/api/admin/users/{target_user}")
async def admin_delete_user(target_user: str, username: str = Depends(_require_admin)):
    if target_user == ADMIN_USER:
        raise HTTPException(status_code=400, detail="cannot delete admin user")
    if not _db_pool:
        raise HTTPException(status_code=503, detail="database unavailable")
    async with _db_pool.acquire() as conn:
        result = await conn.execute("DELETE FROM users WHERE username=$1", target_user)
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail=f"user not found: {target_user}")
    return {"ok": True, "deleted": target_user}

def _path_state(path: Path | str | None, *, kind: str = "file") -> dict[str, Any]:
    if not path:
        return {"path": "", "exists": False, "kind": kind}
    item = Path(path)
    exists = item.exists()
    state: dict[str, Any] = {
        "path": str(item),
        "exists": exists,
        "kind": kind,
        "is_file": item.is_file() if exists else False,
        "is_dir": item.is_dir() if exists else False,
    }
    try:
        if exists:
            state["size"] = item.stat().st_size if item.is_file() else None
            state["writable"] = os.access(str(item if item.is_dir() else item.parent), os.W_OK)
    except Exception:
        state["writable"] = False
    return state

def _command_version(command: list[str]) -> dict[str, Any]:
    label = " ".join(command)
    try:
        completed = subprocess.run(
            command,
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
        )
        output = (completed.stdout or "").strip().splitlines()
        return {
            "command": label,
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "version": output[0][:240] if output else "",
        }
    except Exception as exc:
        return {"command": label, "ok": False, "returncode": None, "version": "", "error": str(exc)}

async def _database_state() -> dict[str, Any]:
    if not _db_pool:
        return {"connected": False, "checked": False}
    started = time.perf_counter()
    try:
        async with _db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {
            "connected": True,
            "checked": True,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
        }
    except Exception as exc:
        return {
            "connected": False,
            "checked": True,
            "error": str(exc)[:240],
        }

@app.get("/api/admin/diagnostics")
async def admin_diagnostics(username: str = Depends(_require_admin)):
    defaults = discover_environment_defaults()
    default_shell = find_default_shell_apk()
    env_names = [
        "ENKO_PRODUCTION",
        "ENKO_PUBLIC_API_REDACTION",
        "ENKO_CORS_ORIGINS",
        "ENKO_HOST",
        "ENKO_PORT",
        "ENKO_WORKERS",
        "ENKO_DATABASE_URL",
        "ANDROID_HOME",
        "ANDROID_SDK_ROOT",
        "JAVA_HOME",
        "GRADLE_USER_HOME",
    ]
    env = {name: ("set" if os.environ.get(name) else "") for name in env_names}
    if os.environ.get("ENKO_DATABASE_URL"):
        env["ENKO_DATABASE_URL"] = "set"
    database = await _database_state()
    return {
        "ok": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "server": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "executable": sys.executable,
            "cwd": os.getcwd(),
            "uid": os.getuid() if hasattr(os, "getuid") else None,
        },
        "flags": {
            "production": PRODUCTION,
            "public_api_redaction": PUBLIC_API_REDACTION,
            "public_docs_enabled": ENABLE_PUBLIC_DOCS,
            "monitor_token_configured": bool(MONITOR_TOKEN),
            "cors_origins": CORS_ORIGINS,
        },
        "paths": {
            "repo_root": _path_state(REPO_ROOT, kind="dir"),
            "web_root": _path_state(WEB_ROOT, kind="dir"),
            "job_root": _path_state(JOB_ROOT, kind="dir"),
            "upload_root": _path_state(UPLOAD_ROOT, kind="dir"),
            "output": _path_state(REPO_ROOT / "output", kind="dir"),
            "react_dist": _path_state(WEB_ROOT / "react-dist" / "index.html"),
            "packer": _path_state(REPO_ROOT / "packer" / "harden_apk.py"),
            "release_manifest": _path_state(REPO_ROOT / "release" / "release_manifest.json"),
        },
        "shell": {
            "available": default_shell is not None,
            "default": _path_state(default_shell),
            "candidates": [
                _path_state(REPO_ROOT / "shell-app" / "app" / "build" / "outputs" / "apk" / "release" / "app-release-unsigned.apk"),
                _path_state(REPO_ROOT / "shell-app" / "app" / "build" / "outputs" / "apk" / "release" / "app-release.apk"),
                _path_state(REPO_ROOT / "shell-app" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"),
            ],
        },
        "toolchain": {
            name: {**_path_state(value), "configured": bool(value), "usable": bool(value and path_exists(value))}
            for name, value in defaults.items()
        },
        "commands": {
            "java": _command_version(["java", "-version"]),
            "python": _command_version([sys.executable, "--version"]),
            "git": _command_version(["git", "--version"]),
            "node": _command_version(["node", "--version"]),
            "npm": _command_version(["npm", "--version"]),
        },
        "database": database,
        "environment": env,
    }

@app.get("/api/tier-info")
async def tier_info(username: str = Depends(verify_token)):
    """Get current user's tier details including usage."""
    tier = await db_get_user_tier(username)
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    daily_used = await db_get_user_daily_jobs(username)
    daily_limit = limits["daily_limit"]
    return {
        "tier": tier,
        "limits": limits,
        "usage": {
            "daily_jobs_used": daily_used,
            "daily_jobs_limit": daily_limit,
            "daily_jobs_remaining": max(0, daily_limit - daily_used) if daily_limit > 0 else -1,
        },
    }

# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health(username: str = Depends(verify_token)):
    default_shell = find_default_shell_apk()
    defaults = discover_environment_defaults()
    return {
        "ok": True,
        "root": "" if PUBLIC_API_REDACTION else str(REPO_ROOT),
        "defaults": {
            key: ("configured" if value else "")
            for key, value in defaults.items()
        } if PUBLIC_API_REDACTION else defaults,
        "shellApkAvailable": default_shell is not None,
        "defaultShellApk": "" if PUBLIC_API_REDACTION else (str(default_shell) if default_shell else ""),
        "username": username,
        "db_connected": _db_pool is not None,
        "version": "2.2.0",
        "websocketAvailable": True,
    }

@app.get("/api/health/deep")
async def health_deep(request: Request):
    """Deep health check for authenticated operators or monitor token holders."""
    verify_monitor_access(request)
    checks: dict[str, Any] = {"timestamp": datetime.now(timezone.utc).isoformat()}

    # DB connectivity
    try:
        if _db_pool:
            async with _db_pool.acquire() as conn:
                row = await conn.fetchval("SELECT 1")
            checks["database"] = {"ok": True}
        else:
            checks["database"] = {"ok": False, "error": "unavailable" if PUBLIC_API_REDACTION else "pool not initialized"}
    except Exception as exc:
        checks["database"] = {"ok": False, "error": "unavailable" if PUBLIC_API_REDACTION else str(exc)}

    # File system writable
    try:
        test_dir = REPO_ROOT / "output"
        test_dir.mkdir(parents=True, exist_ok=True)
        test_file = test_dir / ".health_check"
        test_file.write_text("ok")
        test_file.unlink()
        checks["filesystem"] = {"ok": True}
    except Exception as exc:
        checks["filesystem"] = {"ok": False, "error": "unavailable" if PUBLIC_API_REDACTION else str(exc)}

    # Packer available
    packer_ok = (REPO_ROOT / "packer" / "harden_apk.py").exists()
    checks["packer"] = {"ok": packer_ok}

    checks["ready"] = all(c.get("ok", False) for c in checks.values() if isinstance(c, dict))
    status_code = 200 if checks["ready"] else 503
    return JSONResponse(content=checks, status_code=status_code)

@app.get("/api/metrics")
async def metrics(request: Request):
    """Prometheus text exposition format metrics for authenticated monitoring."""
    verify_monitor_access(request)
    lines = ["# HELP enko_http_requests_total HTTP requests by method, path, status"]
    lines.append("# TYPE enko_http_requests_total counter")
    for (method, path, status), count in sorted(_metrics_requests.items()):
        lines.append(f'enko_http_requests_total{{method="{method}",path="{path}",status="{status}"}} {count}')

    lines.append("# HELP enko_jobs_total Jobs by final status")
    lines.append("# TYPE enko_jobs_total counter")
    for status, count in sorted(_metrics_jobs.items()):
        lines.append(f'enko_jobs_total{{status="{status}"}} {count}')

    if _metrics_job_durations:
        avg_dur = sum(_metrics_job_durations) / len(_metrics_job_durations)
        lines.append("# HELP enko_job_duration_avg_seconds Average job duration")
        lines.append("# TYPE enko_job_duration_avg_seconds gauge")
        lines.append(f"enko_job_duration_avg_seconds {avg_dur:.2f}")

    from starlette.responses import PlainTextResponse
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

@app.get("/api/stats")
async def stats(username: str = Depends(verify_token)):
    if not _db_pool:
        return {"total_jobs": 0, "succeeded": 0, "failed": 0, "avg_score": None,
                "today_jobs": 0, "today_succeeded": 0, "today_running": 0,
                "success_rate": 0, "grade_distribution": {}, "recent_jobs": []}
    return await db_get_stats(username)

@app.post("/api/upload")
async def upload_apk(request: Request, file: UploadFile = File(...), username: str = Depends(verify_token)):
    _check_upload_rate_limit(request.client.host if request.client else "unknown")
    if not file.filename:
        raise HTTPException(status_code=400, detail={"message": "未提供文件", "error_code": "NO_FILE"})
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail={"message": "文件为空", "error_code": "EMPTY_FILE"})
    sanitized = Path(file.filename).name
    unique_name = f"{uuid.uuid4().hex}_{sanitized}"
    save_path = UPLOAD_ROOT / unique_name
    save_path.write_bytes(content)
    public_path = _public_file_ref(_PUBLIC_UPLOAD_PREFIX, save_path) if PUBLIC_API_REDACTION else str(save_path)
    return {"ok": True, "path": public_path, "filename": sanitized, "size": len(content)}

# ---------------------------------------------------------------------------
# APK Method Analysis — protection map generation
# ---------------------------------------------------------------------------
PACKER_ROOT = REPO_ROOT / "packer"

@app.post("/api/analyze-methods")
async def analyze_methods(request: Request, username: str = Depends(verify_token)):
    """Analyze APK and return auto-recommended protection map + all protectable methods."""
    tier = await db_get_user_tier(username)
    if not TIER_LIMITS.get(tier, TIER_LIMITS["free"])["allow_analyze_methods"]:
        raise HTTPException(status_code=403, detail={"message": "智能方法分析为专业版功能", "error_code": "TIER_RESTRICTED"})
    payload = await request.json()
    apk_path_str = _resolve_public_ref(payload.get("apk_path", ""), expected="upload")
    flutter_mode = payload.get("flutter_mode", False)
    vmp_count = payload.get("vmp_count")
    dex2c_count = payload.get("dex2c_count")
    extract_count = payload.get("extract_count")
    include_packages = payload.get("include_packages", [])
    enabled_phases = payload.get("enabled_phases", {}) or {}
    selection_preset = str(payload.get("selection_preset", "balanced") or "balanced")

    apk_path = Path(apk_path_str)
    if not apk_path.exists():
        raise HTTPException(status_code=400, detail={"message": "APK 文件不存在", "error_code": "APK_NOT_FOUND"})

    try:
        # Import auto_protect_map from packer
        sys.path.insert(0, str(PACKER_ROOT))
        from auto_protect_map import (
            collect_methods_from_apk,
            pick_methods,
            _infer_top_packages,
            _infer_top_flutter_packages,
            _in_selected_package,
            recommend_level_for_method,
            SYSTEM_PREFIXES,
            FLUTTER_FRAMEWORK_PREFIXES,
        )

        def _do_analysis():
            methods = collect_methods_from_apk(apk_path)

            _exclude = list(SYSTEM_PREFIXES)
            if flutter_mode:
                for prefix in FLUTTER_FRAMEWORK_PREFIXES:
                    if prefix not in _exclude:
                        _exclude.append(prefix)

            _include = list(include_packages)
            if not _include:
                if flutter_mode:
                    _include = _infer_top_flutter_packages(methods, exclude_prefixes=_exclude)
                else:
                    _include = _infer_top_packages(methods, topn=5, exclude_prefixes=_exclude)

            preset_counts = {
                "compat": {"extract": 8, "vmp": 14, "dex2c": 2},
                "balanced": {"extract": 12, "vmp": 28, "dex2c": 5},
                "strong": {"extract": 24, "vmp": 56, "dex2c": 8},
            }.get(selection_preset, {"extract": 12, "vmp": 28, "dex2c": 5})
            requested_counts = {
                "extract": int(extract_count if extract_count is not None else preset_counts["extract"]),
                "vmp": int(vmp_count if vmp_count is not None else preset_counts["vmp"]),
                "dex2c": int(dex2c_count if dex2c_count is not None else preset_counts["dex2c"]),
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
                methods, _include, _exclude,
                vmp_count=max(0, requested_counts["vmp"]),
                dex2c_count=max(0, requested_counts["dex2c"]),
                extract_count=max(0, requested_counts["extract"]),
                min_score_vmp=15, min_score_dex2c=20, min_score_extract=8,
                flutter_mode=flutter_mode,
            )

            all_methods = []
            for m in methods:
                if m.class_desc.startswith(tuple(SYSTEM_PREFIXES)):
                    continue
                in_scope = _in_selected_package(m.class_desc, _include, _exclude)
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

            recommended = {}
            for r in extract_sel:
                recommended[r.rec.spec] = {"level": 1, "label": "extract", "score": r.score, "reasons": r.reasons}
            for r in vmp_sel:
                recommended[r.rec.spec] = {"level": 2, "label": "vmp", "score": r.score, "reasons": r.reasons}
            for r in d2c_sel:
                recommended[r.rec.spec] = {"level": 3, "label": "dex2c", "score": r.score, "reasons": r.reasons}

            return {
                "ok": True,
                "total_methods": len(methods),
                "scoped_methods": sum(1 for m in all_methods if m["in_scope"]),
                "include_packages": _include,
                "enabled_phases": phase_enabled,
                "selection_preset": selection_preset,
                "recommended": recommended,
                "all_methods": all_methods,
                "summary": {
                    "extract": len(extract_sel),
                    "vmp": len(vmp_sel),
                    "dex2c": len(d2c_sel),
                },
            }

        return await asyncio.to_thread(_do_analysis)
    except Exception as exc:
        logger.exception("analyze-methods failed")
        message = "分析失败，请检查 APK 或稍后重试。" if PUBLIC_API_REDACTION else f"分析失败: {exc}"
        raise HTTPException(status_code=500, detail={"message": message, "error_code": "ANALYZE_FAILED"})

@app.post("/api/save-protection-map")
async def save_protection_map(request: Request, username: str = Depends(verify_token)):
    """Save a generated protection map to a temp file and return the path."""
    payload = await request.json()
    map_content = payload.get("content", "")
    if not map_content.strip():
        raise HTTPException(status_code=400, detail={"message": "保护映射表内容为空", "error_code": "EMPTY_MAP"})
    if len(map_content) > 500_000:  # 500KB max
        raise HTTPException(status_code=413, detail={"message": "映射表过大（上限 500KB）", "error_code": "MAP_TOO_LARGE"})

    # Validate format: each line should be "<spec> <level>"
    for i, line in enumerate(map_content.strip().splitlines(), 1):
        parts = line.strip().split()
        if len(parts) < 2:
            raise HTTPException(status_code=400, detail={"message": f"第 {i} 行格式错误", "error_code": "INVALID_FORMAT"})
        if parts[-1] not in ("0", "1", "2", "3"):
            raise HTTPException(status_code=400, detail={"message": f"第 {i} 行保护级别无效（应为 0-3）", "error_code": "INVALID_LEVEL"})

    uploads_dir = REPO_ROOT / "output"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    map_path = uploads_dir / f"protection-map-{uuid.uuid4().hex}.txt"
    map_path.write_text(map_content, encoding="utf-8")
    public_path = _public_file_ref(_PUBLIC_MAP_PREFIX, map_path) if PUBLIC_API_REDACTION else str(map_path)
    return {"ok": True, "path": public_path}

@app.get("/api/jobs")
async def list_jobs(username: str = Depends(verify_token)):
    with JOBS_LOCK:
        job_ids = list(JOBS.keys())
    jobs = []
    for jid in job_ids:
        snapshot = snapshot_job(jid)
        if _can_access_job(snapshot, username):
            jobs.append(public_job_snapshot(snapshot))
    jobs.sort(key=lambda j: j.get("created_at") or "", reverse=True)
    return {"jobs": jobs}

@app.post("/api/jobs", status_code=201)
async def create_job_endpoint(request: Request, username: str = Depends(verify_token)):
    payload = await request.json()
    tier = await db_get_user_tier(username)
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

    # Daily limit check for non-unlimited tiers
    daily_limit = limits["daily_limit"]
    if daily_limit > 0:
        today_count = await db_get_user_daily_jobs(username)
        if today_count >= daily_limit:
            raise HTTPException(
                status_code=429,
                detail={"message": f"已达今日加固上限（{daily_limit} 次），明日重置或升级专业版",
                        "error_code": "DAILY_LIMIT"},
            )

    try:
        job = create_job_with_db(_normalize_public_job_config(payload), username=username, tier=tier)
        return {"job": public_job_snapshot(job)}
    except HTTPException:
        raise
    except Exception as exc:
        if PUBLIC_API_REDACTION:
            raise HTTPException(status_code=400, detail={"message": "任务创建失败，请检查配置或联系支持。", "error_code": "JOB_CREATE_FAILED"})
        raise HTTPException(status_code=400, detail=str(exc))

@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str, username: str = Depends(verify_token)):
    with JOBS_LOCK:
        if job_id not in JOBS or not _can_access_job(JOBS[job_id], username):
            raise HTTPException(status_code=404, detail=f"unknown job: {job_id}")
        has_log = bool(JOBS[job_id].get("log"))
    # Lazy-load logs from DB for restored jobs
    if not has_log and _db_pool:
        try:
            async with _db_pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT line FROM job_logs WHERE job_id=$1 ORDER BY id", job_id
                )
                if rows:
                    with JOBS_LOCK:
                        JOBS[job_id]["log"] = [r["line"] for r in rows]
        except Exception:
            logger.debug("Failed to lazy-load logs for job %s", job_id)
    return {"job": public_job_snapshot(snapshot_job(job_id))}

_dl_tokens: dict[str, tuple[str, float]] = {}  # token -> (job_id, expires_at)

@app.post("/api/jobs/{job_id}/download-token")
async def create_download_token(job_id: str, username: str = Depends(verify_token)):
    """Create a short-lived one-time download token for direct browser download."""
    job = _require_job_access(job_id, username)
    output_apk = job.get("output_apk", "")
    if not output_apk or not Path(output_apk).exists():
        raise HTTPException(status_code=404, detail="output APK not available")
    import secrets as _secrets
    token = _secrets.token_urlsafe(32)
    _dl_tokens[token] = (job_id, time.time() + 120)  # 2 min expiry
    # Cleanup expired tokens
    now = time.time()
    expired = [k for k, (_, exp) in _dl_tokens.items() if exp < now]
    for k in expired:
        _dl_tokens.pop(k, None)
    return {"token": token}

@app.get("/api/jobs/{job_id}/download")
async def download_job(job_id: str, dl_token: str | None = None, request: Request = None):
    # Auth: accept either dl_token query param or Authorization header
    if dl_token:
        entry = _dl_tokens.pop(dl_token, None)
        if not entry or entry[0] != job_id or entry[1] < time.time():
            raise HTTPException(status_code=403, detail="下载链接已过期或无效")
    else:
        username = verify_token(request)  # raises 401 if invalid
        _require_job_access(job_id, username)
    with JOBS_LOCK:
        if job_id not in JOBS:
            raise HTTPException(status_code=404, detail=f"unknown job: {job_id}")
        job = JOBS[job_id]
    output_apk = job.get("output_apk", "")
    if not output_apk or not Path(output_apk).exists():
        raise HTTPException(status_code=404, detail="output APK not available")
    fname = Path(output_apk).name
    media_type = "application/vnd.android.package-archive"
    return FileResponse(
        path=output_apk,
        media_type=media_type,
        filename=fname,
    )


@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: str, username: str = Depends(verify_token)):
    """Delete a completed/failed job from memory and database."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job or not _can_access_job(job, username):
            raise HTTPException(status_code=404, detail=f"unknown job: {job_id}")
        if job.get("status") in ("running", "queued"):
            raise HTTPException(status_code=409, detail="无法删除运行中或排队中的任务")
        del JOBS[job_id]
    delete_job_snapshot(job_id)
    # Remove from database
    if _db_pool:
        try:
            async with _db_pool.acquire() as conn:
                await conn.execute("DELETE FROM job_logs WHERE job_id=$1", job_id)
                await conn.execute("DELETE FROM jobs WHERE id=$1", job_id)
        except Exception:
            logger.warning("Failed to delete job %s from DB", job_id)
    # Cleanup output files
    output_apk = job.get("output_apk", "")
    if output_apk:
        apk_path = Path(output_apk)
        if apk_path.exists():
            try:
                apk_path.unlink()
            except Exception:
                pass
        # Try to clean the job cache directory
        job_dir = apk_path.parent
        if job_dir.exists() and job_dir != UPLOAD_ROOT:
            try:
                import shutil
                shutil.rmtree(job_dir, ignore_errors=True)
            except Exception:
                pass
    invalidate_stats_cache()
    return {"ok": True}

# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------
@app.websocket("/api/jobs/{job_id}/ws")
async def job_websocket(websocket: WebSocket, job_id: str, token: str = Query("")):
    username = verify_token_from_qs(token)
    if not username:
        await websocket.close(code=4001, reason="unauthorized")
        return
    with JOBS_LOCK:
        if job_id not in JOBS or not _can_access_job(JOBS[job_id], username):
            await websocket.close(code=4004, reason="unknown job")
            return
    await websocket.accept()
    _ws_clients[job_id].add(websocket)
    try:
        # Send current log history
        with JOBS_LOCK:
            if job_id in JOBS:
                j = JOBS[job_id]
                if not PUBLIC_API_REDACTION:
                    for line in j.get("log", []):
                        await websocket.send_text(json.dumps({"type": "log", "line": line}))
                await websocket.send_text(json.dumps({
                    "type": "status", "status": j.get("status"),
                    "progress": j.get("progress", 0),
                    "progress_label": j.get("progress_label", ""),
                }))
        # Keep alive until client disconnects or job finishes
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"type": "ping"}))
            except WebSocketDisconnect:
                break
    finally:
        _ws_clients[job_id].discard(websocket)

# ---------------------------------------------------------------------------
# Static files & SPA fallback
# ---------------------------------------------------------------------------
REACT_ROOT = WEB_ROOT / "react-dist"

def _static_file(root: Path, requested: str) -> Path | None:
    try:
        root_resolved = root.resolve()
        candidate = (root_resolved / requested).resolve()
        candidate.relative_to(root_resolved)
    except Exception:
        return None
    return candidate if candidate.is_file() else None

def _react_index_response() -> HTMLResponse:
    index = REACT_ROOT / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text(encoding="utf-8"))
    raise HTTPException(status_code=404, detail="react build not found")

def _react_asset_response(full_path: str):
    file_path = _static_file(REACT_ROOT, full_path)
    if file_path:
        return FileResponse(file_path)
    if full_path.startswith("assets/"):
        raise HTTPException(status_code=404, detail="asset not found")
    return _react_index_response()

if PUBLIC_API_REDACTION:
    app.mount(
        "/assets",
        StaticFiles(directory=str(REACT_ROOT / "assets"), check_dir=False),
        name="react-assets",
    )
else:
    app.mount("/static", StaticFiles(directory=str(WEB_ROOT)), name="static")

@app.get("/react")
@app.get("/react/{full_path:path}")
async def react_spa(full_path: str = ""):
    return _react_asset_response(full_path)

@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    if PUBLIC_API_REDACTION:
        if full_path in {"docs", "redoc", "openapi.json"}:
            raise HTTPException(status_code=404, detail="not found")
        if full_path.startswith(("static/", "js/", "css/")) or full_path in {
            "app.js",
            "index.html",
            "redesign.css",
            "server.py",
            "server_prod.py",
        }:
            raise HTTPException(status_code=404, detail="not found")
        return _react_asset_response(full_path)

    file_path = _static_file(WEB_ROOT, full_path)
    if file_path:
        return FileResponse(file_path)
    index = WEB_ROOT / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text(encoding="utf-8"))
    raise HTTPException(status_code=404, detail="not found")
