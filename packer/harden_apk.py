#!/usr/bin/env python3
"""Enko APK Hardening Pipeline — Core orchestrator.

Sections:
  1. Imports & Constants
  2. Utility Functions (run, hash, paths)
  3. Signing & Certificate
  4. Manifest Patching
  5. Protection Map Parsing
  6. Native Core Profile
  7. VMP / DEX Compilation
  8. Polymorphic Shell
  9. Payload Encryption
  10. Runtime Config
  11. Security Report
  12. Main Pipeline
  13. CLI Entry Point
"""
import argparse
import base64
import hashlib
import json
import os
import random
import re
import shlex
import shutil
import string
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import zlib
from pathlib import Path
from typing import Any

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ModuleNotFoundError as e:
    AES = None  # type: ignore[assignment]
    get_random_bytes = None  # type: ignore[assignment]
    _CRYPTO_IMPORT_ERROR = e
else:
    _CRYPTO_IMPORT_ERROR = None  # type: ignore[assignment]


PAYLOAD_MAGIC = b"Q7mP2t9Lx1cV8rK"
PAYLOAD_PACKAGE_MAGIC = b"VTX_PACK_CORE_B7XQ1"
PROXY_APP_CLASS = "com.enko.shell.ProxyApplication"
ACCESS_NETWORK_STATE = "android.permission.ACCESS_NETWORK_STATE"
NATIVE_LAYER_CFG_NAME = "libvtcfg.so"
NATIVE_LAYER_PAYLOAD_NAME = "libvtpl.so"
NATIVE_LAYER_VMP_NAME = "libvtvm.so"
NATIVE_LAYER_EXTRACT_NAME = "libvtex.so"
DEFAULT_VMP_TARGET_LIB = "libagpcore.so"
NATIVE_LAYER_SHELL_VMP_NAME = "libvtshvm.so"

# Shell DEX methods to protect with VMP when --vmp-shell-dex is enabled.
# These are the highest-value methods in the shell that attackers target.
SHELL_VMP_TARGETS: list[tuple[str, str, str | None]] = [
    ("Lcom/enko/shell/ProxyApplication;", "installPayload", None),
    ("Lcom/enko/shell/ProxyApplication;", "enforceRiskPolicy", None),
    ("Lcom/enko/shell/IntegrityGate;", "enforceIdentity", None),
    ("Lcom/enko/shell/IntegrityGate;", "verifyShellDexIntegrity", None),
    ("Lcom/enko/shell/IntegrityGate;", "verifyNativeLibsIntegrity", None),
    ("Lcom/enko/shell/IntegrityGate;", "enforceRollbackGuard", None),
    ("Lcom/enko/shell/SignatureVerifier;", "verifyCurrentSign", None),
    ("Lcom/enko/shell/JavaHookDetector;", "detect", None),
]
VMP_OBFUSCATION_PRESETS: dict[str, tuple[float, float, float]] = {
    "stable": (0.0, 0.0, 0.0),
    "light": (0.08, 0.02, 0.04),
    "medium": (0.18, 0.05, 0.08),
}
VMP_VM_TIERS: dict[str, dict[str, Any]] = {
    "compat": {
        "code": 0,
        "label": "compatibility VM",
        "dispatch": "compat-safe",
        "purpose": "prefer predictable runtime behavior for business-critical flows",
    },
    "light": {
        "code": 1,
        "label": "light VM",
        "dispatch": "threaded-default",
        "purpose": "default balance between compatibility and reverse-engineering friction",
    },
    "strong": {
        "code": 2,
        "label": "strong VM",
        "dispatch": "threaded-hardened",
        "purpose": "stronger handler/perturbation gates for security-critical methods",
    },
}
VMP_BYTECODE_FORMAT_CAPABILITIES: dict[str, Any] = {
    "blob_version": 4,
    "instruction_encoding": "fixed8",
    "instruction_width_bytes": 8,
    "field_layout": ["opcode:u8", "dst:u8", "src1:u8", "src2:u8", "imm:s32"],
    "field_layout_randomized": False,
    "variable_length_supported": False,
    "opcode_table_randomized": True,
    "semantic_alias_handlers": True,
    "semantic_alias_handler_variants": {
        "add-int": 10,
        "add-int/lit": 8,
        "sub-int": 3,
        "sub-int/lit": 3,
        "and-int": 2,
        "and-int/lit": 2,
        "or-int": 2,
        "or-int/lit": 2,
        "xor-int": 2,
        "xor-int/lit": 2,
    },
    "semantic_alias_implementation": "native-multi-shape-int-binop-v2",
    "semantic_alias_implementation_shapes": 17,
    "operand_scrambling": "method-lfsr",
    "branch_target_unit": "instruction-index",
    "try_catch_unit": "instruction-index",
    "vm_tier_partitioning": True,
    "vm_tiers": list(VMP_VM_TIERS),
    "vm_tier_strategy": "runtime-context-tier-v1",
    "planned_next_blob_version": 5,
    "status": "v4-compatible-fixed-width",
}
PAYLOAD_KEY_SEED = b"vtx_payload_key_v2x"

# Original shell package (slash-form and dot-form).
SHELL_PKG_SLASH = "com/enko/shell"      # 14 chars — length preserved during polymorphism
SHELL_PKG_DOT = "com.enko.shell"        # dot-form counterpart
INIT_PROVIDER_CLASS = "com.enko.shell.EnkoInitProvider"
SHELL_POLY_CLASS_NAMES = [
    "ApplicationReplacer",
    "DexProtector",
    "EnkoInitProvider",
    "EnkoInMemoryDexClassLoader",
    "IntegrityGate",
    "JavaHookDetector",
    "NativeBridge",
    "NativeRiskEvaluator",
    "NetworkRiskDetector",
    "NetworkRiskWatchdog",
    "PayloadCrypto",
    "PayloadParser",
    "ProxyApplication",
    "RuntimeConfig",
    "SignatureVerifier",
]
SHELL_POLY_METHOD_NAMES = [
    "buildApkEntryIndex",
    "enforceIdentity",
    "enforceRiskPolicy",
    "enforceRollbackGuard",
    "installPayload",
    "loadRuntimeConfig",
    "nativeAntiDumpInit",
    "nativeCommitNativeLibsDigest",
    "nativeCommitTrackedLibDigest",
    "nativeComputeSha256",
    "nativeD2cRegisterNatives",
    "nativeDecrypt",
    "nativeDecryptConfig",
    "nativeDecryptWithEmbeddedKey",
    "nativeDeobfuscateKey",
    "nativeDetectDumpTools",
    "nativeDetectRisk",
    "nativeEvaluateRisk",
    "nativeExtractBindDexBuffers",
    "nativeExtractLoad",
    "nativeExtractRestore",
    "nativeExtractRestoreClass",
    "nativeGetConfigIntegrityKey",
    "nativeMarkNoDump",
    "nativeOpenReadOnly",
    "nativeProtectDexRegion",
    "nativeShellVmpLoad",
    "nativeShellVmpRegisterNatives",
    "nativeVerifyApkIntegrity",
    "nativeVerifyShellDex",
    "nativeVmpLoad",
    "nativeVmpRegisterNatives",
    "nativeWipeMemory",
    "readBlobFromNativeLayer",
    "verifyCurrentSign",
    "verifyNativeLibsIntegrity",
    "verifyShellDexIntegrity",
]
SHELL_POLY_FIELD_NAMES = [
    "BUFFER_ADDRESS_FIELD",
    "CORRUPT_HEADER_BYTES",
    "KEY_MAX_BUILD_EPOCH",
    "KEY_MAX_BUILD_ID",
    "KEY_MAX_BUILD_VERSION",
    "ROLLBACK_PREF",
    "blockHitCount",
    "blockProxyVpn",
    "buildEpochSec",
    "buildId",
    "buildVersionCode",
    "commercialMode",
    "delayedKillScheduled",
    "degradedMode",
    "detectEmulator",
    "detectRoot",
    "dex2cEnabled",
    "expectedPackageName",
    "expectedSignSha256",
    "extractActive",
    "extractEnabled",
    "extractOnDemand",
    "libAppSha256",
    "libFlutterSha256",
    "nativeLibsSha256",
    "payloadCompression",
    "protectDexPages",
    "realApplication",
    "realApplicationClass",
    "riskPolicy",
    "riskProfile",
    "runtimeConfig",
    "sAppCreateDone",
    "sLoaded",
    "sRng",
    "shellDexSha256",
    "shellVmpEnabled",
    "vmpEnabled",
]

# Per-APK key slot markers (must match enko_key.c)
PER_APK_KEY_SLOT_HEAD = b"\xD3\x91\x6A\x2E\xB7\x4C\xF8\x15\x9A\x63\xC1\x7D\xE4\x22\x5B\x90"  # 16 bytes
PER_APK_KEY_SLOT_TAIL = b"\x8E\x47\xB2\x19\x5C\xD0\x73\xA6\xF1\x3D\x84\x2A\xC9\x6E\x11\xF5"  # 16 bytes

# Config encryption magic (must match obs_cfg_magic in enko_gcm.c)
CFG_ENC_MAGIC = b"R4nD8sW2kZ5yH0f"  # 15 bytes

# Must match MASK_PART_A..D in shell-app/app/src/main/cpp/enko_key.c
NATIVE_KEY_XOR_MASK = bytes([
    0xA3, 0x5C, 0x7E, 0x19, 0xB2, 0xD4, 0xF0, 0x68,
    0x3A, 0x91, 0xC5, 0xE7, 0x0B, 0x4D, 0x82, 0xF6,
    0x17, 0x8B, 0xE3, 0x5A, 0xC9, 0x04, 0x76, 0xDF,
    0x61, 0xAD, 0x38, 0xF2, 0x4E, 0x85, 0xB0, 0x2C,
])


class HardenError(Exception):
    pass


DEFAULT_CMD_TIMEOUT = 300  # seconds (5 min per external tool invocation)

_STEP_TOTAL = 5
_step_times: list[float] = []


def _log_step(n: int, label: str) -> None:
    """Print a prominent step banner and track elapsed time."""
    now = time.monotonic()
    if _step_times:
        prev = _step_times[-1]
        print(f"    └─ done in {now - prev:.1f}s")
    _step_times.append(now)
    bar = "━" * 50
    print(f"\n{bar}")
    print(f"  Step {n}/{_STEP_TOTAL}: {label}")
    print(bar)


HEARTBEAT_INTERVAL = 10  # seconds between "still running" messages
VERSION_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
RELEASE_MANIFEST_REQUIRED_KEYS = (
    "engine_version",
    "rules_version",
    "policy_version",
    "map_version",
    "config_schema_version",
)


def run(cmd: list[str], timeout: int = DEFAULT_CMD_TIMEOUT, label: str = "") -> None:
    tag = f" ({label})" if label else ""
    print(f"[cmd]{tag} {' '.join(cmd)}")
    t0 = time.monotonic()
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,          # line-buffered
    )
    assert proc.stdout is not None

    # Heartbeat thread: prints elapsed time periodically so the user knows
    # the process is still alive even when the subprocess produces no output.
    stop_event = threading.Event()
    last_output_time = time.monotonic()
    lock = threading.Lock()

    def heartbeat() -> None:
        while not stop_event.wait(HEARTBEAT_INTERVAL):
            with lock:
                silent = time.monotonic() - last_output_time
            elapsed = time.monotonic() - t0
            print(f"  ... still running ({elapsed:.0f}s, no output for {silent:.0f}s)")

    hb = threading.Thread(target=heartbeat, daemon=True)
    hb.start()

    captured: list[str] = []
    try:
        for line in proc.stdout:
            line = line.rstrip("\n")
            captured.append(line)
            with lock:
                last_output_time = time.monotonic()
            print(f"  | {line}")
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        elapsed = time.monotonic() - t0
        raise HardenError(
            f"command timed out after {elapsed:.0f}s: {' '.join(cmd)}\n"
            f"last output: {''.join(captured[-5:])}"
        )
    finally:
        stop_event.set()
        hb.join(timeout=2)
    elapsed = time.monotonic() - t0
    if proc.returncode != 0:
        raise HardenError(
            f"command failed (exit {proc.returncode}, {elapsed:.1f}s): {' '.join(cmd)}\n"
            + "\n".join(captured[-30:])
        )
    print(f"  [done in {elapsed:.1f}s]")


def ensure_file(path: Path, name: str) -> None:
    if not path.exists() or not path.is_file():
        raise HardenError(f"{name} not found: {path}")


def infer_gradle_mapping_path(apk_path: Path) -> Path | None:
    """
    Infer AGP mapping.txt path from a Gradle APK output path:
      .../build/outputs/apk/<variant>/<apk>.apk
      -> .../build/outputs/mapping/<variant>/mapping.txt
    """
    variant_dir = apk_path.parent
    apk_dir = variant_dir.parent
    outputs_dir = apk_dir.parent
    build_dir = outputs_dir.parent
    if (
        apk_dir.name.lower() != "apk"
        or outputs_dir.name.lower() != "outputs"
        or build_dir.name.lower() != "build"
    ):
        return None
    return build_dir / "outputs" / "mapping" / variant_dir.name / "mapping.txt"


def verify_release_obfuscation(apk_path: Path, label: str, *, allow_weak_release: bool) -> None:
    mapping_path = infer_gradle_mapping_path(apk_path)
    if mapping_path is None:
        if allow_weak_release:
            print(f"[!] {label}: cannot infer Gradle mapping path, skip obfuscation verification")
            return
        raise HardenError(
            f"{label}: cannot verify R8 obfuscation from apk path: {apk_path}. "
            "Use a Gradle release output path or pass --allow-weak-release."
        )

    if not mapping_path.exists() or not mapping_path.is_file():
        if allow_weak_release:
            print(f"[!] {label}: mapping not found ({mapping_path}), continue due --allow-weak-release")
            return
        raise HardenError(
            f"{label}: mapping file missing ({mapping_path}). "
            "Build release with -PenkoReleaseObfuscate=true or pass --allow-weak-release."
        )
    print(f"[*] {label}: obfuscation mapping verified: {mapping_path}")


def which_or_fail(binary: str) -> str:
    p = shutil.which(binary)
    if p is None:
        raise HardenError(f"binary not found in PATH: {binary}")
    return p


def normalize_sha256_hex(raw: str) -> str:
    h = (raw or "").strip().replace(":", "").replace("-", "")
    if not h:
        return ""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", h):
        raise HardenError("--sign-cert-sha256 must be 64 hex chars (colons allowed)")
    return h.upper()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    _hash_file_into(h, path)
    return h.hexdigest().upper()


def _hash_file_into(h: "hashlib._Hash", path: Path) -> None:
    """Stream file contents into a hashlib hash object."""
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)


def normalize_version_token(raw: str, key_name: str) -> str:
    value = (raw or "").strip()
    if not value or not VERSION_TOKEN_RE.fullmatch(value):
        raise HardenError(
            f"invalid {key_name} in --release-manifest: {value!r} "
            "(allowed: letters/digits/._-, max 64 chars)"
        )
    return value


def load_release_manifest(path: Path, protection_map_path: Path | None) -> dict[str, object]:
    ensure_file(path, "--release-manifest")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise HardenError(f"invalid JSON in --release-manifest: {path}") from e

    if not isinstance(payload, dict):
        raise HardenError("--release-manifest root must be a JSON object")

    out: dict[str, object] = {}
    for key in RELEASE_MANIFEST_REQUIRED_KEYS:
        out[key] = normalize_version_token(str(payload.get(key, "")), key)

    generated_at = payload.get("generated_at_utc")
    if isinstance(generated_at, str) and generated_at.strip():
        out["generated_at_utc"] = generated_at.strip()

    files = payload.get("files")
    if isinstance(files, dict):
        copied_files: dict[str, dict[str, str]] = {}
        for name, meta in files.items():
            if not isinstance(name, str) or not isinstance(meta, dict):
                continue
            entry_path = str(meta.get("path", "")).strip()
            entry_sha = str(meta.get("sha256", "")).strip().upper()
            if entry_path and re.fullmatch(r"[0-9A-F]{64}", entry_sha):
                copied_files[name] = {"path": entry_path, "sha256": entry_sha}
        if copied_files:
            out["files"] = copied_files

    files_val = out.get("files")
    if protection_map_path and isinstance(files_val, dict):
        pm_meta = files_val.get("protection_map")
        if isinstance(pm_meta, dict):
            expected = str(pm_meta.get("sha256", "")).strip().upper()
            if expected:
                actual = sha256_file(protection_map_path)
                if actual != expected:
                    raise HardenError(
                        "--release-manifest protection_map sha256 mismatch: "
                        f"expected {expected}, got {actual}"
                    )

    out["manifest_path"] = str(path)
    return out


def extract_sign_sha256_from_keystore(
    keystore: Path, ks_pass: str, key_alias: str, key_pass: str
) -> str:
    keytool = shutil.which("keytool")
    if keytool is None:
        raise HardenError(
            "keytool not found in PATH; provide --sign-cert-sha256 manually or install JDK keytool"
        )

    env = os.environ.copy()
    env["_ENKO_KS_PASS"] = ks_pass
    env["_ENKO_KEY_PASS"] = key_pass
    cmd = [
        keytool,
        "-exportcert",
        "-alias",
        key_alias,
        "-keystore",
        str(keystore),
        "-storepass:env",
        "_ENKO_KS_PASS",
        "-keypass:env",
        "_ENKO_KEY_PASS",
    ]
    print("[*] extracting signing cert from keystore via keytool")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    if result.returncode != 0:
        out = result.stdout.decode(errors="ignore")
        raise HardenError(f"failed to export cert from keystore via keytool:\n{out}")
    cert_der = result.stdout
    if not cert_der:
        raise HardenError("empty certificate bytes from keytool -exportcert")
    return hashlib.sha256(cert_der).hexdigest().upper()


def extract_sign_sha256_from_apk(apksigner: str, apk: Path) -> str:
    cmd = [apksigner, "verify", "--print-certs", str(apk)]
    print(f"[cmd] {' '.join(cmd)}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if result.returncode != 0:
        raise HardenError(f"failed to extract cert from apk: {apk}\n{result.stdout}")

    m = re.search(
        r"certificate SHA-256 digest:\s*([0-9A-Fa-f:\-]{64,95})",
        result.stdout,
        flags=re.IGNORECASE,
    )
    if not m:
        raise HardenError("cannot parse certificate SHA-256 digest from apksigner output")
    return normalize_sha256_hex(m.group(1))


def extract_shell_dex_from_apk(shell_apk: Path, out_dex: Path) -> Path:
    ensure_file(shell_apk, "shell apk")
    try:
        with zipfile.ZipFile(shell_apk, "r") as zf:
            dex_data = zf.read("classes.dex")
    except KeyError as e:
        raise HardenError(f"shell apk does not contain classes.dex: {shell_apk}") from e
    except zipfile.BadZipFile as e:
        raise HardenError(f"invalid shell apk zip: {shell_apk}") from e
    out_dex.write_bytes(dex_data)
    return out_dex


def extract_native_libs_from_apk(shell_apk: Path, decoded_dir: Path, target_abis: list[str] | None = None) -> int:
    """Copy native .so files from the shell APK into the decoded APK's lib/ directory.
    
    If *target_abis* is provided, only copy libs matching those ABIs.
    """
    count = 0
    try:
        with zipfile.ZipFile(shell_apk, "r") as zf:
            for entry in zf.namelist():
                if entry.startswith("lib/") and entry.endswith(".so"):
                    parts = entry.split("/")
                    if len(parts) >= 3 and target_abis:
                        abi = parts[1]
                        if abi not in target_abis:
                            continue
                    dest = decoded_dir / entry
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(zf.read(entry))
                    count += 1
    except Exception as e:
        print(f"[!] native lib extraction failed: {e}")
    return count


def parse_manifest_original_app(manifest_text: str) -> str | None:
    m = re.search(r"<application\b([^>]*)>", manifest_text, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        raise HardenError("cannot find <application> tag in AndroidManifest.xml")
    attrs = m.group(1)
    n = re.search(r'android:name\s*=\s*"([^"]+)"', attrs, flags=re.IGNORECASE)
    return n.group(1) if n else None


def patch_manifest_app(manifest_text: str, proxy_app: str) -> str:
    m = re.search(r"<application\b([^>]*)>", manifest_text, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        raise HardenError("cannot find <application> tag in AndroidManifest.xml")

    full_tag = m.group(0)
    attrs = m.group(1)
    if re.search(r'android:name\s*=\s*"[^"]+"', attrs, flags=re.IGNORECASE):
        patched_tag = re.sub(
            r'android:name\s*=\s*"[^"]+"',
            f'android:name="{proxy_app}"',
            full_tag,
            count=1,
            flags=re.IGNORECASE,
        )
    else:
        if full_tag.endswith("/>"):
            patched_tag = full_tag[:-2] + f' android:name="{proxy_app}" />'
        else:
            patched_tag = full_tag[:-1] + f' android:name="{proxy_app}">'

    return manifest_text.replace(full_tag, patched_tag, 1)


def patch_extract_native_libs(manifest_text: str) -> str:
    """Ensure extractNativeLibs is true so the system can handle our .dat blobs in lib/."""
    if re.search(r'android:extractNativeLibs\s*=\s*"true"', manifest_text, flags=re.IGNORECASE):
        return manifest_text
    m = re.search(r'android:extractNativeLibs\s*=\s*"[^"]*"', manifest_text, flags=re.IGNORECASE)
    if m:
        return manifest_text.replace(m.group(0), 'android:extractNativeLibs="true"', 1)
    # Attribute not present; inject it into the <application> tag.
    app_m = re.search(r'<application\b', manifest_text, flags=re.IGNORECASE)
    if app_m:
        return manifest_text[:app_m.end()] + ' android:extractNativeLibs="true"' + manifest_text[app_m.end():]
    return manifest_text


def patch_manifest_debuggable(manifest_text: str, enabled: bool = False) -> str:
    """Force the hardened output's android:debuggable flag."""
    value = "true" if enabled else "false"
    attr = f'android:debuggable="{value}"'
    m = re.search(r'android:debuggable\s*=\s*"[^"]*"', manifest_text, flags=re.IGNORECASE)
    if m:
        return manifest_text.replace(m.group(0), attr, 1)

    app_m = re.search(r'<application\b', manifest_text, flags=re.IGNORECASE)
    if app_m:
        return manifest_text[:app_m.end()] + f" {attr}" + manifest_text[app_m.end():]
    return manifest_text


def ensure_init_provider(
    manifest_text: str, package_name: str, provider_class: str = INIT_PROVIDER_CLASS,
) -> str:
    """Ensure the shell bootstrap ContentProvider is present in <application>."""
    provider_authority = f"{package_name}.enko_init"

    existing = re.search(
        r'<provider\b[^>]*android:name\s*=\s*"'
        + re.escape(provider_class)
        + r'"[^>]*>',
        manifest_text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if existing:
        provider_tag = existing.group(0)
        if re.search(
            r'android:authorities\s*=\s*"'
            + re.escape(provider_authority)
            + r'"',
            provider_tag,
            flags=re.IGNORECASE,
        ):
            return manifest_text

    app_m = re.search(r"<application\b[^>]*>", manifest_text, flags=re.IGNORECASE | re.DOTALL)
    if not app_m:
        raise HardenError("cannot find <application> to inject init provider")

    inject = (
        '\n'
        '        <provider\n'
        f'            android:name="{provider_class}"\n'
        f'            android:authorities="{provider_authority}"\n'
        '            android:exported="false"\n'
        '            android:initOrder="999" />'
    )
    return manifest_text[:app_m.end()] + inject + manifest_text[app_m.end():]


def ensure_uses_permission(manifest_text: str, permission_name: str) -> str:
    pat = (
        r'<uses-permission\b[^>]*android:name\s*=\s*"'
        + re.escape(permission_name)
        + r'"[^>]*/?>'
    )
    if re.search(pat, manifest_text, flags=re.IGNORECASE):
        return manifest_text

    app_idx = manifest_text.find("<application")
    if app_idx <= 0:
        raise HardenError("cannot find <application> to inject uses-permission")

    inject = f'    <uses-permission android:name="{permission_name}" />\n'
    return manifest_text[:app_idx] + inject + manifest_text[app_idx:]


def parse_protection_map(
    map_path: Path,
) -> tuple[
    list[tuple[str, str, str | None]],  # extract targets (level 1)
    list[tuple[str, str, str | None]],  # vmp targets (level 2)
    list[tuple[str, str, str | None]],  # dex2c targets (level 3)
]:
    """Parse a protection-map config file.

    Format: one entry per line as::

        Lcom/example/Foo;->methodName 3
        Lcom/example/Foo;->methodName(II)V 1
        Lcom/example/Util;->* 2
        # comment

    Levels: 0=none, 1=extract, 2=vmp, 3=dex2c.
    Returns three lists (extract, vmp, dex2c) in the same format
    as :func:`parse_vmp_dex_spec`.
    """
    ensure_file(map_path, "--protection-map")
    extract_targets: list[tuple[str, str, str | None]] = []
    vmp_targets: list[tuple[str, str, str | None]] = []
    dex2c_targets: list[tuple[str, str, str | None]] = []
    seen: dict[str, int] = {}  # key → level, for conflict detection

    for raw_line in map_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Expected: <method_spec> <level>
        parts = line.rsplit(None, 1)
        if len(parts) != 2:
            raise HardenError(f"invalid protection-map line (expected '<method> <level>'): {line!r}")
        spec_part, level_str = parts
        try:
            level = int(level_str)
        except ValueError:
            raise HardenError(f"invalid protection level (not an int): {line!r}")
        if level not in (0, 1, 2, 3):
            raise HardenError(f"protection level must be 0-3: {line!r}")
        if level == 0:
            continue  # no protection

        # Parse method spec (same grammar as VMP spec).
        m = re.match(r'^(L[^;]+;)->([^(\s]+)(?:(\(.*))?$', spec_part)
        if not m:
            raise HardenError(f"invalid method spec in protection-map: {spec_part!r}")
        class_desc = m.group(1)
        method_name = m.group(2)
        sig = m.group(3) if m.group(3) else None

        key = f"{class_desc}->{method_name}" + (sig or "")
        if key in seen:
            raise HardenError(
                f"conflicting protection-map: {key} has both level {seen[key]} and {level}"
            )
        seen[key] = level

        entry = (class_desc, method_name, sig)
        if level == 1:
            extract_targets.append(entry)
        elif level == 2:
            vmp_targets.append(entry)
        elif level == 3:
            dex2c_targets.append(entry)

    return extract_targets, vmp_targets, dex2c_targets


def parse_vmp_dex_spec(spec_path: Path) -> list[tuple[str, str, str | None]]:
    """Parse a VMP method spec file.

    Format: one method per line as ``Lcom/example/Foo;->methodName`` or
    ``Lcom/example/Foo;->methodName(II)V``.  Lines starting with ``#`` or
    blank lines are ignored.

    Returns list of (class_descriptor, method_name, signature_or_None).
    """
    ensure_file(spec_path, "--vmp-dex-methods spec")
    targets: list[tuple[str, str, str | None]] = []
    for raw_line in spec_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Expected: Lcom/example/Foo;->methodName  or  Lcom/example/Foo;->methodName(II)V
        m = re.match(r'^(L[^;]+;)->([^(\s]+)(?:(\(.*))?$', line)
        if not m:
            raise HardenError(f"invalid VMP method spec line: {line!r}")
        class_desc = m.group(1)
        method_name = m.group(2)
        sig = m.group(3) if m.group(3) else None
        targets.append((class_desc, method_name, sig))
    if not targets:
        raise HardenError(f"VMP method spec file is empty: {spec_path}")
    return targets


def dedupe_method_targets(
    targets: list[tuple[str, str, str | None]],
) -> list[tuple[str, str, str | None]]:
    seen: set[tuple[str, str, str | None]] = set()
    out: list[tuple[str, str, str | None]] = []
    for target in targets:
        if target in seen:
            continue
        seen.add(target)
        out.append(target)
    return out


def count_protectable_methods(dex_files: list[Path]) -> int:
    packer_dir = str(Path(__file__).resolve().parent)
    if packer_dir not in sys.path:
        sys.path.insert(0, packer_dir)

    from dex_parser import ACC_ABSTRACT, ACC_NATIVE, parse_dex

    total = 0
    for dex_path in dex_files:
        dex = parse_dex(dex_path.read_bytes())
        for cls in dex.class_defs:
            if cls.class_data is None:
                continue
            for method in cls.class_data.direct_methods + cls.class_data.virtual_methods:
                if method.code is None:
                    continue
                if method.access_flags & ACC_NATIVE:
                    continue
                if method.access_flags & ACC_ABSTRACT:
                    continue
                if dex.method_name(method.method_idx).startswith("<"):
                    continue
                total += 1
    return total


def list_matching_native_libs(decoded_apk_dir: Path, lib_name: str) -> list[Path]:
    lib_root = decoded_apk_dir / "lib"
    if not lib_root.exists():
        return []
    return sorted(path for path in lib_root.rglob(lib_name) if path.is_file())


def compute_native_lib_sha256_for_paths(paths: list[Path], *, label: str) -> str:
    if not paths:
        return ""
    h = hashlib.sha256()
    for so_file in sorted(paths):
        _hash_file_into(h, so_file)
    sha = h.hexdigest().upper()
    print(f"[*] {label} sha256: {sha} ({len(paths)} file(s))")
    return sha


def inspect_native_core_profile(decoded_apk_dir: Path) -> dict[str, Any]:
    libapp_paths = list_matching_native_libs(decoded_apk_dir, "libapp.so")
    libflutter_paths = list_matching_native_libs(decoded_apk_dir, "libflutter.so")
    return {
        "flutter_detected": bool(libapp_paths or libflutter_paths),
        "abis": sorted(
            {
                path.parent.name
                for path in libapp_paths + libflutter_paths
                if path.parent is not None
            }
        ),
        "libapp_paths": [str(path.relative_to(decoded_apk_dir)) for path in libapp_paths],
        "libflutter_paths": [str(path.relative_to(decoded_apk_dir)) for path in libflutter_paths],
        "libapp_sha256": compute_native_lib_sha256_for_paths(
            libapp_paths,
            label="flutter libapp.so",
        ) if libapp_paths else "",
        "libflutter_sha256": compute_native_lib_sha256_for_paths(
            libflutter_paths,
            label="flutter libflutter.so",
        ) if libflutter_paths else "",
        "hook_watch_targets": ["agpcore"]
        + (["libapp.so"] if libapp_paths else [])
        + (["libflutter.so"] if libflutter_paths else []),
    }


def run_vmp_dex_compilation(
    dex_files: list[Path],
    vmp_targets: list[tuple[str, str, str | None]],
    fail_open: bool,
    wipe_insns: bool = True,
    *,
    split_prob: float = 0.0,
    junk_ratio: float = 0.0,
    inline_junk_ratio: float = 0.0,
    obfuscation_report: dict[str, Any] | None = None,
) -> tuple[bytes | None, list[dict[str, Any]]]:
    """Compile target methods from DEX files into a single VMP blob and patch.

    Uses ``compile_methods_multi_dex`` so all DEX files share a single blob
    with globally contiguous method IDs.

    Returns ``(blob_bytes | None, method_info_list)``.
    """
    packer_dir = str(Path(__file__).resolve().parent)
    if packer_dir not in sys.path:
        sys.path.insert(0, packer_dir)

    from dex_parser import parse_dex
    from dex_writer import patch_methods_to_native
    from vmp_compiler import compile_methods_multi_dex

    requested_obfuscation = {
        "split_prob": float(split_prob),
        "junk_ratio": float(junk_ratio),
        "inline_junk_ratio": float(inline_junk_ratio),
    }
    if obfuscation_report is not None:
        obfuscation_report.update(
            {
                "requested": dict(requested_obfuscation),
                "effective": dict(requested_obfuscation),
                "downgraded": False,
                "downgrade_reason": "",
            }
        )

    # Parse all DEX files upfront.
    dex_objects = []
    for dex_path in dex_files:
        dex_objects.append(parse_dex(dex_path.read_bytes()))

    try:
        blob, compiled_per_dex, method_info = compile_methods_multi_dex(
            dex_objects,
            vmp_targets,
            split_prob=split_prob,
            junk_ratio=junk_ratio,
            inline_junk_ratio=inline_junk_ratio,
        )
    except Exception as exc:
        can_downgrade = any(value > 0.0 for value in requested_obfuscation.values())
        if can_downgrade:
            print(
                "[!] VMP DEX: obfuscated compile failed; "
                "retrying stable VMP obfuscation profile "
                f"(reason: {exc})"
            )
            try:
                blob, compiled_per_dex, method_info = compile_methods_multi_dex(
                    dex_objects,
                    vmp_targets,
                    split_prob=0.0,
                    junk_ratio=0.0,
                    inline_junk_ratio=0.0,
                )
                if obfuscation_report is not None:
                    obfuscation_report.update(
                        {
                            "effective": {
                                "split_prob": 0.0,
                                "junk_ratio": 0.0,
                                "inline_junk_ratio": 0.0,
                            },
                            "downgraded": True,
                            "downgrade_reason": str(exc),
                        }
                    )
                print("[*] VMP DEX: stable downgrade succeeded")
            except Exception as stable_exc:
                msg = (
                    "VMP DEX compilation failed after stable downgrade: "
                    f"initial={exc}; stable={stable_exc}"
                )
                if fail_open:
                    print(f"[!] {msg}; continue because --vmp-dex-fail-open is set")
                    return None, []
                raise HardenError(msg) from stable_exc
        else:
            msg = f"VMP DEX compilation failed: {exc}"
            if fail_open:
                print(f"[!] {msg}; continue because --vmp-dex-fail-open is set")
                return None, []
            raise HardenError(msg) from exc

    total_compiled = sum(len(v) for v in compiled_per_dex.values())
    if total_compiled == 0:
        print("[*] VMP DEX: no target methods found in any DEX file")
        return None, []

    # Patch each DEX that had compiled methods.
    for dex_idx, compiled_indices in compiled_per_dex.items():
        dex = dex_objects[dex_idx]
        dex_path = dex_files[dex_idx]
        patched = patch_methods_to_native(dex, compiled_indices, wipe_insns=wipe_insns)
        dex_path.write_bytes(patched)
        print(f"[*] VMP DEX: patched {dex_path.name} ({len(compiled_indices)} methods → native)")

    print(f"[*] VMP DEX: total {total_compiled} method(s) compiled, blob {len(blob)} bytes")
    return blob, method_info


# ── Polymorphic shell generation (C1) ─────────────────────────────────
#
# Each build randomizes the shell package name so that generic unpackers
# (FDex2, DexDump, Frida scripts that match `com.enko.shell.*`) break.
#
# Approach: same-length binary replacement in the DEX and SO files.
# `com/enko/shell` (14 chars) -> `com/en***/****` (14 chars).
# The `com.en...` prefix keeps the standalone package string in the same
# sorted DEX string_ids neighborhood as `com.enko.shell`.
# All offsets in the DEX remain valid because string lengths don't change.
# The checksum and SHA-1 signature in the DEX header are recomputed.

def _rand_lower_alpha(n: int) -> str:
    """Return a random lowercase alpha string of length *n*."""
    return "".join(random.choices(string.ascii_lowercase, k=n))


def _rand_java_tail(n: int) -> str:
    alphabet = string.ascii_letters
    return "".join(random.choices(alphabet, k=n))


def _rank_token(index: int, width: int = 2) -> str:
    chars: list[str] = []
    value = index
    for _ in range(width):
        chars.append(string.ascii_lowercase[value % 26])
        value //= 26
    return "".join(reversed(chars))


def _make_ranked_same_len_aliases(names: list[str], prefix_len: int = 3) -> dict[str, str]:
    """Generate same-length Java identifier aliases that keep DEX sort stable."""
    out: dict[str, str] = {}
    groups: dict[str, list[str]] = {}
    for name in names:
        if len(name) < 4:
            continue
        prefix = name[: min(prefix_len, max(1, len(name) - 3))]
        groups.setdefault(prefix, []).append(name)

    for prefix, group in groups.items():
        for idx, name in enumerate(sorted(group)):
            token = _rank_token(idx)
            keep = prefix + token
            if len(keep) >= len(name):
                alias = prefix + _rand_java_tail(len(name) - len(prefix))
            else:
                alias = keep + _rand_java_tail(len(name) - len(keep))
            if alias == name:
                alias = alias[:-1] + ("Z" if alias[-1] != "Z" else "Y")
            out[name] = alias
    return out


def generate_shell_symbol_aliases() -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    return (
        _make_ranked_same_len_aliases(SHELL_POLY_CLASS_NAMES, prefix_len=3),
        _make_ranked_same_len_aliases(SHELL_POLY_METHOD_NAMES, prefix_len=7),
        _make_ranked_same_len_aliases(SHELL_POLY_FIELD_NAMES, prefix_len=5),
    )


def generate_native_layer_name_aliases() -> dict[str, str]:
    originals = [
        NATIVE_LAYER_CFG_NAME,
        NATIVE_LAYER_EXTRACT_NAME,
        NATIVE_LAYER_PAYLOAD_NAME,
        NATIVE_LAYER_SHELL_VMP_NAME,
        NATIVE_LAYER_VMP_NAME,
    ]
    aliases: dict[str, str] = {}
    for idx, original in enumerate(originals):
        if not (original.startswith("lib") and original.endswith(".so")):
            aliases[original] = original
            continue
        middle_len = len(original) - len("lib") - len(".so")
        rank = string.ascii_lowercase[idx]
        if middle_len >= 2:
            middle = "v" + rank + _rand_lower_alpha(middle_len - 2)
        else:
            middle = _rand_lower_alpha(middle_len)
        alias = f"lib{middle}.so"
        assert len(alias) == len(original)
        aliases[original] = alias
    return aliases


def generate_polymorphic_package() -> str:
    """Generate a random package in slash-form with the same length as SHELL_PKG_SLASH (14 chars).

    Format: ``com/en<3-char>/<4-char>`` -> 3 + 1 + 5 + 1 + 4 = 14 chars.

    The original shell DEX contains the standalone string ``com.enko.shell`` in
    sorted string_ids between other detector package names.  Keeping the new
    package under ``com.en`` preserves that order while still randomizing the
    concrete shell namespace.
    """
    assert len(SHELL_PKG_SLASH) == 14
    seg1 = "en" + _rand_lower_alpha(3)
    seg2 = _rand_lower_alpha(4)
    pkg = f"com/{seg1}/{seg2}"
    assert len(pkg) == 14, f"generated package length {len(pkg)} != 14"
    return pkg


def _recompute_dex_header(data: bytearray) -> None:
    """Recompute DEX signature (SHA-1) and checksum (Adler-32) in-place."""
    import hashlib as _hl, zlib as _zl
    # SHA-1 covers bytes 32..end
    sig = _hl.sha1(data[32:]).digest()
    data[12:32] = sig
    # Adler-32 covers bytes 12..end
    cksum = _zl.adler32(bytes(data[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", data, 8, cksum)


def _assert_dex_string_ids_sorted(data: bytes | bytearray) -> None:
    """Validate the DEX string_ids order after same-length binary patching."""
    try:
        from dex_parser import parse_dex

        dex = parse_dex(bytes(data))
    except Exception as exc:
        raise HardenError(f"polymorphic shell produced an invalid DEX: {exc}") from exc

    for idx in range(len(dex.strings) - 1):
        left = dex.strings[idx]
        right = dex.strings[idx + 1]
        if left > right:
            raise HardenError(
                "polymorphic shell produced out-of-order DEX string_ids: "
                f"{idx}:{left!r} > {idx + 1}:{right!r}"
            )


def apply_polymorphic_shell(
    shell_dex_path: Path,
    decoded_dir: Path,
    new_pkg_slash: str,
) -> dict[str, Any]:
    """Replace *all* occurrences of the original shell package in the DEX and
    native .so files. Also randomize high-signal class/method names and native
    layer blob filenames.

    This is a **same-length binary replacement** so no offsets change.
    """
    old_slash = SHELL_PKG_SLASH.encode("utf-8")
    new_slash = new_pkg_slash.encode("utf-8")
    old_dot = SHELL_PKG_DOT.encode("utf-8")
    new_dot = new_pkg_slash.replace("/", ".").encode("utf-8")
    assert len(old_slash) == len(new_slash)
    assert len(old_dot) == len(new_dot)

    original_dex = shell_dex_path.read_bytes()

    def _build_replacements(
        class_aliases: dict[str, str],
        method_aliases: dict[str, str],
        field_aliases: dict[str, str],
        blob_aliases: dict[str, str],
    ) -> list[tuple[bytes, bytes]]:
        replacements: list[tuple[bytes, bytes]] = [(old_slash, new_slash), (old_dot, new_dot)]
        for alias_map, label in (
            (class_aliases, "class"),
            (method_aliases, "method"),
            (field_aliases, "field"),
            (blob_aliases, "blob"),
        ):
            for source, target in alias_map.items():
                if len(source) != len(target):
                    raise HardenError(f"invalid {label} alias length: {source}->{target}")
                replacements.append((source.encode("utf-8"), target.encode("utf-8")))
        return sorted(replacements, key=lambda item: len(item[0]), reverse=True)

    class_aliases: dict[str, str] = {}
    method_aliases: dict[str, str] = {}
    field_aliases: dict[str, str] = {}
    blob_aliases: dict[str, str] = {}
    replacements: list[tuple[bytes, bytes]] = []
    dex_data = bytearray(original_dex)
    for attempt in range(128):
        class_aliases, method_aliases, field_aliases = generate_shell_symbol_aliases()
        blob_aliases = generate_native_layer_name_aliases()
        replacements = _build_replacements(
            class_aliases,
            method_aliases,
            field_aliases,
            blob_aliases,
        )
        patched = original_dex
        for old, new in replacements:
            patched = patched.replace(old, new)
        dex_data = bytearray(patched)
        try:
            _assert_dex_string_ids_sorted(dex_data)
        except HardenError:
            if attempt == 127:
                raise
            continue
        break

    # ── 1. Patch shell DEX ──
    dex_count = sum(original_dex.count(old) for old, _ in replacements)
    _recompute_dex_header(dex_data)
    shell_dex_path.write_bytes(dex_data)

    # ── 2. Patch native .so files in decoded_dir/lib/*/*.so ──
    so_total = 0
    lib_dir = decoded_dir / "lib"
    if lib_dir.is_dir():
        for so_path in lib_dir.rglob("*.so"):
            so_data = so_path.read_bytes()
            patched = so_data
            for old, new in replacements:
                patched = patched.replace(old, new)
            if patched != so_data:
                so_path.write_bytes(patched)
                so_total += 1

    new_pkg_dot = new_pkg_slash.replace("/", ".")
    print(
        f"[*] polymorphic shell: {SHELL_PKG_DOT} → {new_pkg_dot}; "
        f"symbols={len(class_aliases) + len(method_aliases) + len(field_aliases)}, "
        f"blobs={len(blob_aliases)} "
        f"(DEX: {dex_count} refs, SO: {so_total} files)"
    )
    return {
        "package_dot": new_pkg_dot,
        "class_aliases": class_aliases,
        "method_aliases": method_aliases,
        "field_aliases": field_aliases,
        "blob_aliases": blob_aliases,
    }


def remap_class_name(original: str, new_pkg_dot: str) -> str:
    """Remap a fully-qualified class name from the original package to the new one.

    ``com.enko.shell.ProxyApplication`` → ``<new_pkg_dot>.ProxyApplication``
    """
    if original.startswith(SHELL_PKG_DOT + "."):
        return new_pkg_dot + original[len(SHELL_PKG_DOT):]
    return original


def remap_shell_class_name(
    original: str,
    new_pkg_dot: str,
    class_aliases: dict[str, str] | None,
) -> str:
    remapped = remap_class_name(original, new_pkg_dot)
    if not class_aliases:
        return remapped
    dot = remapped.rfind(".")
    if dot < 0:
        return class_aliases.get(remapped, remapped)
    simple = remapped[dot + 1:]
    return remapped[:dot + 1] + class_aliases.get(simple, simple)


def remap_shell_descriptor(
    descriptor: str,
    old_pkg_slash: str,
    new_pkg_slash: str,
    class_aliases: dict[str, str] | None,
) -> str:
    out = descriptor.replace(old_pkg_slash, new_pkg_slash, 1)
    if not class_aliases:
        return out
    for source, target in class_aliases.items():
        out = out.replace(f"/{source};", f"/{target};")
    return out


def collect_dex_files(decoded_apk_dir: Path) -> list[Path]:
    import re
    def _dex_sort_key(p: Path) -> tuple[int, str]:
        m = re.search(r'classes(\d*)\.dex$', p.name)
        return (int(m.group(1)) if m and m.group(1) else 0, p.name)
    dex_files = sorted(decoded_apk_dir.glob("classes*.dex"), key=_dex_sort_key)
    if not dex_files:
        raise HardenError("no classes*.dex found in decoded APK root")
    return dex_files


def package_dex_files(dex_files: list[Path]) -> bytes:
    out = bytearray()
    out.extend(PAYLOAD_PACKAGE_MAGIC)
    out.extend(struct.pack(">I", len(dex_files)))
    for dex_file in dex_files:
        name = dex_file.name.encode("utf-8")
        if len(name) > 0xFFFF:
            raise HardenError(f"dex filename too long: {dex_file.name}")
        out.extend(struct.pack(">H", len(name)))
        out.extend(name)

        data_len = dex_file.stat().st_size
        if data_len < 0 or data_len > 0xFFFFFFFF:
            raise HardenError(f"dex file size out of range: {dex_file.name}")
        out.extend(struct.pack(">I", int(data_len)))
        with dex_file.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                out.extend(chunk)
    return bytes(out)


def encrypt_payload(plain: bytes, key: bytes) -> bytes:
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plain)
    # Java JCE AES/GCM expects ciphertext||tag (tag at end).
    return PAYLOAD_MAGIC + nonce + ciphertext + tag


def _payload_envelope_next(state: int) -> int:
    state &= 0xFFFFFFFF
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= state >> 17
    state ^= (state << 5) & 0xFFFFFFFF
    return state & 0xFFFFFFFF


def wrap_payload_envelope(inner: bytes, metadata: dict[str, Any] | None = None) -> bytes:
    """Hide the stable AES-GCM payload magic behind a per-build byte envelope."""
    rng = random.SystemRandom()
    seed = rng.getrandbits(32) or 0x6D2B79F5
    inner_len = len(inner)
    if inner_len > 0xFFFFFFFF:
        raise HardenError("encrypted payload too large")
    padding_len = rng.randint(8, 95)
    out = bytearray()
    out.extend(struct.pack(">I", seed))
    out.extend(struct.pack(">I", inner_len ^ seed ^ 0xA35F9C21))
    state = seed ^ 0xC0DEC0DE
    for i, b in enumerate(inner):
        state = _payload_envelope_next(state)
        mask = ((state >> ((i & 3) * 8)) & 0xFF) ^ ((i * 0x5D + 0xA7) & 0xFF)
        out.append(b ^ mask)
    for _ in range(padding_len):
        state = _payload_envelope_next(state)
        out.append(rng.getrandbits(8) ^ (state & 0xFF))
    if metadata is not None:
        metadata.update(
            {
                "format": "seeded-xor-v2-trailing-padding",
                "inner_length": inner_len,
                "padding_length": padding_len,
                "total_length": len(out),
                "stable_magic_hidden": True,
            }
        )
    return bytes(out)


def encrypt_config(plain: bytes, key: bytes) -> bytes:
    """AES-GCM encrypt runtime config with config-specific magic."""
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plain)
    return CFG_ENC_MAGIC + nonce + ciphertext + tag


def derive_embedded_payload_key() -> bytes:
    """Derive AES-256 payload key from native compiled-in material."""
    return hashlib.sha256(PAYLOAD_KEY_SEED + NATIVE_KEY_XOR_MASK).digest()


def derive_cfg_encryption_key() -> bytes:
    """Derive AES-128 config encryption key (matches enko_derive_cfg_key)."""
    return hashlib.sha256(NATIVE_KEY_XOR_MASK).digest()[:16]


def select_payload_bytes(plain: bytes, mode: str) -> tuple[bytes, str]:
    m = (mode or "auto").strip().lower()
    if m not in ("auto", "zlib", "none"):
        raise HardenError("--payload-compress must be one of: auto, zlib, none")

    if m == "none":
        return plain, "NONE"

    zipped = zlib.compress(plain, level=9)
    if m == "zlib":
        return zipped, "ZLIB"

    # Auto mode: only use zlib if it saves enough bytes to justify inflate cost.
    if len(zipped) + 128 < len(plain):
        return zipped, "ZLIB"
    return plain, "NONE"


def normalize_app_name(raw_name: str | None, package_name: str) -> str | None:
    if not raw_name:
        return None
    n = raw_name.strip()
    if not n:
        return None
    if n.startswith("."):
        return package_name + n
    if "." not in n:
        return f"{package_name}.{n}"
    return n


def parse_package_name(manifest_text: str) -> str:
    m = re.search(r'<manifest\b[^>]*\bpackage\s*=\s*"([^"]+)"', manifest_text, flags=re.IGNORECASE)
    if not m:
        raise HardenError("cannot find package attribute in <manifest>")
    return m.group(1).strip()


def parse_manifest_version_code(manifest_text: str) -> int:
    m = re.search(
        r'<manifest\b[^>]*\bandroid:versionCode\s*=\s*"([^"]+)"',
        manifest_text,
        flags=re.IGNORECASE,
    )
    if not m:
        return 0
    raw = m.group(1).strip()
    if not raw:
        return 0
    try:
        if raw.lower().startswith("0x"):
            value = int(raw, 16)
        else:
            value = int(raw, 10)
    except ValueError:
        return 0
    return max(value, 0)


def infer_version_code_from_binary_manifest(apk_path: Path) -> int:
    """Read versionCode directly from the APK's binary AndroidManifest.xml.

    When apktool cannot resolve framework attribute references the decoded
    XML may contain placeholder values instead of the real versionCode.
    This function reads the *original* binary manifest inside the ZIP and
    parses the AXML chunk for the ``android:versionCode`` attribute
    (resource-id 0x0101021b) to obtain the correct integer value.
    """
    ANDROID_VERSION_CODE_ATTR = 0x0101021B
    RES_XML_RESOURCE_MAP_TYPE = 0x0180
    RES_XML_START_ELEMENT_TYPE = 0x0102
    try:
        import zipfile, struct
        with zipfile.ZipFile(str(apk_path), "r") as zf:
            data = zf.read("AndroidManifest.xml")
    except Exception:
        return 0
    if len(data) < 16:
        return 0

    # Pass 1: build resource-id map (string pool index → resource id)
    res_id_map: dict[int, int] = {}
    cur = 8  # skip AXML header (type + hdrSize + size)
    while cur + 8 <= len(data):
        ct, chs, cs = struct.unpack_from("<HHI", data, cur)
        if cs < 8 or cur + cs > len(data):
            break
        if ct == RES_XML_RESOURCE_MAP_TYPE:
            for i in range((cs - chs) // 4):
                off = cur + chs + i * 4
                if off + 4 <= len(data):
                    res_id_map[i] = struct.unpack_from("<I", data, off)[0]
        cur += cs

    # Pass 2: scan start-element chunks for versionCode attribute
    cur = 8
    while cur + 8 <= len(data):
        ct, chs, cs = struct.unpack_from("<HHI", data, cur)
        if cs < 8 or cur + cs > len(data):
            break
        if ct == RES_XML_START_ELEMENT_TYPE and cs >= 36:
            # ResXMLTree_attrExt starts at cur + 16 (after node header)
            if cur + 30 <= len(data):
                attr_start = struct.unpack_from("<H", data, cur + 24)[0]
                attr_size = struct.unpack_from("<H", data, cur + 26)[0]
                attr_count = struct.unpack_from("<H", data, cur + 28)[0]
                if attr_size >= 20 and attr_count > 0:
                    attr_base = cur + 16 + attr_start
                    for a in range(attr_count):
                        a_off = attr_base + a * attr_size
                        if a_off + 20 > len(data):
                            break
                        a_name = struct.unpack_from("<I", data, a_off + 4)[0]
                        mapped_rid = res_id_map.get(a_name, 0)
                        if mapped_rid == ANDROID_VERSION_CODE_ATTR:
                            tv_type: int = struct.unpack_from("<B", data, a_off + 15)[0]
                            tv_data: int = struct.unpack_from("<I", data, a_off + 16)[0]
                            if tv_type == 0x10 and tv_data > 0:
                                return tv_data
        cur += cs
    return 0


def infer_version_code_from_output_metadata(apk_path: Path) -> int:
    meta_path = apk_path.parent / "output-metadata.json"
    if not meta_path.exists() or not meta_path.is_file():
        return 0
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return 0

    elements = meta.get("elements")
    if isinstance(elements, list):
        for elem in elements:
            if not isinstance(elem, dict):
                continue
            output_name = str(elem.get("outputFile", "") or "").strip()
            if output_name and Path(output_name).name != apk_path.name:
                continue
            vc = elem.get("versionCode")
            if isinstance(vc, int):
                return max(vc, 0)
            if isinstance(vc, str) and vc.strip().isdigit():
                return max(int(vc.strip()), 0)
    return 0


def generate_build_id(
    package_name: str,
    version_code: int,
    build_epoch_sec: int,
    input_apk: Path,
) -> str:
    rand = get_random_bytes(8).hex()
    material = (
        f"{package_name}|{version_code}|{build_epoch_sec}|{input_apk.name}|{rand}"
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest().upper()[:24]

def get_native_layer_abi_dirs(decoded_apk_dir: Path) -> list[Path]:
    lib_root = decoded_apk_dir / "lib"
    abi_dirs: list[Path] = []
    if lib_root.exists():
        abi_dirs = sorted([p for p in lib_root.iterdir() if p.is_dir()])
    if not abi_dirs:
        # Fallback for cases where shell native libs are absent (e.g. --shell-dex only).
        fallback = lib_root / "armeabi-v7a"
        fallback.mkdir(parents=True, exist_ok=True)
        abi_dirs = [fallback]
    return abi_dirs


def write_native_layer_blob(decoded_apk_dir: Path, filename: str, data: bytes) -> list[Path]:
    out_paths: list[Path] = []
    for abi_dir in get_native_layer_abi_dirs(decoded_apk_dir):
        out_path = abi_dir / filename
        out_path.write_bytes(data)
        out_paths.append(out_path)
    return out_paths


def parse_vmp_target_libs(raw: str) -> list[str]:
    items = [(x or "").strip() for x in (raw or "").split(",")]
    libs = [x for x in items if x]
    if not libs:
        raise HardenError("--vmp-target-libs cannot be empty when VMP is enabled")
    for lib in libs:
        if "/" in lib or "\\" in lib:
            raise HardenError("--vmp-target-libs must contain filenames only (e.g. libagpcore.so)")
    return libs


def run_vmp_over_native_libs(
    decoded_apk_dir: Path,
    vmp_command_template: str,
    target_libs: list[str],
    fail_open: bool,
) -> None:
    lib_root = decoded_apk_dir / "lib"
    if not lib_root.exists():
        msg = "VMP requested but decoded APK has no lib/ directory"
        if fail_open:
            print(f"[!] {msg}; continue because --vmp-fail-open is set")
            return
        raise HardenError(msg)

    jobs: list[tuple[str, str, Path, Path]] = []
    for abi_dir in sorted([p for p in lib_root.iterdir() if p.is_dir()]):
        abi = abi_dir.name
        for lib in target_libs:
            in_path = abi_dir / lib
            if in_path.exists():
                out_path = abi_dir / f"{in_path.stem}.vmp{in_path.suffix}"
                jobs.append((abi, lib, in_path, out_path))

    if not jobs:
        msg = f"VMP requested but none of target libs were found: {target_libs}"
        if fail_open:
            print(f"[!] {msg}; continue because --vmp-fail-open is set")
            return
        raise HardenError(msg)

    for abi, lib, in_path, out_path in jobs:
        try:
            cmd = vmp_command_template.format(
                input=str(in_path),
                output=str(out_path),
                abi=abi,
                lib=lib,
            )
        except KeyError as e:
            raise HardenError(
                "invalid --vmp-command-template placeholder; "
                "supported: {input} {output} {abi} {lib}"
            ) from e

        print(f"[*] VMP process start: {abi}/{lib}")
        print(f"[cmd] {cmd}")
        vmp_t0 = time.monotonic()
        vmp_proc = subprocess.Popen(
            shlex.split(cmd) if os.name != "nt" else cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False,
            bufsize=1,
        )
        vmp_out: list[str] = []
        assert vmp_proc.stdout is not None
        for vline in vmp_proc.stdout:
            vline = vline.rstrip("\n")
            vmp_out.append(vline)
            print(f"  | {vline}")
        try:
            vmp_proc.wait(timeout=DEFAULT_CMD_TIMEOUT)
        except subprocess.TimeoutExpired:
            vmp_proc.kill()
            vmp_proc.wait(timeout=5)
        vmp_elapsed = time.monotonic() - vmp_t0
        if vmp_proc.returncode != 0:
            msg = (
                f"VMP command failed for {abi}/{lib} "
                f"(exit {vmp_proc.returncode}, {vmp_elapsed:.1f}s):\n"
                + "\n".join(vmp_out[-20:])
            )
            if fail_open:
                print(f"[!] {msg}\n[!] continue because --vmp-fail-open is set")
                continue
            raise HardenError(msg)
        print(f"  [VMP done in {vmp_elapsed:.1f}s]")

        if out_path.exists():
            shutil.move(str(out_path), str(in_path))
            print(f"[*] VMP output applied: {in_path}")
        elif in_path.exists():
            # Some tools patch in-place even when output is provided.
            print(f"[*] VMP completed (in-place output assumed): {in_path}")
        else:
            msg = f"VMP completed but neither output nor input file exists: {abi}/{lib}"
            if fail_open:
                print(f"[!] {msg}\n[!] continue because --vmp-fail-open is set")
                continue
            raise HardenError(msg)


def compute_native_libs_sha256(decoded_apk_dir: Path) -> str:
    """Compute SHA-256 of all .so files in lib/ directory (sorted by relative path).

    Must match the runtime verification in ProxyApplication.verifyNativeLibsIntegrity:
    iterate all lib/**/*.so entries sorted by path, feed bytes sequentially into SHA-256.
    """
    lib_root = decoded_apk_dir / "lib"
    if not lib_root.exists():
        return ""
    # Exclude the config blob — it contains nativeLibsSha256 itself,
    # so including it would create a circular dependency.
    cfg_name = NATIVE_LAYER_CFG_NAME
    so_files = sorted(
        f for f in lib_root.rglob("*.so") if f.name != cfg_name
    )
    if not so_files:
        return ""
    h = hashlib.sha256()
    for so_file in so_files:
        _hash_file_into(h, so_file)
    sha = h.hexdigest().upper()
    print(f"[*] native libs sha256: {sha} ({len(so_files)} .so file(s))")
    return sha


def configure_apktool_no_compress(decoded_dir: Path) -> None:
    """Modify apktool.yml to ensure native libs (.so) and data files (.dat) are not compressed."""
    apktool_yml = decoded_dir / "apktool.yml"
    if not apktool_yml.exists():
        print("[!] apktool.yml not found; native libs may be compressed")
        return

    try:
        content = apktool_yml.read_text(encoding="utf-8")
        lines = content.splitlines()

        in_do_not_compress = False
        new_lines: list[str] = []
        do_not_compress_found = False
        existing_extensions: set[str] = set()

        # Keep the original YAML indentation style for list items.
        # Examples:
        #   doNotCompress:\n- arsc
        #   doNotCompress:\n  - arsc
        item_indent = ""

        def add_missing_items() -> None:
            prefix = f"{item_indent}- "
            if "so" not in existing_extensions:
                new_lines.append(f"{prefix}so")
            if "dat" not in existing_extensions:
                new_lines.append(f"{prefix}dat")

        for line in lines:
            stripped = line.strip()

            if stripped.startswith("doNotCompress:"):
                in_do_not_compress = True
                do_not_compress_found = True
                new_lines.append(line)
                continue

            if in_do_not_compress:
                if stripped.startswith("-"):
                    # Capture the file's existing indentation once we see the first item.
                    if not existing_extensions:
                        item_indent = line[: len(line) - len(line.lstrip())]
                    ext = stripped.lstrip("- ").strip().lower()
                    existing_extensions.add(ext)
                    new_lines.append(line)
                    continue

                if stripped and not stripped.startswith("#"):
                    # End of doNotCompress section.
                    in_do_not_compress = False
                    add_missing_items()
                    new_lines.append(line)
                    continue

                new_lines.append(line)
                continue

            new_lines.append(line)

        # If we were still in doNotCompress at end of file.
        if in_do_not_compress:
            add_missing_items()

        # If doNotCompress section was not found, add it.
        if not do_not_compress_found:
            new_lines.append("doNotCompress:")
            new_lines.append("- so")
            new_lines.append("- dat")

        apktool_yml.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        print("[*] apktool.yml updated to not compress .so and .dat files")
    except Exception as e:
        print(f"[!] failed to modify apktool.yml: {e}")


def patch_per_apk_key_in_so(decoded_apk_dir: Path, payload_key: bytes) -> int:
    """Binary-patch PAYLOAD_KEY_SLOT in every libagpcore.so.

    Generates random per-APK slot markers so no two hardened APKs share
    the same marker bytes.  Patches both ENKO_MARKER_STORE (marker
    definition) and ENKO_PERAPK_KEY_BLOB (the actual key slot).
    """
    lib_root = decoded_apk_dir / "lib"
    if not lib_root.exists():
        return 0

    masked_key = bytes(k ^ m for k, m in zip(payload_key, NATIVE_KEY_XOR_MASK))
    key_check = hashlib.sha256(payload_key).digest()

    # Anchor magic for locating ENKO_MARKER_STORE (must match enko_key.c)
    MARKER_STORE_ANCHOR = b"\xE7\x3A\x91\x5C\xD2\x8F\x46\xB0"

    patched_count = 0
    for abi_dir in sorted(p for p in lib_root.iterdir() if p.is_dir()):
        so_path = abi_dir / "libagpcore.so"
        if not so_path.exists():
            continue

        data = bytearray(so_path.read_bytes())

        # ── Generate random per-APK markers ──
        rng = random.SystemRandom()
        per_apk_head = bytes(rng.getrandbits(8) for _ in range(16))
        per_apk_tail = bytes(rng.getrandbits(8) for _ in range(16))

        # ── Patch ENKO_MARKER_STORE with random markers ──
        store_off = data.find(MARKER_STORE_ANCHOR)
        if store_off < 0:
            print(f"[!] per-apk marker store not found in {so_path.relative_to(decoded_apk_dir)}")
            continue
        head_field_off = store_off + len(MARKER_STORE_ANCHOR)
        tail_field_off = head_field_off + 16
        data[head_field_off:head_field_off + 16] = per_apk_head
        data[tail_field_off:tail_field_off + 16] = per_apk_tail

        # ── Patch ENKO_PERAPK_KEY_BLOB ──
        # Search for the blob using the compile-time head marker.
        head_offset = -1
        start = 0
        while True:
            i = data.find(PER_APK_KEY_SLOT_HEAD, start)
            if i < 0:
                break
            check_off = i + len(PER_APK_KEY_SLOT_HEAD) + 32
            tail_off = check_off + 32
            tail_actual = bytes(data[tail_off:tail_off + len(PER_APK_KEY_SLOT_TAIL)])
            if tail_actual == PER_APK_KEY_SLOT_TAIL:
                head_offset = i
                break
            start = i + 1

        if head_offset < 0:
            print(f"[!] per-apk key blob not found in {so_path.relative_to(decoded_apk_dir)}")
            continue

        slot_offset = head_offset + len(PER_APK_KEY_SLOT_HEAD)
        check_offset = slot_offset + 32

        # Overwrite compile-time markers with per-APK random values
        data[head_offset:head_offset + 16] = per_apk_head
        data[slot_offset:slot_offset + 32] = masked_key
        data[check_offset:check_offset + 32] = key_check
        data[tail_off:tail_off + 16] = per_apk_tail

        so_path.write_bytes(bytes(data))
        patched_count += 1
        print(f"[*] per-apk key patched (random markers): {so_path.relative_to(decoded_apk_dir)}")

    return patched_count


def write_runtime_config(
    decoded_apk_dir: Path,
    real_app_class: str | None,
    payload_compression: str,
    expected_package_name: str,
    sign_cert_sha256: str,
    risk_policy: str,
    risk_profile: str,
    block_proxy_vpn: bool,
    detect_root: bool = True,
    detect_emulator: bool = True,
    protect_dex_pages: bool = True,
    vmp_dex_enabled: bool = False,
    vmp_vm_tier: str = "light",
    extract_enabled: bool = False,
    extract_on_demand: bool = False,
    dex2c_enabled: bool = False,
    shell_vmp_enabled: bool = False,
    commercial_mode: bool = False,
    shell_dex_sha256: str = "",
    native_libs_sha256: str = "",
    libapp_sha256: str = "",
    libflutter_sha256: str = "",
    build_id: str = "",
    build_epoch_sec: int = 0,
    build_version_code: int = 0,
    native_cfg_name: str = NATIVE_LAYER_CFG_NAME,
) -> list[Path]:

    runtime_cfg = {
        "realApplicationClass": real_app_class or "",
        "payloadCompression": payload_compression.upper(),
        "expectedPackageName": expected_package_name,
        "expectedSignSha256": sign_cert_sha256,
        "riskPolicy": risk_policy,
        "riskProfile": risk_profile,
        "blockProxyVpn": "1" if block_proxy_vpn else "0",
        "detectRoot": "1" if detect_root else "0",
        "detectEmulator": "1" if detect_emulator else "0",
        "protectDexPages": "1" if protect_dex_pages else "0",
        "vmpEnabled": "1" if vmp_dex_enabled else "0",
        "vmpVmTier": vmp_vm_tier,
        "extractEnabled": "1" if extract_enabled else "0",
        "extractOnDemand": "1" if extract_on_demand else "0",
        "dex2cEnabled": "1" if dex2c_enabled else "0",
        "shellVmpEnabled": "1" if shell_vmp_enabled else "0",
        "commercialMode": "1" if commercial_mode else "0",
        "shellDexSha256": shell_dex_sha256,
        "nativeLibsSha256": native_libs_sha256,
        "libAppSha256": libapp_sha256,
        "libFlutterSha256": libflutter_sha256,
        "buildId": (build_id or "").upper(),
        "buildEpochSec": str(int(build_epoch_sec)) if build_epoch_sec > 0 else "0",
        "buildVersionCode": str(int(build_version_code)) if build_version_code > 0 else "0",
    }
    lines = []
    for k, v in runtime_cfg.items():
        lines.append(f"{k}={base64.b64encode(v.encode('utf-8')).decode('ascii')}")
    config_body = "\n".join(lines) + "\n"

    # Encrypt the entire config with AES-GCM (replaces the old HMAC scheme).
    cfg_key = derive_cfg_encryption_key()
    encrypted_cfg = encrypt_config(config_body.encode("utf-8"), cfg_key)
    return write_native_layer_blob(
        decoded_apk_dir,
        native_cfg_name,
        encrypted_cfg,
    )


def read_runtime_config_example() -> str:
    return (
        "runtime config keys (stored encrypted in libvtcfg.so):\n"
        "realApplicationClass=<base64 utf8>\n"
        "payloadCompression=<base64 utf8>\n"
        "expectedPackageName=<base64 utf8>\n"
        "expectedSignSha256=<base64 utf8>\n"
        "riskPolicy=<base64 utf8>\n"
        "riskProfile=<base64 utf8>\n"
        "blockProxyVpn=<base64 utf8>\n"
        "detectRoot=<base64 utf8>\n"
        "detectEmulator=<base64 utf8>\n"
        "protectDexPages=<base64 utf8>\n"
        "vmpEnabled=<base64 utf8>\n"
        "vmpVmTier=<base64 utf8>\n"
        "extractEnabled=<base64 utf8>\n"
        "extractOnDemand=<base64 utf8>\n"
        "dex2cEnabled=<base64 utf8>\n"
        "shellVmpEnabled=<base64 utf8>\n"
        "commercialMode=<base64 utf8>\n"
        "shellDexSha256=<base64 utf8>\n"
        "nativeLibsSha256=<base64 utf8>\n"
        "libAppSha256=<base64 utf8>\n"
        "libFlutterSha256=<base64 utf8>\n"
        "buildId=<base64 utf8>\n"
        "buildEpochSec=<base64 utf8>\n"
        "buildVersionCode=<base64 utf8>\n"
    )


def build_security_report(
    args: argparse.Namespace,
    *,
    signing_enabled: bool,
    sign_cert_sha256: str,
    extract_enabled: bool,
    vmp_dex_enabled: bool,
    dex2c_enabled: bool,
    extract_compiled_count: int,
    vmp_compiled_count: int,
    d2c_compiled_count: int,
    extract_requested_count: int,
    vmp_requested_count: int,
    d2c_requested_count: int,
    protectable_method_count: int,
    flutter_mode: bool,
    native_core_profile: dict[str, Any],
) -> dict[str, Any]:
    requested_total = extract_requested_count + vmp_requested_count + d2c_requested_count
    compiled_total = extract_compiled_count + vmp_compiled_count + d2c_compiled_count
    enabled_phase_count = sum(
        1 for enabled in (extract_enabled, vmp_dex_enabled, dex2c_enabled) if enabled
    )
    compiled_phase_count = sum(
        1
        for count in (extract_compiled_count, vmp_compiled_count, d2c_compiled_count)
        if count > 0
    )
    request_hit_ratio = (
        min(1.0, compiled_total / requested_total) if requested_total > 0 else 0.0
    )
    protectable_coverage_ratio = (
        compiled_total / protectable_method_count if protectable_method_count > 0 else 0.0
    )
    density_ratio = min(1.0, protectable_coverage_ratio / 0.05) if compiled_total > 0 else 0.0
    phase_ratio = (
        compiled_phase_count / enabled_phase_count if enabled_phase_count > 0 else 0.0
    )
    method_coverage_ratio = min(
        1.0,
        (0.35 * request_hit_ratio) + (0.45 * density_ratio) + (0.20 * phase_ratio),
    )
    method_coverage_points = int(round(5 * method_coverage_ratio))

    if protectable_coverage_ratio >= 0.05:
        coverage_grade = "A"
    elif protectable_coverage_ratio >= 0.03:
        coverage_grade = "B"
    elif protectable_coverage_ratio >= 0.015:
        coverage_grade = "C"
    elif compiled_total > 0:
        coverage_grade = "D"
    else:
        coverage_grade = "E"

    release_signing_ready = bool(signing_enabled or sign_cert_sha256)
    signing_mode = (
        "in-pipeline"
        if signing_enabled
        else ("external-original-certificate" if sign_cert_sha256 else "missing")
    )
    controls = [
        {
            "name": "signed-output",
            "weight": 20,
            "points": 20 if release_signing_ready else 0,
            "enabled": release_signing_ready,
            "mode": signing_mode,
            "deferred": bool(not signing_enabled and sign_cert_sha256),
        },
        {
            "name": "runtime-signature-pin",
            "weight": 15,
            "points": 15 if sign_cert_sha256 else 0,
            "enabled": bool(sign_cert_sha256),
        },
        {
            "name": "per-apk-payload-key",
            "weight": 15,
            "points": 15 if args.per_apk_key else 0,
            "enabled": bool(args.per_apk_key),
        },
        {
            "name": "risk-policy-block",
            "weight": 10,
            "points": 10 if args.risk_policy == "block" else (7 if args.risk_policy == "degrade" else (4 if args.risk_policy == "warn" else 0)),
            "enabled": args.risk_policy in ("block", "degrade", "warn"),
        },
        {
            "name": "risk-profile-strict",
            "weight": 10,
            "points": 10 if args.risk_profile == "strict" else 0,
            "enabled": args.risk_profile == "strict",
        },
        {
            "name": "block-proxy-vpn",
            "weight": 5,
            "points": 5 if args.block_proxy_vpn else 0,
            "enabled": bool(args.block_proxy_vpn),
        },
        {
            "name": "emulator-check-enabled",
            "weight": 5,
            "points": 5 if args.detect_emulator else 0,
            "enabled": bool(args.detect_emulator),
        },
        {
            "name": "no-fail-open",
            "weight": 10,
            "points": 10
            if not (
                args.vmp_fail_open
                or args.vmp_dex_fail_open
                or args.extract_fail_open
                or args.dex2c_fail_open
            )
            else 0,
            "enabled": not (
                args.vmp_fail_open
                or args.vmp_dex_fail_open
                or args.extract_fail_open
                or args.dex2c_fail_open
            ),
        },
        {
            "name": "zipalign-enabled",
            "weight": 5,
            "points": 5 if not args.skip_zipalign else 0,
            "enabled": not args.skip_zipalign,
        },
        {
            "name": "method-protection-coverage",
            "weight": 5,
            "points": method_coverage_points,
            "enabled": compiled_total > 0,
            "requested_total": requested_total,
            "compiled_total": compiled_total,
            "coverage_grade": coverage_grade,
            "role": "secondary" if flutter_mode else "primary",
        },
        {
            "name": "commercial-mode",
            "weight": 5,
            "points": 5 if args.commercial_mode else 0,
            "enabled": bool(args.commercial_mode),
        },
    ]
    if flutter_mode:
        libapp_present = bool(native_core_profile.get("libapp_paths"))
        libapp_pinned = bool(native_core_profile.get("libapp_sha256"))
        libflutter_present = bool(native_core_profile.get("libflutter_paths"))
        libflutter_pinned = bool(native_core_profile.get("libflutter_sha256"))
        core_present = libapp_present or libflutter_present
        controls.append(
            {
                "name": "flutter-native-core-integrity",
                "weight": 5,
                "points": 5
                if core_present
                and (not libapp_present or libapp_pinned)
                and (not libflutter_present or libflutter_pinned)
                else 0,
                "enabled": core_present,
                "libapp_present": libapp_present,
                "libapp_pinned": libapp_pinned,
                "libflutter_present": libflutter_present,
                "libflutter_pinned": libflutter_pinned,
            }
        )

    score = sum(int(control["points"]) for control in controls)
    max_score = sum(int(control["weight"]) for control in controls)
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    else:
        grade = "D"

    recommendations: list[str] = []
    for control in controls:
        if int(control["points"]) >= int(control["weight"]):
            continue
        if control["name"] == "method-protection-coverage":
            if compiled_total == 0:
                recommendations.append("method-protection-missing")
            else:
                recommendations.append("increase-method-protection-coverage")
        elif control["name"] == "flutter-native-core-integrity":
            recommendations.append("enable-flutter-native-core-integrity")
        else:
            recommendations.append(str(control["name"]))
    dex2c_ollvm_probe = dict(getattr(args, "dex2c_ollvm_probe", {}) or {})
    dex2c_ollvm_build = dict(getattr(args, "dex2c_ollvm_build_report", {}) or {})
    dex2c_ollvm_protected_libraries = list(
        dex2c_ollvm_build.get("ollvm_protected_libraries", []) or []
    )
    dex2c_ollvm_fallback_libraries = list(
        dex2c_ollvm_build.get("fallback_libraries", []) or []
    )
    vmp_obfuscation_report = dict(getattr(args, "vmp_dex_obfuscation_report", {}) or {})
    vmp_obfuscation_effective = dict(vmp_obfuscation_report.get("effective", {}) or {})
    return {
        "score": score,
        "max_score": max_score,
        "grade": grade,
        "controls": controls,
        "recommendations": recommendations,
        "method_protection": {
            "requested": {
                "extract": extract_requested_count,
                "vmp_dex": vmp_requested_count,
                "dex2c": d2c_requested_count,
            },
            "compiled": {
                "extract": extract_compiled_count,
                "vmp_dex": vmp_compiled_count,
                "dex2c": d2c_compiled_count,
            },
            "requested_total": requested_total,
            "compiled_total": compiled_total,
            "enabled_phases": enabled_phase_count,
            "compiled_phases": compiled_phase_count,
            "request_hit_ratio": round(request_hit_ratio, 4),
            "protectable_methods_total": protectable_method_count,
            "protectable_coverage_ratio": round(protectable_coverage_ratio, 4),
            "coverage_target_ratio": 0.05,
            "coverage_grade": coverage_grade,
            "role": "secondary" if flutter_mode else "primary",
            "score_ratio": round(method_coverage_ratio, 4),
            "score_points": method_coverage_points,
            "auto_protect_profile": str(getattr(args, "auto_protect_profile", "balanced")),
            "vmp_obfuscation": {
                "string_pool_encrypted": True,
                "string_pool_format_version": 4,
                "string_pool_decryption_mode": "load-time-per-vmp-context",
                "identifier_plaintext_audit": True,
                "split_prob": round(float(args.vmp_dex_split_prob), 4),
                "junk_ratio": round(float(args.vmp_dex_junk_ratio), 4),
                "inline_junk_ratio": round(float(args.vmp_dex_inline_junk_ratio), 4),
                "effective_split_prob": round(
                    float(vmp_obfuscation_effective.get("split_prob", args.vmp_dex_split_prob)),
                    4,
                ),
                "effective_junk_ratio": round(
                    float(vmp_obfuscation_effective.get("junk_ratio", args.vmp_dex_junk_ratio)),
                    4,
                ),
                "effective_inline_junk_ratio": round(
                    float(
                        vmp_obfuscation_effective.get(
                            "inline_junk_ratio",
                            args.vmp_dex_inline_junk_ratio,
                        )
                    ),
                    4,
                ),
                "downgraded": bool(vmp_obfuscation_report.get("downgraded", False)),
                "downgrade_reason": str(vmp_obfuscation_report.get("downgrade_reason", "")),
                "mode": str(getattr(args, "vmp_dex_obfuscation_mode", "custom")),
                "applies_to": ["payload", "shell"] if getattr(args, "vmp_shell_dex", False) else ["payload"],
            },
            "vmp_interpreter_core": {
                "partitioning_enabled": True,
                "available_tiers": [
                    {
                        "name": name,
                        "code": int(meta["code"]),
                        "label": str(meta["label"]),
                        "dispatch": str(meta["dispatch"]),
                        "purpose": str(meta["purpose"]),
                    }
                    for name, meta in VMP_VM_TIERS.items()
                ],
                "requested_tier": str(getattr(args, "vmp_vm_tier_requested", getattr(args, "vmp_vm_tier", "auto"))),
                "effective_tier": str(getattr(args, "vmp_vm_tier_effective", "light")),
                "tier_code": int(getattr(args, "vmp_vm_tier_code", 1)),
                "runtime_config_key": "vmpVmTier",
                "payload_tier": str(getattr(args, "vmp_vm_tier_effective", "light")),
                "shell_tier": str(getattr(args, "vmp_vm_tier_effective", "light"))
                if getattr(args, "vmp_shell_dex", False)
                else "disabled",
                "method_partition_strategy": "build-level-safe-tier-v1",
                "native_context_tier_state": True,
                "bytecode_semantics_changed": False,
            },
            "vmp_bytecode_format": dict(VMP_BYTECODE_FORMAT_CAPABILITIES),
            "dex2c_native_obfuscation": {
                "target_library": "libagpjnix.so",
                "ollvm_enabled": bool(getattr(args, "dex2c_ollvm", True)),
                "ollvm_required": bool(getattr(args, "dex2c_ollvm_required", False)),
                "ollvm_clang": str(getattr(args, "dex2c_ollvm_clang", "")),
                "ollvm_available": bool(dex2c_ollvm_probe.get("available", False)),
                "ollvm_version": str(dex2c_ollvm_probe.get("version", "")),
                "ollvm_effective": bool(dex2c_ollvm_protected_libraries),
                "ollvm_protected_libraries": dex2c_ollvm_protected_libraries,
                "ollvm_protected_abis": list(
                    dex2c_ollvm_build.get("ollvm_protected_abis", []) or []
                ),
                "fallback_libraries": dex2c_ollvm_fallback_libraries,
                "fallback_abis": list(dex2c_ollvm_build.get("fallback_abis", []) or []),
                "fallback_used": bool(dex2c_ollvm_build.get("fallback_used", False)),
                "per_abi": list(dex2c_ollvm_build.get("per_abi", []) or []),
                "preflight_status": str(
                    dex2c_ollvm_probe.get(
                        "preflight_status",
                        "not-run" if dex2c_enabled else "not-needed",
                    )
                ),
                "preflight_reason": str(dex2c_ollvm_probe.get("reason", "")),
                "passes": [
                    "cffobf",
                    "subobf",
                    "bcfobf",
                    "splitobf",
                    "strcry",
                ],
            },
        },
        "target_runtime": {
            "mode": "flutter" if flutter_mode else "standard",
            "flutter_detected": bool(native_core_profile.get("flutter_detected")),
            "abis": list(native_core_profile.get("abis", [])),
            "runtime_protections": {
                "protect_dex_pages": bool(getattr(args, "protect_dex_pages", True)),
                "extract_on_demand": bool(getattr(args, "extract_on_demand", False)),
                "detect_emulator": bool(getattr(args, "detect_emulator", True)),
                "detect_root": bool(getattr(args, "detect_root", True)),
                "dex_page_protection_decoupled": True,
            },
            "native_core": {
                "libapp": {
                    "present": bool(native_core_profile.get("libapp_paths")),
                    "path_count": len(list(native_core_profile.get("libapp_paths", []))),
                    "integrity_pinned": bool(native_core_profile.get("libapp_sha256")),
                    "paths": list(native_core_profile.get("libapp_paths", [])),
                },
                "libflutter": {
                    "present": bool(native_core_profile.get("libflutter_paths")),
                    "path_count": len(list(native_core_profile.get("libflutter_paths", []))),
                    "integrity_pinned": bool(native_core_profile.get("libflutter_sha256")),
                    "paths": list(native_core_profile.get("libflutter_paths", [])),
                },
                "hook_watch_targets": list(
                    native_core_profile.get("hook_watch_targets", ["agpcore"])
                ),
            },
        },
        "compiled": {
            "extract": extract_compiled_count,
            "vmp_dex": vmp_compiled_count,
            "dex2c": d2c_compiled_count,
        },
    }


def write_security_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")


def probe_ollvm_clang(
    clang_path: str,
    *,
    requested: bool = True,
    required: bool = False,
    timeout_sec: float = 8.0,
) -> dict[str, Any]:
    """Probe the configured Hikari/OLLVM clang before a long DEX2C build."""
    report: dict[str, Any] = {
        "requested": bool(requested),
        "required": bool(required),
        "path": str(clang_path or ""),
        "available": False,
        "version": "",
        "preflight_status": "disabled",
        "reason": "",
    }
    if not requested:
        return report

    raw_path = str(clang_path or "").strip()
    if not raw_path:
        report["preflight_status"] = "missing-path"
        report["reason"] = "--dex2c-ollvm-clang is empty"
        if required:
            raise HardenError(report["reason"])
        return report

    path = Path(raw_path).expanduser()
    report["path"] = str(path)
    if not path.exists() or not path.is_file():
        report["preflight_status"] = "missing"
        report["reason"] = f"Hikari/OLLVM clang not found: {path}"
        if required:
            raise HardenError(str(report["reason"]))
        return report

    try:
        result = subprocess.run(
            [str(path), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_sec,
        )
    except OSError as exc:
        report["preflight_status"] = "exec-failed"
        report["reason"] = f"failed to execute Hikari/OLLVM clang: {exc}"
        if required:
            raise HardenError(str(report["reason"])) from exc
        return report
    except subprocess.TimeoutExpired as exc:
        report["preflight_status"] = "timeout"
        report["reason"] = f"Hikari/OLLVM clang --version timed out after {timeout_sec:.0f}s"
        if required:
            raise HardenError(str(report["reason"])) from exc
        return report

    output = (result.stdout or "").strip()
    version_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
    report["version"] = version_line
    if result.returncode != 0:
        report["preflight_status"] = "version-failed"
        report["reason"] = (
            f"Hikari/OLLVM clang --version failed with exit {result.returncode}: "
            f"{version_line or '<no output>'}"
        )
        if required:
            raise HardenError(str(report["reason"]))
        return report

    report["available"] = True
    report["preflight_status"] = "available"
    return report


def _method_target_report(target: tuple[str, str, str | None]) -> dict[str, str]:
    class_desc, method_name, signature = target
    return {
        "spec": f"{class_desc}->{method_name}{signature or ''}",
        "class_desc": class_desc,
        "method_name": method_name,
        "signature": signature or "*",
    }


def _method_info_report(item: dict[str, Any]) -> dict[str, Any]:
    class_desc = str(item.get("class_desc", ""))
    method_name = str(item.get("method_name", ""))
    signature = str(item.get("signature", ""))
    return {
        "spec": f"{class_desc}->{method_name}{signature}",
        "class_desc": class_desc,
        "method_name": method_name,
        "signature": signature,
        "method_id": item.get("method_id"),
        "dex_index": item.get("dex_index"),
        "method_idx": item.get("method_idx"),
        "is_static": bool(item.get("is_static", False)),
        "has_try_catch": bool(item.get("has_try_catch", False)),
    }


def _ranked_method_report(ranked: Any) -> dict[str, Any]:
    rec = ranked.rec
    return {
        "spec": rec.spec,
        "dex": rec.dex_name,
        "score": int(ranked.score),
        "code_bytes": int(rec.code_bytes),
        "registers_size": int(rec.registers_size),
        "outs_size": int(rec.outs_size),
        "tries_size": int(rec.tries_size),
        "invoke_count": int(rec.invoke_count),
        "reasons": list(ranked.reasons),
    }


def build_method_protection_details(
    *,
    protection_map_path: str,
    extract_methods_path: str,
    vmp_dex_methods_path: str,
    dex2c_methods_path: str,
    auto_protect_report: dict[str, Any],
    extract_spec: list[tuple[str, str, str | None]],
    vmp_spec: list[tuple[str, str, str | None]],
    dex2c_spec: list[tuple[str, str, str | None]],
    vmp_method_info: list[dict[str, Any]],
    shell_vmp_method_info: list[dict[str, Any]],
    extract_compiled_count: int,
    dex2c_compiled_count: int,
) -> dict[str, Any]:
    return {
        "sources": {
            "protection_map": bool(protection_map_path),
            "extract_methods_file": bool(extract_methods_path),
            "vmp_dex_methods_file": bool(vmp_dex_methods_path),
            "dex2c_methods_file": bool(dex2c_methods_path),
            "auto_protect": bool(auto_protect_report.get("enabled")),
        },
        "requested": {
            "extract": [_method_target_report(target) for target in extract_spec],
            "vmp_dex": [_method_target_report(target) for target in vmp_spec],
            "dex2c": [_method_target_report(target) for target in dex2c_spec],
        },
        "compiled": {
            "extract": {
                "count": int(extract_compiled_count),
                "details_available": False,
            },
            "vmp_dex": {
                "count": len(vmp_method_info),
                "methods": [_method_info_report(item) for item in vmp_method_info],
            },
            "dex2c": {
                "count": int(dex2c_compiled_count),
                "details_available": False,
                "target_library": "libagpjnix.so",
            },
            "shell_vmp": {
                "count": len(shell_vmp_method_info),
                "methods": [_method_info_report(item) for item in shell_vmp_method_info],
            },
        },
        "auto_protect": auto_protect_report,
    }


def resolve_vmp_obfuscation_options(args: argparse.Namespace) -> None:
    preset = str(getattr(args, "vmp_dex_obfuscation_preset", "stable") or "stable")
    if preset not in VMP_OBFUSCATION_PRESETS:
        raise HardenError(f"unknown VMP obfuscation preset: {preset}")

    split_default, junk_default, inline_default = VMP_OBFUSCATION_PRESETS[preset]
    option_defaults = {
        "vmp_dex_split_prob": split_default,
        "vmp_dex_junk_ratio": junk_default,
        "vmp_dex_inline_junk_ratio": inline_default,
    }
    explicit = False
    for opt_name, default_value in option_defaults.items():
        raw = getattr(args, opt_name, None)
        if raw is None:
            setattr(args, opt_name, default_value)
        else:
            explicit = True
            setattr(args, opt_name, float(raw))

    actual = (
        float(args.vmp_dex_split_prob),
        float(args.vmp_dex_junk_ratio),
        float(args.vmp_dex_inline_junk_ratio),
    )
    args.vmp_dex_obfuscation_mode = "custom" if explicit and actual != VMP_OBFUSCATION_PRESETS[preset] else preset


def resolve_vmp_vm_tier(args: argparse.Namespace) -> str:
    requested = str(getattr(args, "vmp_vm_tier", "auto") or "auto").strip().lower()
    if requested != "auto":
        if requested not in VMP_VM_TIERS:
            raise HardenError(f"unknown VMP VM tier: {requested}")
        effective = requested
    else:
        auto_profile = str(getattr(args, "auto_protect_profile", "balanced") or "balanced")
        risk_profile = str(getattr(args, "risk_profile", "balanced") or "balanced")
        risk_policy = str(getattr(args, "risk_policy", "block") or "block")
        if bool(getattr(args, "commercial_mode", False)) or auto_profile in {"strong", "extreme"}:
            effective = "strong"
        elif risk_profile == "strict" and risk_policy == "block":
            effective = "strong"
        elif auto_profile == "compat" or risk_profile == "compat":
            effective = "compat"
        else:
            effective = "light"
    args.vmp_vm_tier_requested = requested
    args.vmp_vm_tier_effective = effective
    args.vmp_vm_tier_code = int(VMP_VM_TIERS[effective]["code"])
    return effective


def resolve_extract_restore_options(args: argparse.Namespace) -> None:
    if getattr(args, "extract_on_demand", None) is None:
        args.extract_on_demand = args.risk_profile != "compat"


def _vmp_plaintext_needles(method_info: list[dict[str, Any]]) -> list[bytes]:
    needles: set[bytes] = set()
    for item in method_info:
        for key in ("class_desc", "method_name", "signature"):
            value = str(item.get(key, "") or "")
            if len(value) >= 6:
                needles.add(value.encode("utf-8"))
        class_desc = str(item.get("class_desc", "") or "")
        if class_desc.startswith("L") and class_desc.endswith(";"):
            slash_name = class_desc[1:-1]
            if len(slash_name) >= 6:
                needles.add(slash_name.encode("utf-8"))
                needles.add(slash_name.replace("/", ".").encode("utf-8"))
    return sorted(needles)


def audit_vmp_blob_plaintext(
    decoded_apk_dir: Path,
    *,
    payload_method_info: list[dict[str, Any]],
    shell_method_info: list[dict[str, Any]],
    vmp_blob_name: str = NATIVE_LAYER_VMP_NAME,
    shell_vmp_blob_name: str = NATIVE_LAYER_SHELL_VMP_NAME,
) -> dict[str, Any]:
    checks = [
        (vmp_blob_name, _vmp_plaintext_needles(payload_method_info)),
        (shell_vmp_blob_name, _vmp_plaintext_needles(shell_method_info)),
    ]
    hits: list[dict[str, Any]] = []
    checked_files = 0

    for filename, needles in checks:
        if not needles:
            continue
        for path in sorted(decoded_apk_dir.glob(f"lib/*/{filename}")):
            checked_files += 1
            data = path.read_bytes()
            matched = [
                needle.decode("utf-8", "replace")
                for needle in needles
                if needle in data
            ]
            if matched:
                hits.append({
                    "path": str(path.relative_to(decoded_apk_dir)),
                    "needles": matched[:20],
                    "truncated": len(matched) > 20,
                })

    return {
        "checked_files": checked_files,
        "hit_count": sum(len(item["needles"]) for item in hits),
        "status": "clean" if not hits else "plaintext-hit",
        "hits": hits,
    }


def harden(args: argparse.Namespace) -> None:
    harden_t0 = time.monotonic()
    if _CRYPTO_IMPORT_ERROR is not None:
        raise HardenError(
            "missing dependency: pycryptodome. Install with: pip install pycryptodome"
        )
    resolve_vmp_obfuscation_options(args)
    resolve_extract_restore_options(args)
    effective_vmp_vm_tier = resolve_vmp_vm_tier(args)
    print(
        "[*] VMP VM tier: "
        f"requested={args.vmp_vm_tier_requested}, effective={effective_vmp_vm_tier}"
    )
    if args.min_extract_count < 0:
        raise HardenError("--min-extract-count must be >= 0")
    if args.min_vmp_dex_count < 0:
        raise HardenError("--min-vmp-dex-count must be >= 0")
    if args.min_dex2c_count < 0:
        raise HardenError("--min-dex2c-count must be >= 0")
    if args.min_security_score < 0 or args.min_security_score > 100:
        raise HardenError("--min-security-score must be between 0 and 100")
    for opt_name in (
        "vmp_dex_split_prob",
        "vmp_dex_junk_ratio",
        "vmp_dex_inline_junk_ratio",
    ):
        val = float(getattr(args, opt_name, 0.0))
        if val < 0.0 or val > 1.0:
            raise HardenError(f"--{opt_name.replace('_', '-')} must be between 0.0 and 1.0")

    input_apk = Path(args.input_apk).resolve()
    output_apk = Path(args.output_apk).resolve()

    ensure_file(input_apk, "input apk")
    print(f"[*] input apk: {input_apk} ({input_apk.stat().st_size / 1024:.0f} KB)")

    shell_apk_for_verify: Path | None = None
    if args.shell_apk:
        shell_apk_for_verify = Path(args.shell_apk).resolve()
        ensure_file(shell_apk_for_verify, "shell apk")

    release_meta: dict[str, Any] | None = None
    release_manifest_raw = (args.release_manifest or "").strip()
    release_pmap_path: Path | None = None
    if (args.protection_map or "").strip():
        release_pmap_path = Path(args.protection_map).resolve()
    if release_manifest_raw:
        release_meta = load_release_manifest(
            Path(release_manifest_raw).resolve(),
            release_pmap_path,
        )
        print(
            "[*] release meta loaded: "
            f"engine={release_meta['engine_version']}, "
            f"rules={release_meta['rules_version']}, "
            f"policy={release_meta['policy_version']}, "
            f"map={release_meta['map_version']}, "
            f"schema={release_meta['config_schema_version']}"
        )

    if args.commercial_mode:
        verify_release_obfuscation(
            input_apk,
            "input apk",
            allow_weak_release=bool(args.allow_weak_release),
        )
        if shell_apk_for_verify is not None:
            verify_release_obfuscation(
                shell_apk_for_verify,
                "shell apk",
                allow_weak_release=bool(args.allow_weak_release),
            )
        elif not args.allow_weak_release:
            raise HardenError(
                "--commercial-mode requires --shell-apk for release obfuscation verification "
                "(or pass --allow-weak-release)"
            )

    use_per_apk_key = args.per_apk_key
    if use_per_apk_key:
        payload_key = get_random_bytes(32)
        payload_key_hex = payload_key.hex().upper()
        print("[*] per-apk random payload key generated")
    else:
        embedded_payload_key = derive_embedded_payload_key()
        payload_key_hex = args.payload_key_hex.strip()
        if payload_key_hex:
            if not re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{64}", payload_key_hex):
                raise HardenError("--payload-key-hex must be 32 hex (AES-128) or 64 hex (AES-256)")
            payload_key = bytes.fromhex(payload_key_hex)
            if payload_key != embedded_payload_key:
                raise HardenError(
                    "--payload-key-hex does not match native embedded key; "
                    "omit this flag or rebuild shell native key material"
                )
        else:
            payload_key = embedded_payload_key
            payload_key_hex = payload_key.hex().upper()
        print("[*] using legacy embedded payload key")
    if args.native_key_obfuscation:
        print("[!] --native-key-obfuscation is deprecated: payload key is no longer written to cfg")
    vmp_command_template = (args.vmp_command_template or "").strip()
    vmp_enabled = bool(vmp_command_template)
    vmp_target_libs: list[str] = []
    if vmp_enabled:
        vmp_target_libs = parse_vmp_target_libs(args.vmp_target_libs)
    keystore = Path(args.keystore).resolve() if args.keystore else None
    sign_fields = [args.keystore, args.ks_pass, args.key_alias, args.key_pass]
    provided_sign_fields = sum(1 for x in sign_fields if (x or "").strip())
    if provided_sign_fields not in (0, 4):
        raise HardenError(
            "signing args must be all-or-none: --keystore --ks-pass --key-alias --key-pass"
        )

    if not args.skip_sign and provided_sign_fields != 4:
        raise HardenError(
            "--sign requires all signing args: --keystore --ks-pass --key-alias --key-pass"
        )
    signing_enabled = (provided_sign_fields == 4) and (not args.skip_sign)
    if args.skip_sign and provided_sign_fields == 4:
        print("[*] signing credentials supplied without --sign; output remains unsigned and cert is used for pinning only")
    if args.commercial_mode:
        if args.skip_zipalign:
            raise HardenError("--commercial-mode forbids --skip-zipalign")
        if args.vmp_fail_open or args.vmp_dex_fail_open or args.extract_fail_open or args.dex2c_fail_open:
            raise HardenError("--commercial-mode forbids all fail-open options")
        if args.risk_policy != "block":
            raise HardenError("--commercial-mode requires --risk-policy block")
        if args.risk_profile != "strict":
            raise HardenError("--commercial-mode requires --risk-profile strict")
        if not args.block_proxy_vpn:
            raise HardenError("--commercial-mode requires --block-proxy-vpn")
        if not args.per_apk_key:
            raise HardenError("--commercial-mode requires per-APK key (do not use --no-per-apk-key)")
        if args.min_security_score == 0:
            args.min_security_score = 90
        # Commercial builds auto-enable AI decoy/canary injection (cheap,
        # static, never touches real code) unless explicitly turned off.
        if not args.ai_decoy:
            args.ai_decoy = True
            print("[*] commercial mode: AI decoy/canary injection enabled")
    if provided_sign_fields == 4 and keystore is not None:
        ensure_file(keystore, "keystore")
    skip_zipalign = bool(args.skip_zipalign)
    if args.zipalign:
        zipalign = args.zipalign
    else:
        zipalign_found = shutil.which("zipalign")
        if zipalign_found:
            zipalign = zipalign_found
        elif skip_zipalign:
            zipalign = ""
            print("[!] zipalign not found; continue because --skip-zipalign is set")
        else:
            raise HardenError("binary not found in PATH: zipalign")
    apksigner = args.apksigner or (which_or_fail("apksigner") if signing_enabled else args.apksigner)
    if not apksigner and not signing_enabled:
        apksigner = shutil.which("apksigner") or ""

    sign_cert_sha256 = normalize_sha256_hex(args.sign_cert_sha256)
    if not sign_cert_sha256:
        if provided_sign_fields == 4 and keystore is not None:
            sign_cert_sha256 = extract_sign_sha256_from_keystore(
                keystore,
                args.ks_pass,
                args.key_alias,
                args.key_pass,
            )
            print(f"[*] sign cert sha256 auto-extracted from keystore: {sign_cert_sha256}")
        elif apksigner:
            try:
                sign_cert_sha256 = extract_sign_sha256_from_apk(apksigner, input_apk)
                print(f"[*] sign cert sha256 extracted from input apk: {sign_cert_sha256}")
            except Exception as e:
                print(f"[!] sign cert sha256 not pinned automatically: {e}")
                print("[!] continue without runtime signature pin (pass --sign-cert-sha256 to enforce)")
        else:
            print("[!] apksigner not found; signature pin disabled unless --sign-cert-sha256 is provided")
    if args.commercial_mode and not sign_cert_sha256:
        raise HardenError(
            "--commercial-mode requires runtime signature pin. "
            "Use a signed input APK, provide --apksigner so it can be read, "
            "or pass --sign-cert-sha256 manually. Output signing can still be skipped."
        )

    apktool = args.apktool or which_or_fail("apktool")

    # Parse target ABIs
    target_abis_raw = (args.target_abis or "").strip()
    target_abis: list[str] | None = None
    if target_abis_raw:
        valid_abis = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}
        target_abis = [a.strip() for a in target_abis_raw.split(",") if a.strip()]
        unknown = set(target_abis) - valid_abis
        if unknown:
            raise HardenError(f"unknown target ABIs: {', '.join(sorted(unknown))}")
        print(f"[*] target ABIs: {', '.join(target_abis)}")
    else:
        print("[*] target ABIs: auto-detect (all available)")

    with tempfile.TemporaryDirectory(prefix="enko_harden_") as tmp:
        tmp_dir = Path(tmp)
        decoded_dir = tmp_dir / "decoded"
        unsigned_apk = tmp_dir / "unsigned.apk"
        aligned_apk = tmp_dir / "aligned.apk"
        resolved_shell_dex = tmp_dir / "shell_classes.dex"

        if args.shell_dex:
            user_shell_dex = Path(args.shell_dex).resolve()
            ensure_file(user_shell_dex, "shell dex")
            shutil.copy2(user_shell_dex, resolved_shell_dex)
            print(f"[*] using shell dex: {user_shell_dex}")
        elif args.shell_apk:
            user_shell_apk = Path(args.shell_apk).resolve()
            extract_shell_dex_from_apk(user_shell_apk, resolved_shell_dex)
            print(f"[*] extracted shell dex from apk: {user_shell_apk}")
        else:
            raise HardenError("either --shell-dex or --shell-apk is required")

        _step_times.clear()
        _log_step(1, "Decode APK")
        run([apktool, "d", "-s", "-f", str(input_apk), "-o", str(decoded_dir)], label="decode")

        manifest_path = decoded_dir / "AndroidManifest.xml"
        ensure_file(manifest_path, "decoded AndroidManifest.xml")
        manifest_text = manifest_path.read_text(encoding="utf-8")

        package_name = parse_package_name(manifest_text)
        version_code = parse_manifest_version_code(manifest_text)
        if version_code <= 0:
            version_code = infer_version_code_from_binary_manifest(input_apk)
        if version_code <= 0:
            version_code = infer_version_code_from_output_metadata(input_apk)
        if version_code <= 0:
            version_code = 1
        raw_original_app = parse_manifest_original_app(manifest_text)
        original_app = normalize_app_name(raw_original_app, package_name)
        build_epoch_sec = int(time.time())
        build_id = generate_build_id(package_name, version_code, build_epoch_sec, input_apk)

        print(f"[*] detected package: {package_name}")
        print(f"[*] detected versionCode: {version_code if version_code > 0 else '<unknown>'}")
        print(f"[*] generated build-id: {build_id}, build-epoch: {build_epoch_sec}")
        print(f"[*] detected original application: {original_app or '<none>'}")
        print("[*] " + read_runtime_config_example().strip())

        # ── Protection-map: unified per-method protection level config ──
        protection_map_path = (args.protection_map or "").strip()
        pmap_extract_targets: list[tuple[str, str, str | None]] = []
        pmap_vmp_targets: list[tuple[str, str, str | None]] = []
        pmap_dex2c_targets: list[tuple[str, str, str | None]] = []
        if protection_map_path:
            pmap_extract_targets, pmap_vmp_targets, pmap_dex2c_targets = parse_protection_map(
                Path(protection_map_path).resolve()
            )
            print(
                f"[*] protection-map: {len(pmap_extract_targets)} extract, "
                f"{len(pmap_vmp_targets)} vmp, {len(pmap_dex2c_targets)} dex2c"
            )

        # ── VMP DEX compilation (before payload packaging) ──
        vmp_dex_methods_path = (args.vmp_dex_methods or "").strip()
        vmp_dex_enabled = bool(vmp_dex_methods_path) or bool(pmap_vmp_targets)
        vmp_dex_blob: bytes | None = None
        vmp_method_info: list[dict[str, Any]] = []
        vmp_compiled_count = 0
        vmp_dex_obfuscation_report: dict[str, Any] = {}

        # ── Method extraction (before payload packaging) ──
        extract_methods_path = (args.extract_methods or "").strip()
        extract_enabled = bool(extract_methods_path) or bool(pmap_extract_targets)
        extract_blob: bytes | None = None
        extract_compiled_count = 0

        # ── DEX2C compilation (before payload packaging) ──
        dex2c_methods_path = (args.dex2c_methods or "").strip()
        dex2c_enabled = bool(dex2c_methods_path) or bool(pmap_dex2c_targets)
        d2c_compiled_count = 0
        dex2c_build_report: dict[str, Any] = {}
        args.vmp_dex_obfuscation_report = vmp_dex_obfuscation_report

        # ── Auto protection-map generation ──
        # When no explicit method specs are provided, use local heuristics
        # to select a reasonable set of methods for extract/VMP/DEX2C.
        auto_protect_extract: list[tuple[str, str, str | None]] = []
        auto_protect_vmp: list[tuple[str, str, str | None]] = []
        auto_protect_dex2c: list[tuple[str, str, str | None]] = []
        auto_protect_report: dict[str, Any] = {"enabled": False}
        if (
            not getattr(args, "no_auto_protect", False)
            and not protection_map_path
            and not extract_methods_path
            and not vmp_dex_methods_path
            and not dex2c_methods_path
        ):
            print("[*] auto-protect: no explicit method specs — running local heuristics")
            try:
                packer_dir = str(Path(__file__).resolve().parent)
                if packer_dir not in sys.path:
                    sys.path.insert(0, packer_dir)
                from auto_protect_map import (
                    collect_methods_from_apk,
                    pick_methods,
                    resolve_auto_protect_profile,
                )

                methods = collect_methods_from_apk(input_apk)
                print(f"[*] auto-protect: collected {len(methods)} method(s) from APK")

                has_ndk = bool((args.ndk_path or "").strip())
                auto_profile = resolve_auto_protect_profile(
                    getattr(args, "auto_protect_profile", "balanced"),
                    has_ndk=has_ndk,
                )
                auto_protect_report = {
                    "enabled": True,
                    "profile": auto_profile.name,
                    "label": auto_profile.label,
                    "selected": {"extract": [], "vmp_dex": [], "dex2c": []},
                }
                auto_vmp_count = auto_profile.vmp_count
                auto_d2c_count = auto_profile.dex2c_count
                auto_extract_count = auto_profile.extract_count
                print(
                    "[*] auto-protect: profile="
                    f"{auto_profile.name} ({auto_profile.label})"
                )

                if not has_ndk:
                    print("[!] auto-protect: --ndk-path not set; skipping VMP/DEX2C (extract-only)")
                if auto_vmp_count == 0 and auto_d2c_count == 0 and auto_extract_count == 0:
                    print("[*] auto-protect: nothing to select")
                else:
                    extract_sel, vmp_sel, d2c_sel = pick_methods(
                        methods=methods,
                        include_packages=[],
                        exclude_prefixes=[],
                        vmp_count=auto_vmp_count,
                        dex2c_count=auto_d2c_count,
                        extract_count=auto_extract_count,
                        min_score_vmp=auto_profile.min_score_vmp,
                        min_score_dex2c=auto_profile.min_score_dex2c,
                        min_score_extract=auto_profile.min_score_extract,
                        flutter_mode=bool(getattr(args, "flutter_mode", False)),
                    )
                    auto_protect_extract = [(r.rec.class_desc, r.rec.method_name, r.rec.signature) for r in extract_sel]
                    auto_protect_vmp = [(r.rec.class_desc, r.rec.method_name, r.rec.signature) for r in vmp_sel]
                    auto_protect_dex2c = [(r.rec.class_desc, r.rec.method_name, r.rec.signature) for r in d2c_sel]
                    auto_protect_report = {
                        "enabled": True,
                        "profile": auto_profile.name,
                        "label": auto_profile.label,
                        "selected": {
                            "extract": [_ranked_method_report(r) for r in extract_sel],
                            "vmp_dex": [_ranked_method_report(r) for r in vmp_sel],
                            "dex2c": [_ranked_method_report(r) for r in d2c_sel],
                        },
                    }
                    print(
                        f"[*] auto-protect: selected extract={len(auto_protect_extract)}, "
                        f"vmp={len(auto_protect_vmp)}, dex2c={len(auto_protect_dex2c)}"
                    )
            except Exception as e:
                print(f"[!] auto-protect failed: {e}; continuing without method protection")
                auto_protect_report = {"enabled": True, "error": str(e)}
                import traceback
                traceback.print_exc()

        # Merge auto-protect targets into pmap targets.
        if auto_protect_extract:
            pmap_extract_targets = list(pmap_extract_targets) + auto_protect_extract
        if auto_protect_vmp:
            pmap_vmp_targets = list(pmap_vmp_targets) + auto_protect_vmp
        if auto_protect_dex2c:
            pmap_dex2c_targets = list(pmap_dex2c_targets) + auto_protect_dex2c

        # Recompute enabled flags after auto-protect.
        if auto_protect_extract or auto_protect_vmp or auto_protect_dex2c:
            vmp_dex_enabled = vmp_dex_enabled or bool(pmap_vmp_targets)
            extract_enabled = extract_enabled or bool(pmap_extract_targets)
            dex2c_enabled = dex2c_enabled or bool(pmap_dex2c_targets)

        # Auto-clamp min thresholds to protection-map target counts.
        # Users may set high thresholds that exceed what the APK can provide.
        if pmap_extract_targets and args.min_extract_count > len(pmap_extract_targets):
            print(f"[*] auto-clamp: --min-extract-count {args.min_extract_count} → {len(pmap_extract_targets)} (protection-map limit)")
            args.min_extract_count = len(pmap_extract_targets)
        if pmap_vmp_targets and args.min_vmp_dex_count > len(pmap_vmp_targets):
            print(f"[*] auto-clamp: --min-vmp-dex-count {args.min_vmp_dex_count} → {len(pmap_vmp_targets)} (protection-map limit)")
            args.min_vmp_dex_count = len(pmap_vmp_targets)
        if pmap_dex2c_targets and args.min_dex2c_count > len(pmap_dex2c_targets):
            print(f"[*] auto-clamp: --min-dex2c-count {args.min_dex2c_count} → {len(pmap_dex2c_targets)} (protection-map limit)")
            args.min_dex2c_count = len(pmap_dex2c_targets)

        if args.commercial_mode:
            if extract_enabled and args.min_extract_count == 0:
                args.min_extract_count = 1
            if vmp_dex_enabled and args.min_vmp_dex_count == 0:
                args.min_vmp_dex_count = 1
            if dex2c_enabled and args.min_dex2c_count == 0:
                args.min_dex2c_count = 1
            if dex2c_enabled and not args.dex2c_ollvm:
                raise HardenError("--commercial-mode requires --dex2c-ollvm when DEX2C is enabled")
            if dex2c_enabled:
                args.dex2c_ollvm_required = True

        args.dex2c_ollvm_probe = probe_ollvm_clang(
            str(args.dex2c_ollvm_clang),
            requested=bool(dex2c_enabled and args.dex2c_ollvm),
            required=bool(dex2c_enabled and args.dex2c_ollvm_required),
        )
        args.dex2c_ollvm_build_report = dex2c_build_report
        if dex2c_enabled and args.dex2c_ollvm:
            probe_status = str(args.dex2c_ollvm_probe.get("preflight_status", "not-run"))
            if args.dex2c_ollvm_probe.get("available"):
                print(
                    "[*] DEX2C OLLVM preflight: "
                    f"{args.dex2c_ollvm_probe.get('version') or '<version unknown>'}"
                )
            elif args.dex2c_ollvm_required:
                raise HardenError(
                    str(args.dex2c_ollvm_probe.get("reason") or "DEX2C OLLVM unavailable")
                )
            else:
                print(
                    "[!] DEX2C OLLVM preflight: "
                    f"{probe_status}; normal NDK fallback may be used "
                    f"({args.dex2c_ollvm_probe.get('reason')})"
                )

        _log_step(2, "Package & Encrypt Payload")
        dex_files = collect_dex_files(decoded_dir)
        print(f"[*] found dex files: {[p.name for p in dex_files]}")
        protectable_method_count = count_protectable_methods(dex_files)
        print(f"[*] protectable methods in APK: {protectable_method_count}")

        vmp_spec: list[tuple[str, str, str | None]] = []
        extract_spec: list[tuple[str, str, str | None]] = []
        dex2c_spec: list[tuple[str, str, str | None]] = []
        vmp_requested_count = 0
        extract_requested_count = 0
        d2c_requested_count = 0

        if vmp_dex_enabled:
            ndk_path_raw = (args.ndk_path or "").strip()
            if not ndk_path_raw:
                raise HardenError(
                    "--ndk-path is required when VMP DEX protection is enabled "
                    "(needed for compiling JNI stub .so)"
                )
            print("[*] VMP DEX: compiling target methods...")
            if vmp_dex_methods_path:
                vmp_spec = parse_vmp_dex_spec(Path(vmp_dex_methods_path).resolve())
            # Merge protection-map VMP targets.
            if pmap_vmp_targets:
                vmp_spec.extend(pmap_vmp_targets)
            vmp_spec = dedupe_method_targets(vmp_spec)
            vmp_requested_count = len(vmp_spec)
            print(f"[*] VMP DEX: {len(vmp_spec)} target method(s)")
            vmp_dex_blob, vmp_method_info = run_vmp_dex_compilation(
                dex_files,
                vmp_spec,
                fail_open=args.vmp_dex_fail_open,
                wipe_insns=args.vmp_dex_wipe_insns,
                split_prob=args.vmp_dex_split_prob,
                junk_ratio=args.vmp_dex_junk_ratio,
                inline_junk_ratio=args.vmp_dex_inline_junk_ratio,
                obfuscation_report=vmp_dex_obfuscation_report,
            )
            args.vmp_dex_obfuscation_report = vmp_dex_obfuscation_report
            vmp_compiled_count = len(vmp_method_info)
            # The production computed-goto VMP interpreter does not honor
            # in-method try/catch (handler dispatch exists only in the portable
            # switch fallback). A VMP-protected method that catches its own
            # exceptions would silently change behavior. auto-protect already
            # downgrades such methods, but a hand-written protection map can
            # still target them — warn, and fail-closed under commercial /
            # strict+block builds where business correctness must not regress.
            vmp_try_catch_methods = [
                f"{m.get('class_desc', '')}->{m.get('method_name', '')}{m.get('signature', '')}"
                for m in vmp_method_info
                if m.get("has_try_catch")
            ]
            if vmp_try_catch_methods:
                vmp_strict_build = bool(args.commercial_mode) or (
                    args.risk_policy == "block" and args.risk_profile == "strict"
                )
                preview = ", ".join(vmp_try_catch_methods[:5])
                if len(vmp_try_catch_methods) > 5:
                    preview += f", ... (+{len(vmp_try_catch_methods) - 5} more)"
                msg = (
                    f"VMP DEX: {len(vmp_try_catch_methods)} target method(s) contain "
                    "try/catch blocks that the fast-path interpreter does not catch "
                    f"in-method: {preview}"
                )
                if vmp_strict_build and not args.vmp_dex_fail_open:
                    raise HardenError(
                        msg
                        + ". Remove these methods from the VMP protection map "
                        "(use extract/level 1 instead), or pass --vmp-dex-fail-open "
                        "to override on a non-commercial build."
                    )
                print(
                    f"[!] {msg}; consider downgrading them to extract (level 1) "
                    "to preserve exception semantics."
                )
            if vmp_dex_blob:
                print(f"[*] VMP DEX: blob generated ({len(vmp_dex_blob)} bytes)")
            else:
                msg = "VMP DEX: no methods compiled (blob is empty)"
                if args.vmp_dex_fail_open:
                    print(f"[!] {msg}; continue because --vmp-dex-fail-open is set")
                    vmp_dex_enabled = False
                else:
                    raise HardenError(msg)

        if extract_enabled:
            print("[*] method extraction: extracting target methods...")
            # Add packer dir to sys.path so we can import sibling modules.
            packer_dir = str(Path(__file__).resolve().parent)
            if packer_dir not in sys.path:
                sys.path.insert(0, packer_dir)
            from method_extractor import run_method_extraction

            if extract_methods_path:
                extract_spec = parse_vmp_dex_spec(Path(extract_methods_path).resolve())
            # Merge protection-map extract targets.
            if pmap_extract_targets:
                extract_spec.extend(pmap_extract_targets)
            extract_spec = dedupe_method_targets(extract_spec)
            extract_requested_count = len(extract_spec)
            print(f"[*] extract: {len(extract_spec)} target method(s)")
            extract_blob, extract_count = run_method_extraction(
                dex_files,
                extract_spec,
                payload_key,
                fail_open=args.extract_fail_open,
            )
            extract_compiled_count = extract_count
            if extract_blob:
                print(f"[*] extract: blob generated ({len(extract_blob)} bytes, {extract_count} method(s))")
            else:
                msg = "method extraction: no methods extracted (blob is empty)"
                if args.extract_fail_open:
                    print(f"[!] {msg}; continue because --extract-fail-open is set")
                    extract_enabled = False
                else:
                    raise HardenError(msg)

        # ── DEX2C compilation ──
        if dex2c_enabled:
            print("[*] DEX2C: compiling target methods to native C...")
            if args.dex2c_ollvm:
                required_note = "required" if args.dex2c_ollvm_required else "best-effort"
                print(
                    "[*] DEX2C: Hikari/OLLVM enabled for libagpjnix.so "
                    f"({required_note}, clang={args.dex2c_ollvm_clang})"
                )
            else:
                print("[!] DEX2C: Hikari/OLLVM disabled for libagpjnix.so")
            packer_dir = str(Path(__file__).resolve().parent)
            if packer_dir not in sys.path:
                sys.path.insert(0, packer_dir)
            from dex2c.compiler import run_dex2c_compilation

            if dex2c_methods_path:
                dex2c_spec = parse_vmp_dex_spec(Path(dex2c_methods_path).resolve())
            # Merge protection-map dex2c targets.
            if pmap_dex2c_targets:
                dex2c_spec.extend(pmap_dex2c_targets)
            dex2c_spec = dedupe_method_targets(dex2c_spec)
            d2c_requested_count = len(dex2c_spec)
            print(f"[*] DEX2C: {len(dex2c_spec)} target method(s)")

            try:
                d2c_compiled, d2c_sos = run_dex2c_compilation(
                    dex_files,
                    dex2c_spec,
                    ndk_path=args.ndk_path,
                    decoded_apk_dir=decoded_dir,
                    fail_open=args.dex2c_fail_open,
                    wipe_insns=True,
                    target_abis=target_abis,
                    ollvm_enabled=bool(args.dex2c_ollvm),
                    ollvm_clang=str(args.dex2c_ollvm_clang),
                    ollvm_required=bool(args.dex2c_ollvm_required),
                    build_report=dex2c_build_report,
                )
                args.dex2c_ollvm_build_report = dex2c_build_report
                d2c_compiled_count = d2c_compiled
                if d2c_compiled > 0 and d2c_sos > 0:
                    print(f"[*] DEX2C: {d2c_compiled} method(s) compiled, {d2c_sos} ABI(s)")
                elif d2c_compiled > 0 and d2c_sos == 0:
                    msg = "DEX2C: methods translated but no .so produced"
                    if args.dex2c_fail_open:
                        print(f"[!] {msg}; continue because --dex2c-fail-open is set")
                        dex2c_enabled = False
                    else:
                        raise HardenError(msg)
                else:
                    msg = "DEX2C: no methods compiled"
                    if args.dex2c_fail_open:
                        print(f"[!] {msg}; continue because --dex2c-fail-open is set")
                        dex2c_enabled = False
                    else:
                        raise HardenError(msg)
            except HardenError:
                raise
            except Exception as exc:
                msg = f"DEX2C compilation failed: {exc}"
                if args.dex2c_fail_open:
                    print(f"[!] {msg}; continue because --dex2c-fail-open is set")
                    dex2c_enabled = False
                else:
                    raise HardenError(msg) from exc

        print(
            f"[*] protection hit summary: "
            f"extract={extract_compiled_count}, "
            f"vmp_dex={vmp_compiled_count}, "
            f"dex2c={d2c_compiled_count}"
        )
        native_core_profile = inspect_native_core_profile(decoded_dir)
        flutter_mode = bool(args.flutter_mode or native_core_profile["flutter_detected"])
        if flutter_mode:
            print(
                "[*] flutter runtime profile: "
                f"libapp={len(native_core_profile['libapp_paths'])}, "
                f"libflutter={len(native_core_profile['libflutter_paths'])}, "
                f"hook_targets={','.join(native_core_profile['hook_watch_targets'])}"
            )
        if extract_compiled_count < args.min_extract_count:
            raise HardenError(
                f"extract compiled {extract_compiled_count} method(s), "
                f"below --min-extract-count={args.min_extract_count}"
            )
        if vmp_compiled_count < args.min_vmp_dex_count:
            raise HardenError(
                f"vmp-dex compiled {vmp_compiled_count} method(s), "
                f"below --min-vmp-dex-count={args.min_vmp_dex_count}"
            )
        if d2c_compiled_count < args.min_dex2c_count:
            raise HardenError(
                f"dex2c compiled {d2c_compiled_count} method(s), "
                f"below --min-dex2c-count={args.min_dex2c_count}"
            )

        security_report = build_security_report(
            args,
            signing_enabled=signing_enabled,
            sign_cert_sha256=sign_cert_sha256,
            extract_enabled=extract_enabled,
            vmp_dex_enabled=vmp_dex_enabled,
            dex2c_enabled=dex2c_enabled,
            extract_compiled_count=extract_compiled_count,
            vmp_compiled_count=vmp_compiled_count,
            d2c_compiled_count=d2c_compiled_count,
            extract_requested_count=extract_requested_count,
            vmp_requested_count=vmp_requested_count,
            d2c_requested_count=d2c_requested_count,
            protectable_method_count=protectable_method_count,
            flutter_mode=flutter_mode,
            native_core_profile=native_core_profile,
        )
        if release_meta:
            security_report["release_meta"] = release_meta
        print(
            f"[*] security score: {security_report['score']}/"
            f"{security_report['max_score']} (grade {security_report['grade']})"
        )
        mp_summary = security_report["method_protection"]
        print(
            "[*] method coverage: "
            f"{mp_summary['compiled_total']}/{mp_summary['protectable_methods_total']} "
            f"protectable methods "
            f"({mp_summary['protectable_coverage_ratio']:.2%}, "
            f"coverage grade {mp_summary['coverage_grade']})"
        )
        # Adjust score gate: subtract weight of intentionally-disabled features
        effective_min_score = args.min_security_score
        if effective_min_score > 0:
            skip_weight = 0
            if args.skip_sign and not sign_cert_sha256:
                skip_weight += 20  # signed-output weight
            if args.skip_zipalign:
                skip_weight += 5   # zipalign-enabled weight
            if skip_weight > 0:
                effective_min_score = max(1, effective_min_score - skip_weight)
                if effective_min_score != args.min_security_score:
                    print(f"[*] score gate adjusted: {args.min_security_score} → {effective_min_score} (skip-sign/zipalign)")

        if effective_min_score > 0 and security_report["score"] < effective_min_score:
            raise HardenError(
                f"security score {security_report['score']} below "
                f"adjusted --min-security-score={effective_min_score}; "
                f"missing: {', '.join(security_report['recommendations'])}"
            )

        packaged_plain = package_dex_files(dex_files)
        payload_bytes, payload_compression = select_payload_bytes(packaged_plain, args.payload_compress)
        payload_envelope_report: dict[str, Any] = {}
        encrypted_payload = wrap_payload_envelope(
            encrypt_payload(payload_bytes, payload_key),
            metadata=payload_envelope_report,
        )
        security_report["payload_envelope"] = payload_envelope_report
        print(
            f"[*] payload compression: {payload_compression}, "
            f"size {len(packaged_plain)} -> {len(payload_bytes)} bytes, "
            f"wrapped encrypted blob {len(encrypted_payload)} bytes "
            f"(padding={payload_envelope_report.get('padding_length', 0)})"
        )


        # ── Inject native libs from shell APK EARLY (before polymorphic rename) ──
        if args.shell_apk:
            so_count = extract_native_libs_from_apk(
                Path(args.shell_apk).resolve(), decoded_dir, target_abis=target_abis
            )
            if so_count > 0:
                print(f"[*] injected {so_count} native libraries from shell apk")
            else:
                print("[!] no native libraries found in shell apk (Java-only fallback)")

        # Prune ABI dirs not in target list (applies to both shell and pre-existing libs)
        if target_abis:
            lib_root = decoded_dir / "lib"
            if lib_root.is_dir():
                for abi_dir in sorted(lib_root.iterdir()):
                    if abi_dir.is_dir() and abi_dir.name not in target_abis:
                        shutil.rmtree(abi_dir)
                        print(f"[*] pruned non-target ABI: {abi_dir.name}")

        # ── Polymorphic shell generation (Phase 6.2) ──
        poly_pkg_dot: str = SHELL_PKG_DOT  # default: no rename
        proxy_app_class = PROXY_APP_CLASS
        init_provider_class = INIT_PROVIDER_CLASS
        shell_vmp_targets = SHELL_VMP_TARGETS
        shell_class_aliases: dict[str, str] = {}
        shell_method_aliases: dict[str, str] = {}
        shell_field_aliases: dict[str, str] = {}
        native_layer_names = {
            NATIVE_LAYER_CFG_NAME: NATIVE_LAYER_CFG_NAME,
            NATIVE_LAYER_PAYLOAD_NAME: NATIVE_LAYER_PAYLOAD_NAME,
            NATIVE_LAYER_VMP_NAME: NATIVE_LAYER_VMP_NAME,
            NATIVE_LAYER_EXTRACT_NAME: NATIVE_LAYER_EXTRACT_NAME,
            NATIVE_LAYER_SHELL_VMP_NAME: NATIVE_LAYER_SHELL_VMP_NAME,
        }

        if getattr(args, "polymorphic_shell", False):
            new_pkg_slash = generate_polymorphic_package()
            poly_info = apply_polymorphic_shell(
                resolved_shell_dex, decoded_dir, new_pkg_slash,
            )
            poly_pkg_dot = str(poly_info["package_dot"])
            shell_class_aliases = dict(poly_info.get("class_aliases", {}))
            shell_method_aliases = dict(poly_info.get("method_aliases", {}))
            shell_field_aliases = dict(poly_info.get("field_aliases", {}))
            native_layer_names.update(dict(poly_info.get("blob_aliases", {})))
            proxy_app_class = remap_shell_class_name(
                PROXY_APP_CLASS, poly_pkg_dot, shell_class_aliases
            )
            init_provider_class = remap_shell_class_name(
                INIT_PROVIDER_CLASS, poly_pkg_dot, shell_class_aliases
            )
            # Remap L-descriptor class names: Lcom/enko/shell/Foo; → Lcom/xxxxx/yyyy/Foo;
            old_pkg_slash = SHELL_PKG_SLASH              # com/enko/shell
            new_pkg_slash_str = new_pkg_slash             # com/xxxxx/yyyy
            shell_vmp_targets = [
                (
                    remap_shell_descriptor(
                        cls, old_pkg_slash, new_pkg_slash_str, shell_class_aliases
                    ),
                    shell_method_aliases.get(method, method),
                    sig,
                )
                for cls, method, sig in SHELL_VMP_TARGETS
            ]
            security_report["shell_polymorphism"] = {
                "package": poly_pkg_dot,
                "class_alias_count": len(shell_class_aliases),
                "method_alias_count": len(shell_method_aliases),
                "field_alias_count": len(shell_field_aliases),
                "native_layer_name_count": len(
                    [k for k, v in native_layer_names.items() if k != v]
                ),
            }

        # ── Shell DEX VMP self-protection (Phase 6.1) ──
        shell_vmp_blob: bytes | None = None
        shell_vmp_method_info: list[dict[str, Any]] = []
        shell_vmp_required = bool(
            args.commercial_mode
            or (args.risk_policy == "block" and args.risk_profile == "strict")
        )
        if getattr(args, "vmp_shell_dex", False):
            ndk_path_raw = (args.ndk_path or "").strip()
            if not ndk_path_raw:
                raise HardenError(
                    "--ndk-path is required when --vmp-shell-dex is enabled"
                )
            print("[*] shell VMP: compiling shell DEX critical methods...")
            shell_vmp_obfuscation_report: dict[str, Any] = {}
            shell_vmp_blob, shell_vmp_method_info = run_vmp_dex_compilation(
                [resolved_shell_dex],
                shell_vmp_targets,
                fail_open=not shell_vmp_required,
                wipe_insns=True,
                split_prob=args.vmp_dex_split_prob,
                junk_ratio=args.vmp_dex_junk_ratio,
                inline_junk_ratio=args.vmp_dex_inline_junk_ratio,
                obfuscation_report=shell_vmp_obfuscation_report,
            )
            security_report["method_protection"]["vmp_obfuscation"]["shell"] = shell_vmp_obfuscation_report
            if shell_vmp_blob and shell_vmp_method_info:
                print(
                    f"[*] shell VMP: {len(shell_vmp_method_info)} methods compiled, "
                    f"blob {len(shell_vmp_blob)} bytes"
                )
            else:
                print("[!] shell VMP: no target methods compiled (skipping)")
                if shell_vmp_required:
                    raise HardenError(
                        "shell VMP is required for commercial/strict block builds "
                        "but no shell methods were compiled"
                    )
                shell_vmp_blob = None
                shell_vmp_method_info = []

        for dex_file in dex_files:
            dex_file.unlink()
        shutil.copy2(resolved_shell_dex, decoded_dir / "classes.dex")
        shell_dex_sha256 = hashlib.sha256((decoded_dir / "classes.dex").read_bytes()).hexdigest().upper()
        print(f"[*] shell classes.dex injected (sha256={shell_dex_sha256})")
        # ── VMP JNI stub .so generation (before native VMP / SHA) ──
        if vmp_dex_enabled and vmp_method_info:
            packer_dir = str(Path(__file__).resolve().parent)
            if packer_dir not in sys.path:
                sys.path.insert(0, packer_dir)
            from vmp_stub_gen import build_vmp_stubs

            stub_abis = build_vmp_stubs(vmp_method_info, ndk_path_raw, decoded_dir)
            if stub_abis > 0:
                print(f"[*] VMP stub .so compiled for {stub_abis} ABI(s)")
            else:
                msg = "VMP DEX: stub .so compilation failed for all ABIs"
                if args.vmp_dex_fail_open:
                    print(f"[!] {msg}; continue because --vmp-dex-fail-open is set")
                else:
                    raise HardenError(msg)

        if vmp_enabled:
            run_vmp_over_native_libs(
                decoded_dir,
                vmp_command_template,
                vmp_target_libs,
                args.vmp_fail_open,
            )

        # ── Per-APK key: binary-patch libagpcore.so with random key ──
        if use_per_apk_key:
            patched_so_count = patch_per_apk_key_in_so(decoded_dir, payload_key)
            if patched_so_count == 0:
                raise HardenError(
                    "--per-apk-key is enabled but no libagpcore.so found to patch; "
                    "rebuild shell-app or use --no-per-apk-key"
                )
            print(f"[*] per-apk key patched into {patched_so_count} .so file(s)")

        payload_paths = write_native_layer_blob(
            decoded_dir, native_layer_names[NATIVE_LAYER_PAYLOAD_NAME], encrypted_payload
        )
        payload_paths_rel = [str(p.relative_to(decoded_dir)) for p in payload_paths]
        print(f"[*] encrypted payload written to native layer: {payload_paths_rel}")

        # Write extraction blob to native layer.
        if extract_blob:
            extract_paths = write_native_layer_blob(
                decoded_dir, native_layer_names[NATIVE_LAYER_EXTRACT_NAME], extract_blob
            )
            extract_paths_rel = [str(p.relative_to(decoded_dir)) for p in extract_paths]
            print(f"[*] extraction blob written to native layer: {extract_paths_rel}")

        # Write VMP blob to native layer.
        if vmp_dex_blob:
            vmp_blob_paths = write_native_layer_blob(
                decoded_dir, native_layer_names[NATIVE_LAYER_VMP_NAME], vmp_dex_blob
            )
            vmp_blob_rel = [str(p.relative_to(decoded_dir)) for p in vmp_blob_paths]
            print(f"[*] VMP blob written to native layer: {vmp_blob_rel}")

        # Write shell VMP blob to native layer.
        if shell_vmp_blob:
            shell_vmp_paths = write_native_layer_blob(
                decoded_dir, native_layer_names[NATIVE_LAYER_SHELL_VMP_NAME], shell_vmp_blob
            )
            shell_vmp_rel = [str(p.relative_to(decoded_dir)) for p in shell_vmp_paths]
            print(f"[*] shell VMP blob written to native layer: {shell_vmp_rel}")

            # Generate shell VMP JNI stub .so.
            packer_dir = str(Path(__file__).resolve().parent)
            if packer_dir not in sys.path:
                sys.path.insert(0, packer_dir)
            from vmp_stub_gen import build_vmp_stubs

            shell_stub_abis = build_vmp_stubs(
                shell_vmp_method_info, ndk_path_raw, decoded_dir,
                lib_name="libagpshvmp.so"
            )
            if shell_stub_abis > 0:
                print(f"[*] shell VMP stub .so compiled for {shell_stub_abis} ABI(s)")
            else:
                msg = "shell VMP stub .so compilation failed"
                if shell_vmp_required:
                    raise HardenError(msg)
                print(f"[!] {msg} (continuing)")

        security_report["method_protection"]["map"] = build_method_protection_details(
            protection_map_path=protection_map_path,
            extract_methods_path=extract_methods_path,
            vmp_dex_methods_path=vmp_dex_methods_path,
            dex2c_methods_path=dex2c_methods_path,
            auto_protect_report=auto_protect_report,
            extract_spec=extract_spec,
            vmp_spec=vmp_spec,
            dex2c_spec=dex2c_spec,
            vmp_method_info=vmp_method_info,
            shell_vmp_method_info=shell_vmp_method_info,
            extract_compiled_count=extract_compiled_count,
            dex2c_compiled_count=d2c_compiled_count,
        )

        vmp_plaintext_audit = audit_vmp_blob_plaintext(
            decoded_dir,
            payload_method_info=vmp_method_info,
            shell_method_info=shell_vmp_method_info,
            vmp_blob_name=native_layer_names[NATIVE_LAYER_VMP_NAME],
            shell_vmp_blob_name=native_layer_names[NATIVE_LAYER_SHELL_VMP_NAME],
        )
        security_report["method_protection"]["vmp_obfuscation"]["plaintext_audit"] = vmp_plaintext_audit
        vmp_plaintext_required_clean = bool(
            args.commercial_mode
            or (args.risk_profile == "strict" and args.risk_policy == "block")
        )
        security_report["method_protection"]["vmp_obfuscation"][
            "plaintext_audit_required_clean"
        ] = vmp_plaintext_required_clean
        if vmp_plaintext_audit["checked_files"] > 0:
            if vmp_plaintext_audit["hit_count"] == 0:
                print(
                    "[*] VMP plaintext audit: clean "
                    f"({vmp_plaintext_audit['checked_files']} blob file(s) checked)"
                )
            else:
                print(
                    "[!] VMP plaintext audit: "
                    f"{vmp_plaintext_audit['hit_count']} hit(s) in "
                    f"{vmp_plaintext_audit['checked_files']} blob file(s)"
                )
                if vmp_plaintext_required_clean:
                    raise HardenError(
                        "VMP plaintext audit failed in required-clean mode; "
                        "class/method/signature identifiers leaked in VMP blob"
                    )

        patched_manifest = patch_manifest_app(manifest_text, proxy_app_class)
        patched_manifest = ensure_uses_permission(patched_manifest, ACCESS_NETWORK_STATE)
        patched_manifest = patch_manifest_debuggable(patched_manifest, enabled=False)
        patched_manifest = patch_extract_native_libs(patched_manifest)
        patched_manifest = ensure_init_provider(patched_manifest, package_name, init_provider_class)
        manifest_path.write_text(patched_manifest, encoding="utf-8")
        print(f"[*] manifest application replaced with: {proxy_app_class}")
        print(f"[*] manifest permission ensured: {ACCESS_NETWORK_STATE}")
        print("[*] manifest debuggable forced to false")
        print("[*] manifest extractNativeLibs set to true")
        print(f"[*] manifest init provider ensured: {package_name}.enko_init")

        # AI decoy / canary injection (P5-7): static, fake, never referenced by
        # real code. Poisons fully-automated AI reverse pipelines.
        if args.ai_decoy:
            packer_dir = str(Path(__file__).resolve().parent)
            if packer_dir not in sys.path:
                sys.path.insert(0, packer_dir)
            from ai_decoy import inject_ai_decoys

            decoy_report = inject_ai_decoys(decoded_dir, build_id, seed=None)
            security_report["ai_decoy"] = decoy_report
            print(
                f"[*] AI decoy injected: {decoy_report['injected_count']} artifact(s), "
                f"canary={decoy_report['canary']}"
            )
        else:
            security_report["ai_decoy"] = {"enabled": False}

        native_libs_sha256 = compute_native_libs_sha256(decoded_dir)
        cfg_paths = write_runtime_config(
            decoded_dir,
            original_app,
            payload_compression,
            package_name,
            sign_cert_sha256,
            args.risk_policy,
            args.risk_profile,
            args.block_proxy_vpn,
            detect_root=args.detect_root,
            detect_emulator=args.detect_emulator,
            protect_dex_pages=args.protect_dex_pages,
            vmp_dex_enabled=vmp_dex_enabled,
            vmp_vm_tier=effective_vmp_vm_tier,
            extract_enabled=extract_enabled,
            extract_on_demand=bool(args.extract_on_demand),
            dex2c_enabled=dex2c_enabled,
            shell_vmp_enabled=bool(shell_vmp_blob),
            commercial_mode=bool(args.commercial_mode),
            shell_dex_sha256=shell_dex_sha256,
            native_libs_sha256=native_libs_sha256,
            libapp_sha256=str(native_core_profile.get("libapp_sha256", "")),
            libflutter_sha256=str(native_core_profile.get("libflutter_sha256", "")),
            build_id=build_id,
            build_epoch_sec=build_epoch_sec,
            build_version_code=version_code,
            native_cfg_name=native_layer_names[NATIVE_LAYER_CFG_NAME],
        )
        cfg_paths_rel = [str(p.relative_to(decoded_dir)) for p in cfg_paths]
        print(f"[*] runtime config generated in native layer: {cfg_paths_rel} (payload key omitted)")

        _log_step(3, "Rebuild APK")
        configure_apktool_no_compress(decoded_dir)
        run([apktool, "b", str(decoded_dir), "-o", str(unsigned_apk)], label="rebuild")

        if skip_zipalign:
            shutil.copy2(unsigned_apk, aligned_apk)
            print("[!] zipalign skipped (debug mode): using unaligned apk")
        else:
            _log_step(4, "Zipalign")
            run([zipalign, "-f", "-p", "-v", "4", str(unsigned_apk), str(aligned_apk)], label="zipalign")

        if output_apk.exists():
            output_apk.unlink()

        if signing_enabled:
            if not apksigner:
                raise HardenError("apksigner required for signing but not found")
            _log_step(5, "Sign APK")
            run(
                [
                    apksigner,
                    "sign",
                    "--ks",
                    str(keystore),
                    "--ks-key-alias",
                    args.key_alias,
                    "--ks-pass",
                    f"pass:{args.ks_pass}",
                    "--key-pass",
                    f"pass:{args.key_pass}",
                    "--out",
                    str(output_apk),
                    str(aligned_apk),
                ]
            )
            print(f"[ok] hardened & signed apk generated: {output_apk}")
        else:
            shutil.copy2(aligned_apk, output_apk)
            print(f"[ok] hardened unsigned(aligned) apk generated: {output_apk}")
            print("[*] sign it later with your original certificate")

        security_report["output_apk"] = str(output_apk)
        security_report["risk_policy"] = args.risk_policy
        security_report["risk_profile"] = args.risk_profile
        if args.report_json:
            report_path = Path(args.report_json).resolve()
            write_security_report(report_path, security_report)
            print(f"[*] security report written: {report_path}")

        total_elapsed = time.monotonic() - harden_t0
        out_size = output_apk.stat().st_size if output_apk.exists() else 0
        in_size = input_apk.stat().st_size if input_apk.exists() else 0
        print(f"\n{'━' * 50}")
        print("  [ok] Hardening complete!")
        print(f"     Input:  {in_size / 1024 / 1024:.1f} MB → Output: {out_size / 1024 / 1024:.1f} MB")
        print(f"     Time:   {total_elapsed:.1f}s ({total_elapsed / 60:.1f} min)")
        if args.report_json:
            print(f"     Report: {Path(args.report_json).resolve()}")
        print(f"{'━' * 50}")


def build_parser() -> argparse.ArgumentParser:
    epilog = """\
Examples:
  # Basic hardening (default: no in-pipeline signing)
  python harden_apk.py --input-apk app.apk --shell-apk shell.apk --output-apk hardened.apk

  # Commercial release, keep unsigned output and sign later with the original certificate
  python harden_apk.py --input-apk app-signed.apk --shell-apk shell.apk --output-apk hardened-unsigned.apk \\
    --commercial-mode

  # Optional in-pipeline signing, only when this keystore is the app's original signing key
  python harden_apk.py --input-apk app.apk --shell-apk shell.apk --output-apk hardened.apk \\
    --sign --keystore release.jks --ks-pass mypass --key-alias mykey --key-pass mypass

  # With protection map
  python harden_apk.py --input-apk app.apk --shell-apk shell.apk --output-apk hardened.apk \\
    --protection-map protect.txt

Exit codes: 0=success, 2=known error, 3=unexpected error, 130=interrupted
"""
    p = argparse.ArgumentParser(
        description="Enko APK Hardening Pipeline — apply shell protection, VMP, method extraction, and encryption.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--input-apk", required=True, help="path to original apk")
    shell_group = p.add_mutually_exclusive_group(required=True)
    shell_group.add_argument("--shell-dex", default="", help="path to shell classes.dex")
    shell_group.add_argument("--shell-apk", default="", help="path to shell apk (extract classes.dex automatically)")
    p.add_argument("--output-apk", required=True, help="output hardened apk path")
    p.add_argument("--keystore", default="", help="keystore path (optional)")
    p.add_argument("--ks-pass", default="", help="keystore password (optional)")
    p.add_argument("--key-alias", default="", help="key alias (optional)")
    p.add_argument("--key-pass", default="", help="key password (optional)")
    sign_group = p.add_mutually_exclusive_group()
    sign_group.add_argument(
        "--skip-sign",
        dest="skip_sign",
        action="store_true",
        default=True,
        help="skip in-pipeline signing; output remains unsigned/aligned for later signing with the original cert",
    )
    sign_group.add_argument(
        "--sign",
        dest="skip_sign",
        action="store_false",
        help="sign in pipeline with --keystore/--ks-pass/--key-alias/--key-pass; use only with the app's original cert",
    )
    p.add_argument(
        "--payload-key-hex",
        default="",
        help="optional 32/64-hex key consistency check; if set, must match native embedded payload key",
    )
    p.add_argument(
        "--payload-compress",
        default="auto",
        choices=["auto", "zlib", "none"],
        help="compress packaged dex before encryption",
    )
    p.add_argument(
        "--sign-cert-sha256",
        default="",
        help="expected original signing cert SHA-256 (optional; auto from keystore or signed input APK if omitted)",
    )
    p.add_argument(
        "--risk-policy",
        default="block",
        choices=["block", "degrade", "warn", "log", "off"],
        help="risk environment handling policy at runtime: block=terminate, degrade=disable sensitive features, warn=show dialog, log=silent report, off=skip detection",
    )
    p.add_argument(
        "--risk-profile",
        default="balanced",
        choices=["strict", "balanced", "compat"],
        help="risk scoring profile for environment checks (strict/balanced/compat)",
    )
    proxy_group = p.add_mutually_exclusive_group()
    proxy_group.add_argument(
        "--block-proxy-vpn",
        dest="block_proxy_vpn",
        action="store_true",
        help="treat proxy/vpn/user-ca as high risk",
    )
    proxy_group.add_argument(
        "--allow-proxy-vpn",
        dest="block_proxy_vpn",
        action="store_false",
        help="allow proxy/vpn/user-ca",
    )
    p.set_defaults(block_proxy_vpn=True)
    emulator_group = p.add_mutually_exclusive_group()
    emulator_group.add_argument(
        "--detect-emulator",
        dest="detect_emulator",
        action="store_true",
        help="include emulator signal in runtime risk evaluation (default)",
    )
    emulator_group.add_argument(
        "--disable-emulator-check",
        dest="detect_emulator",
        action="store_false",
        help="do not add emulator-environment signal to risk reasons",
    )
    p.set_defaults(detect_emulator=True)
    dex_protect_group = p.add_mutually_exclusive_group()
    dex_protect_group.add_argument(
        "--protect-dex-pages",
        dest="protect_dex_pages",
        action="store_true",
        help="seal in-memory DEX DirectByteBuffer pages with mprotect(PROT_NONE) after load (default)",
    )
    dex_protect_group.add_argument(
        "--no-protect-dex-pages",
        dest="protect_dex_pages",
        action="store_false",
        help="leave in-memory DEX pages readable after load for maximum compatibility/debugging",
    )
    p.set_defaults(protect_dex_pages=True)
    root_group = p.add_mutually_exclusive_group()
    root_group.add_argument(
        "--detect-root",
        dest="detect_root",
        action="store_true",
        help="include root signal in runtime risk evaluation (default)",
    )
    root_group.add_argument(
        "--disable-root-check",
        dest="detect_root",
        action="store_false",
        help="do not add root-environment signal to risk reasons",
    )
    p.set_defaults(detect_root=True)
    p.add_argument(
        "--per-apk-key",
        dest="per_apk_key",
        action="store_true",
        default=True,
        help="generate per-APK random payload key (default, recommended)",
    )
    p.add_argument(
        "--no-per-apk-key",
        dest="per_apk_key",
        action="store_false",
        help="use legacy shared payload key (all APKs share same key)",
    )
    p.add_argument(
        "--native-key-obfuscation",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,  # deprecated
    )
    p.add_argument(
        "--no-native-key-obfuscation",
        dest="native_key_obfuscation",
        action="store_false",
        help=argparse.SUPPRESS,  # deprecated
    )
    p.add_argument(
        "--vmp-command-template",
        default="",
        help=(
            "optional command template to virtualize native libs; placeholders: "
            "{input} {output} {abi} {lib}"
        ),
    )
    p.add_argument(
        "--vmp-target-libs",
        default=DEFAULT_VMP_TARGET_LIB,
        help="comma-separated native library filenames to process when VMP is enabled",
    )
    p.add_argument(
        "--vmp-fail-open",
        action="store_true",
        help="continue packaging even if VMP command fails",
    )
    p.add_argument(
        "--extract-methods",
        default="",
        help="path to text file listing methods for instruction extraction (Phase 4.1)",
    )
    p.add_argument(
        "--extract-fail-open",
        action="store_true",
        help="continue packaging even if method extraction fails",
    )
    extract_restore_group = p.add_mutually_exclusive_group()
    extract_restore_group.add_argument(
        "--extract-on-demand",
        dest="extract_on_demand",
        action="store_true",
        help="restore extracted methods per class while loading (default for strict/balanced profiles)",
    )
    extract_restore_group.add_argument(
        "--extract-bulk-restore",
        dest="extract_on_demand",
        action="store_false",
        help="restore all extracted methods before creating the payload classloader (default for compat profile)",
    )
    p.set_defaults(extract_on_demand=None)
    p.add_argument(
        "--vmp-dex-methods",
        default="",
        help="path to text file listing methods to VMP-protect (Dalvik bytecode level)",
    )
    p.add_argument(
        "--vmp-dex-fail-open",
        action="store_true",
        help="continue packaging even if Dalvik VMP compilation fails",
    )
    p.add_argument(
        "--no-vmp-dex-wipe-insns",
        dest="vmp_dex_wipe_insns",
        action="store_false",
        default=True,
        help=(
            "do not wipe the original Dalvik insns bytes for methods patched to native via VMP "
            "(default is to wipe, which removes recoverable bytecode from the DEX)"
        ),
    )
    p.add_argument(
        "--vmp-dex-obfuscation-preset",
        default="light",
        choices=sorted(VMP_OBFUSCATION_PRESETS),
        help=(
            "VMP obfuscation preset for payload and shell VMP: "
            "light is the default; stable keeps split/junk off"
        ),
    )
    p.add_argument(
        "--vmp-vm-tier",
        default="auto",
        choices=["auto", *sorted(VMP_VM_TIERS)],
        help=(
            "VMP interpreter core tier: auto resolves from risk/auto-protect profile; "
            "compat favors business compatibility, light is balanced, strong enables "
            "the hardened runtime tier gates"
        ),
    )
    p.add_argument(
        "--vmp-dex-split-prob",
        type=float,
        default=None,
        help=(
            "probability for eligible VMP instructions to split into equivalent "
            "multi-instruction sequences (0.0-1.0; overrides preset value)"
        ),
    )
    p.add_argument(
        "--vmp-dex-junk-ratio",
        type=float,
        default=None,
        help=(
            "ratio of GOTO-guarded VMP junk blocks to insert "
            "(0.0-1.0; overrides preset value)"
        ),
    )
    p.add_argument(
        "--vmp-dex-inline-junk-ratio",
        type=float,
        default=None,
        help=(
            "ratio of inline opaque-predicate VMP junk to insert "
            "(0.0-1.0; overrides preset value)"
        ),
    )
    p.add_argument(
        "--dex2c-methods",
        default="",
        help="path to text file listing methods for DEX2C compilation (Phase 4.2)",
    )
    p.add_argument(
        "--dex2c-fail-open",
        action="store_true",
        help="continue packaging even if DEX2C compilation fails",
    )
    dex2c_ollvm_group = p.add_mutually_exclusive_group()
    dex2c_ollvm_group.add_argument(
        "--dex2c-ollvm",
        dest="dex2c_ollvm",
        action="store_true",
        help="compile libagpjnix.so with Hikari/OLLVM when DEX2C is enabled (default)",
    )
    dex2c_ollvm_group.add_argument(
        "--no-dex2c-ollvm",
        dest="dex2c_ollvm",
        action="store_false",
        help="compile libagpjnix.so with normal NDK clang",
    )
    p.set_defaults(dex2c_ollvm=True)
    p.add_argument(
        "--dex2c-ollvm-clang",
        default=os.environ.get(
            "ENKO_OLLVM_CLANG",
            "/opt/enko/toolchains/hikari-llvm19/install/bin/clang",
        ),
        help="path to Hikari/OLLVM clang for DEX2C libagpjnix.so",
    )
    p.add_argument(
        "--dex2c-ollvm-required",
        action="store_true",
        default=False,
        help="fail DEX2C compilation instead of falling back to normal NDK clang if Hikari/OLLVM is unavailable",
    )
    p.add_argument(
        "--ndk-path",
        default="",
        help="path to Android NDK (required for --vmp-dex-methods and --dex2c-methods)",
    )
    p.add_argument(
        "--vmp-shell-dex",
        action="store_true",
        default=False,
        help=(
            "apply VMP protection to shell DEX critical methods "
            "(ProxyApplication.installPayload, enforceRiskPolicy, etc.). "
            "Requires --ndk-path."
        ),
    )
    p.add_argument(
        "--polymorphic-shell",
        action="store_true",
        default=False,
        help=(
            "randomize shell package, high-signal shell class/method names, "
            "and native-layer blob filenames per build so generic unpackers "
            "that match com.enko.shell/libvt*.so break"
        ),
    )
    decoy_group = p.add_mutually_exclusive_group()
    decoy_group.add_argument(
        "--ai-decoy",
        dest="ai_decoy",
        action="store_true",
        help=(
            "inject fake static decoy artifacts (fake keys/flags/endpoints) and "
            "a per-build canary token to poison fully-automated AI reverse "
            "pipelines (unpack->jadx/strings->LLM). Decoys are fake and never "
            "referenced by real code. Auto-enabled in --commercial-mode."
        ),
    )
    decoy_group.add_argument(
        "--no-ai-decoy",
        dest="ai_decoy",
        action="store_false",
        help="disable AI decoy/canary injection",
    )
    p.set_defaults(ai_decoy=False)
    p.add_argument(
        "--protection-map",
        default="",
        help=(
            "path to protection-map config file. Format: one line per entry, "
            "'<method_spec> <level>'. Levels: 0=none, 1=extract, 2=vmp, 3=dex2c. "
            "Example: 'Lcom/example/Crypto;->encrypt 2'"
        ),
    )
    p.add_argument(
        "--no-auto-protect",
        action="store_true",
        default=False,
        help=(
            "skip automatic protection-map generation. By default, when no --protection-map, "
            "--vmp-dex-methods, --extract-methods, or --dex2c-methods are provided, "
            "the packer auto-selects methods using local heuristics"
        ),
    )
    p.add_argument(
        "--auto-protect-profile",
        default="balanced",
        choices=["compat", "balanced", "strong", "extreme"],
        help=(
            "smart auto-protect selection profile: compat=compatibility first, "
            "balanced=default, strong=more VMP/DEX2C, extreme=max coverage"
        ),
    )
    p.add_argument(
        "--min-extract-count",
        type=int,
        default=0,
        help="minimum extracted method count required; fail build if lower",
    )
    p.add_argument(
        "--min-vmp-dex-count",
        type=int,
        default=0,
        help="minimum VMP DEX compiled method count required; fail build if lower",
    )
    p.add_argument(
        "--min-dex2c-count",
        type=int,
        default=0,
        help="minimum DEX2C compiled method count required; fail build if lower",
    )
    p.add_argument(
        "--min-security-score",
        type=int,
        default=0,
        help=(
            "minimum security score required (0-100). "
            "If non-zero and below threshold, packaging fails."
        ),
    )
    p.add_argument(
        "--report-json",
        default="",
        help="optional output path for hardening security report (JSON)",
    )
    p.add_argument(
        "--release-manifest",
        default="",
        help=(
            "optional release metadata JSON with engine/rules/policy/map/schema versions; "
            "if provided, validated and embedded into report JSON"
        ),
    )
    p.add_argument(
        "--flutter-mode",
        action="store_true",
        help="treat target APK as Flutter/native-core heavy; adds Flutter-native integrity reporting",
    )
    p.add_argument(
        "--commercial-mode",
        action="store_true",
        help=(
            "enforce commercial hardening baseline: strict/block policy, "
            "runtime signature pin + zipalign required, per-APK key required, fail-open flags forbidden, "
            "and default min-security-score=90"
        ),
    )
    p.add_argument(
        "--allow-weak-release",
        action="store_true",
        help=(
            "allow packaging when release obfuscation cannot be verified "
            "(maintenance/debug escape hatch)"
        ),
    )
    p.add_argument(
        "--skip-zipalign",
        action="store_true",
        help="skip zipalign step (debug/testing only)",
    )
    p.add_argument("--apktool", default="", help="apktool binary path (optional)")
    p.add_argument("--zipalign", default="", help="zipalign binary path (optional)")
    p.add_argument("--apksigner", default="", help="apksigner binary path (optional)")
    p.add_argument(
        "--target-abis",
        default="",
        help=(
            "comma-separated list of target ABIs to build for "
            "(e.g. arm64-v8a,armeabi-v7a). "
            "If empty, auto-detect from input APK or use all."
        ),
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_CMD_TIMEOUT,
        help=f"timeout in seconds for each external tool call (default: {DEFAULT_CMD_TIMEOUT})",
    )
    return p


def main() -> int:
    """Entry point.

    Exit codes:
        0 — success
        2 — known error (HardenError): bad arguments, missing files, validation failure
        3 — unexpected error: bug or unhandled exception (includes traceback)
    """
    parser = build_parser()
    args = parser.parse_args()

    # --- Early validation: check critical paths before heavy work ---
    _early_validate(args)

    try:
        harden(args)
        return 0
    except HardenError as e:
        print(f"\n[error] {e}", file=sys.stderr)
        print("[hint] exit code 2 = known error. Check arguments and file paths.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[interrupted] hardening cancelled by user.", file=sys.stderr)
        return 130
    except Exception as e:
        import traceback
        print(f"\n[error] unexpected: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        print("[hint] exit code 3 = unexpected error. Please report this as a bug.", file=sys.stderr)
        return 3


def _early_validate(args: argparse.Namespace) -> None:
    """Validate file paths and tools early, before expensive operations."""
    input_path = Path(args.input_apk)
    if not input_path.exists():
        raise HardenError(f"input APK not found: {input_path}  (check the --input-apk path)")
    if not input_path.suffix == ".apk":
        print(f"[warning] input file does not end in .apk: {input_path.name}", file=sys.stderr)
    if args.shell_apk and not Path(args.shell_apk).exists():
        raise HardenError(f"shell APK not found: {args.shell_apk}  (build the shell app first: ./gradlew :app:assembleRelease)")
    if args.shell_dex and not Path(args.shell_dex).exists():
        raise HardenError(f"shell DEX not found: {args.shell_dex}")
    if args.keystore and not Path(args.keystore).exists():
        raise HardenError(f"keystore not found: {args.keystore}  (check the --keystore path)")
    if args.protection_map and not Path(args.protection_map).exists():
        raise HardenError(f"protection map not found: {args.protection_map}")
    output_dir = Path(args.output_apk).parent
    if not output_dir.exists():
        raise HardenError(f"output directory does not exist: {output_dir}  (create it with: mkdir -p {output_dir})")
    if args.ndk_path and not Path(args.ndk_path).exists():
        raise HardenError(f"NDK path not found: {args.ndk_path}  (install NDK or check --ndk-path)")
    if args.ndk_path:
        ndk_tc = Path(args.ndk_path) / "toolchains"
        if not ndk_tc.exists():
            raise HardenError(f"NDK path invalid (no toolchains/ dir): {args.ndk_path}")


if __name__ == "__main__":
    raise SystemExit(main())
