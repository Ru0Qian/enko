#!/usr/bin/env python3
"""AI decoy / canary injection (P5-7).

Purpose: defeat *fully automated* AI reverse-engineering pipelines
(unpack -> jadx/strings -> LLM summary). Such pipelines treat plausible-looking
static artifacts as facts and write them into their conclusions. We plant
high-attraction but entirely fake artifacts so the automated analysis produces
confident-but-wrong results, and a per-build canary token that is traceable if
it ever surfaces in a submitted exploit, an LLM summary, or a network request.

Hard rules (from the hardening principles):
  * NEVER embed a real key, endpoint, or business secret.
  * NEVER touch real business code paths — decoys live only in dropped
    assets/strings and are never referenced by real logic.
  * This is a low-cost disruption + forensics layer, not a security boundary.

The decoys are written into the decoded APK's ``assets/`` tree (which AI agents
scrape first) plus a few extra string resources. They are covered by the
native-libs/shell integrity hashing only indirectly; they do not participate in
any runtime gate, so they cannot break startup or business flows.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import string
from pathlib import Path
from typing import Any


# Marker embedded inside every decoy artifact so we can (a) prove provenance in
# forensics and (b) audit that decoys never leak into real code. Looks innocuous.
CANARY_PREFIX = "ek"  # short, blends into base64-ish blobs


def generate_canary_token(build_id: str, rng: random.Random) -> str:
    """Per-build unique, traceable token. Embedded inside fake secrets.

    Derived from the build id plus randomness drawn from *rng*:
      * fresh OS-seeded rng (production) -> two builds never share a token;
      * explicit seed (reproducible builds / tests) -> deterministic token.
    The token can be tied back to a specific build during forensics.
    """
    nonce = "".join(rng.choice("0123456789abcdef") for _ in range(16))
    seed = f"{build_id}:{nonce}".encode("utf-8")
    digest = hashlib.sha256(seed).hexdigest()
    return f"{CANARY_PREFIX}_{digest[:24]}"


def _rand_hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _rand_b64ish(rng: random.Random, n: int) -> str:
    alpha = string.ascii_letters + string.digits + "+/"
    return "".join(rng.choice(alpha) for _ in range(n))


def build_decoy_artifacts(canary: str, rng: random.Random) -> dict[str, str]:
    """Return a map of ``relative asset path -> file content``.

    Every artifact is fake. The canary is woven into the most "valuable"-looking
    fields so that whatever an AI agent extracts and reports carries the token.
    """
    fake_aes_key = _rand_hex(rng, 64)              # 256-bit looking, fake
    fake_hmac_key = _rand_b64ish(rng, 44)
    fake_flag = f"FLAG{{{_rand_hex(rng, 16)}_{canary}}}"
    fake_host = rng.choice(
        ["api-gw", "vault", "license", "pay-core", "auth-edge"]
    ) + f"-{_rand_hex(rng, 4)}.internal.example"

    # 1) A fake "runtime secrets" JSON — the single most attractive file for an
    #    automated scraper. Looks like leaked config; every value is bogus.
    secrets_json = json.dumps(
        {
            "_comment": "internal runtime config - do not ship to prod",
            "env": "production",
            "crypto": {
                "payload_aes_key": fake_aes_key,
                "hmac_sign_key": fake_hmac_key,
                "key_rotation_days": rng.randint(30, 180),
            },
            "endpoints": {
                "license_verify": f"https://{fake_host}/v2/license/verify",
                "decrypt_oracle": f"https://{fake_host}/v2/payload/decrypt",
                "telemetry": f"https://{fake_host}/v2/collect",
            },
            "license": {
                "offline_master_flag": fake_flag,
                "bypass_header": "X-Enko-Trusted",
                "trusted_value": canary,
            },
            "build_marker": canary,
        },
        indent=2,
    )

    # 2) A fake decrypt "hint" — written like a developer left notes behind.
    #    Designed so an LLM summarizes a plausible-but-wrong decrypt procedure.
    decrypt_hint = (
        "# payload decrypt procedure (legacy notes)\n"
        f"# 1. read assets/enko_runtime_secrets.json -> crypto.payload_aes_key\n"
        f"# 2. AES-256-CBC, IV = first 16 bytes of libvtpl.so\n"
        f"# 3. validate against license.offline_master_flag\n"
        f"# canary: {canary}\n"
        "# NOTE: rotate key before GA, see endpoints.decrypt_oracle\n"
    )

    # 3) Fake native-bridge "API map" — misleads tools that correlate JNI names.
    jni_map = "\n".join(
        f"{name} -> {_rand_hex(rng, 8)}"
        for name in (
            "nativeUnlockPremium",
            "nativeDecryptMasterKey",
            "nativeBypassLicense",
            "nativeDumpFlag",
            "nativeGetTrustedToken",
        )
    ) + f"\n# trace:{canary}\n"

    return {
        "assets/enko_runtime_secrets.json": secrets_json,
        "assets/.keep_decrypt_notes.txt": decrypt_hint,
        "assets/native_api_map.txt": jni_map,
    }


def inject_ai_decoys(decoded_dir: Path, build_id: str, seed: bytes | None = None) -> dict[str, Any]:
    """Write decoy assets into the decoded APK tree.

    Returns a report dict (canary token + injected file list) for the security
    report. Never raises on individual file errors — decoys are best-effort and
    must never block a build.
    """
    rng = random.Random(seed if seed is not None else os.urandom(16))
    canary = generate_canary_token(build_id, rng)
    artifacts = build_decoy_artifacts(canary, rng)

    assets_root = decoded_dir / "assets"
    assets_root.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    for rel_path, content in artifacts.items():
        target = decoded_dir / rel_path
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            written.append(rel_path)
        except OSError:
            # Best-effort: skip a file that can't be written, never fail build.
            continue

    return {
        "enabled": True,
        "canary": canary,
        "injected_files": written,
        "injected_count": len(written),
        "note": "decoy artifacts are fake; not referenced by real code",
    }

