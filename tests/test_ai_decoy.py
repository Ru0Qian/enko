"""Tests for AI decoy / canary injection (P5-7).

Verifies: canary uniqueness + traceability, decoy artifact generation, that
the canary is woven into the high-value fake fields, that no decoy is wired
into real code paths, and that injection writes the expected asset files.
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKER = ROOT / "packer"
if str(PACKER) not in sys.path:
    sys.path.insert(0, str(PACKER))

import ai_decoy  # noqa: E402


def test_canary_unique_per_build() -> None:
    a = ai_decoy.generate_canary_token("build-1", random.Random(1))
    b = ai_decoy.generate_canary_token("build-1", random.Random(2))
    c = ai_decoy.generate_canary_token("build-2", random.Random(1))
    assert a != b, "same build id with different rng must differ (fresh entropy)"
    assert a != c
    assert a.startswith(ai_decoy.CANARY_PREFIX + "_")
    assert len(a) > len(ai_decoy.CANARY_PREFIX) + 1


def test_decoy_artifacts_contain_canary() -> None:
    canary = ai_decoy.generate_canary_token("b", random.Random(0))
    artifacts = ai_decoy.build_decoy_artifacts(canary, random.Random(0))
    # All three decoy files present.
    assert "assets/enko_runtime_secrets.json" in artifacts
    assert "assets/.keep_decrypt_notes.txt" in artifacts
    assert "assets/native_api_map.txt" in artifacts
    # The canary is woven into every artifact so any leaked summary carries it.
    for content in artifacts.values():
        assert canary in content


def test_decoy_secrets_json_is_valid_and_fake() -> None:
    canary = ai_decoy.generate_canary_token("b", random.Random(5))
    artifacts = ai_decoy.build_decoy_artifacts(canary, random.Random(5))
    parsed = json.loads(artifacts["assets/enko_runtime_secrets.json"])
    # High-value-looking but fake fields exist.
    assert "crypto" in parsed and "payload_aes_key" in parsed["crypto"]
    assert "endpoints" in parsed
    assert parsed["build_marker"] == canary
    # Fake host points at a non-routable example domain (never a real endpoint).
    for url in parsed["endpoints"].values():
        assert ".internal.example" in url


def test_inject_writes_assets(tmp_path: Path) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    report = ai_decoy.inject_ai_decoys(decoded, "build-xyz", seed=b"\x01\x02\x03\x04")
    assert report["enabled"] is True
    assert report["injected_count"] == len(report["injected_files"])
    assert report["injected_count"] >= 3
    # Files actually written under assets/.
    for rel in report["injected_files"]:
        assert (decoded / rel).exists()
        assert rel.startswith("assets/")
    # Canary present and traceable.
    assert report["canary"].startswith(ai_decoy.CANARY_PREFIX + "_")
    secrets_file = decoded / "assets/enko_runtime_secrets.json"
    assert report["canary"] in secrets_file.read_text(encoding="utf-8")


def test_inject_deterministic_with_seed(tmp_path: Path) -> None:
    d1 = tmp_path / "a"; d1.mkdir()
    d2 = tmp_path / "b"; d2.mkdir()
    r1 = ai_decoy.inject_ai_decoys(d1, "same-build", seed=b"seed-1234567890")
    r2 = ai_decoy.inject_ai_decoys(d2, "same-build", seed=b"seed-1234567890")
    # Same seed -> reproducible decoy content (build reproducibility).
    assert r1["canary"] == r2["canary"]
    assert (d1 / "assets/enko_runtime_secrets.json").read_text(encoding="utf-8") == \
           (d2 / "assets/enko_runtime_secrets.json").read_text(encoding="utf-8")
