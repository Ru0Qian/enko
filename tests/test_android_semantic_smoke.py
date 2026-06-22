from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_APK = REPO_ROOT / "test_apks" / "small_app" / "app" / "build" / "outputs" / "apk" / "debug" / "app-hardened-current.apk"


@pytest.mark.skipif(
    os.environ.get("ENKO_RUN_ANDROID_E2E") != "1",
    reason="set ENKO_RUN_ANDROID_E2E=1 to run emulator/device semantic smoke tests",
)
def test_small_hardened_flag_semantics_on_android() -> None:
    apk = Path(os.environ.get("ENKO_E2E_APK", str(DEFAULT_APK))).resolve()
    cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "android_semantic_smoke.py"),
        "--apk",
        str(apk),
    ]
    package = os.environ.get("ENKO_E2E_PACKAGE")
    if package:
        cmd.extend(["--package", package])
    activity = os.environ.get("ENKO_E2E_ACTIVITY")
    if activity:
        cmd.extend(["--activity", activity])
    adb = os.environ.get("ADB")
    if adb:
        cmd.extend(["--adb", adb])

    result = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=int(os.environ.get("ENKO_E2E_TIMEOUT", "180")),
        errors="replace",
    )
    assert result.returncode == 0, result.stdout
