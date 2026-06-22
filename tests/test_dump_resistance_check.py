"""Offline tests for tools/dump_resistance_check.py.

The check tool itself drives a live emulator (run by the user manually or in a
self-hosted CI). These tests cover the parsing/decision logic — what counts
as a PASS or FAIL — so refactors don't silently break the assertions.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import dump_resistance_check as drc  # noqa: E402


def _mock(rc: int, out: str):
    def fake(adb: str, args: list[str], *, timeout: int = 20):
        return rc, out
    return fake


def test_dumpable_zero_explicit_pass() -> None:
    with patch.object(drc, "run_adb", _mock(0, "Name:\t x\nDumpable:\t0\n")):
        ok, msg = drc.check_dumpable_zero("adb", 1234)
    assert ok and "Dumpable=0" in msg


def test_dumpable_zero_filtered_is_pass() -> None:
    """Modern Android filters Dumpable: from non-root reads — must still PASS."""
    with patch.object(drc, "run_adb", _mock(0, "Name:\t x\nState: R\n")):
        ok, msg = drc.check_dumpable_zero("adb", 1234)
    assert ok and "filtered" in msg.lower()


def test_dumpable_one_is_fail() -> None:
    with patch.object(drc, "run_adb", _mock(0, "Dumpable:\t1\n")):
        ok, _ = drc.check_dumpable_zero("adb", 1234)
    assert not ok


def test_proc_mem_permission_denied_is_pass() -> None:
    with patch.object(drc, "run_adb", _mock(
            0, "dd: /proc/1234/mem: Permission denied\nRC=1\n")):
        ok, msg = drc.check_proc_mem_blocked("adb", 1234)
    assert ok and "denied" in msg.lower()


def test_proc_mem_readable_is_fail() -> None:
    with patch.object(drc, "run_adb", _mock(0, "RC=0\n")):
        ok, _ = drc.check_proc_mem_blocked("adb", 1234)
    assert not ok


def test_dex_pages_sealed_pass() -> None:
    log = ("foo\n"
           "EnkoShell: DEX regions sealed: 2/2\n"
           "more lines\n")
    with patch.object(drc, "run_adb", _mock(0, log)):
        ok, msg = drc.check_dex_pages_sealed("adb")
    assert ok and "2/2" in msg


def test_dex_pages_partial_seal_fail() -> None:
    with patch.object(drc, "run_adb", _mock(
            0, "EnkoShell: DEX regions sealed: 1/3\n")):
        ok, _ = drc.check_dex_pages_sealed("adb")
    assert not ok


def test_dex_pages_no_log_fail() -> None:
    with patch.object(drc, "run_adb", _mock(0, "nothing relevant\n")):
        ok, _ = drc.check_dex_pages_sealed("adb")
    assert not ok


def test_loose_dex_visible_in_maps_fail() -> None:
    maps = ("12345-67890 r-xp /data/app/x/base.apk\n"
            "abcdef-fedcba r--p /data/local/tmp/classes.dex\n")
    with patch.object(drc, "run_adb", _mock(0, maps)):
        ok, msg = drc.check_maps_dex_not_readable("adb", 1234)
    assert not ok
    assert "classes.dex" in msg


def test_maps_only_base_apk_is_pass() -> None:
    maps = "12345-67890 r-xp /data/app/x/base.apk\n"
    with patch.object(drc, "run_adb", _mock(0, maps)):
        ok, _ = drc.check_maps_dex_not_readable("adb", 1234)
    assert ok


def test_maps_unreadable_is_pass() -> None:
    """Permission denied on maps is acceptable for non-root scrapers."""
    with patch.object(drc, "run_adb", _mock(1, "Permission denied")):
        ok, msg = drc.check_maps_dex_not_readable("adb", 1234)
    assert ok and "unreadable" in msg
