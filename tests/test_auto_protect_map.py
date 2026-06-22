import sys
from pathlib import Path


PACKER = Path(__file__).resolve().parent.parent / "packer"
if str(PACKER) not in sys.path:
    sys.path.insert(0, str(PACKER))

from auto_protect_map import (  # noqa: E402
    ACC_SYNCHRONIZED,
    AUTO_PROTECT_PROFILES,
    MethodRecord,
    recommend_level_for_method,
    resolve_auto_protect_profile,
    score_for_dex2c,
    score_for_extract,
    score_for_vmp,
    _scan_instruction_shape,
)


def _rec(
    class_desc: str,
    method_name: str,
    signature: str = "()V",
    *,
    code_bytes: int = 160,
    access_flags: int = 0,
    has_monitor: bool = False,
    has_switch: bool = False,
    has_fill_array_data: bool = False,
    invoke_count: int = 0,
) -> MethodRecord:
    return MethodRecord(
        dex_name="classes.dex",
        class_desc=class_desc,
        method_name=method_name,
        signature=signature,
        access_flags=access_flags,
        code_bytes=code_bytes,
        registers_size=4,
        outs_size=2,
        tries_size=0,
        has_monitor=has_monitor,
        has_switch=has_switch,
        has_fill_array_data=has_fill_array_data,
        invoke_count=invoke_count,
    )


def _insns(*units: int) -> bytes:
    return b"".join(int(u & 0xFFFF).to_bytes(2, "little") for u in units)


def test_instruction_shape_scanner_detects_switch_and_skips_payload_data():
    # sparse-switch v2,+4; return-void; payload data contains low bytes that
    # should not be counted as real invoke/monitor opcodes.
    has_monitor, has_switch, has_fill_array_data, invoke_count = _scan_instruction_shape(
        _insns(
            0x022C, 0x0004, 0x0000,
            0x000E,
            0x0200, 0x0002,
            0x006E, 0x0000,
            0x001D, 0x0000,
            0x0003, 0x0000,
            0x0003, 0x0000,
        )
    )

    assert has_switch is True
    assert has_monitor is False
    assert has_fill_array_data is False
    assert invoke_count == 0


def test_ui_lifecycle_callback_prefers_extract_over_vmp_or_dex2c():
    rec = _rec(
        "Lcom/example/app/MainActivity;",
        "onClick",
        "(Landroid/view/View;)V",
    )

    extract = score_for_extract(rec)
    vmp = score_for_vmp(rec)
    dex2c = score_for_dex2c(rec)
    level, phase, _score, reasons, _phase_scores = recommend_level_for_method(rec)

    assert "ui-lifecycle-or-hot-callback" in extract.reasons
    assert vmp.score < extract.score
    assert dex2c.score < extract.score
    assert (level, phase) == (1, "extract")
    assert "ui-lifecycle-or-hot-callback" in reasons


def test_reflection_heavy_gate_is_not_auto_promoted_to_dex2c():
    rec = _rec(
        "Lcom/example/app/SecurityGate;",
        "verifyWithReflection",
        "(Ljava/lang/Class;Ljava/lang/String;)Z",
        code_bytes=260,
    )

    extract = score_for_extract(rec)
    dex2c = score_for_dex2c(rec)
    level, phase, _score, reasons, _phase_scores = recommend_level_for_method(rec)

    assert "reflection-risk" in dex2c.reasons
    assert extract.score > dex2c.score
    assert (level, phase) == (1, "extract")
    assert "reflection-risk" in reasons


def test_synchronized_or_monitor_methods_are_demoted_from_strong_phases():
    rec = _rec(
        "Lcom/example/app/SessionManager;",
        "verifySession",
        "()Z",
        access_flags=ACC_SYNCHRONIZED,
        has_monitor=True,
    )

    extract = score_for_extract(rec)
    vmp = score_for_vmp(rec)
    dex2c = score_for_dex2c(rec)

    assert "synchronized-or-monitor" in vmp.reasons
    assert "synchronized-or-monitor" in dex2c.reasons
    assert extract.score > vmp.score
    assert extract.score > dex2c.score


def test_switch_heavy_gate_prefers_extract_to_keep_vmp_semantics_safe():
    rec = _rec(
        "Lcom/example/app/LicenseGate;",
        "verifySwitchMatrix",
        "()Z",
        code_bytes=420,
        has_switch=True,
    )

    extract = score_for_extract(rec)
    vmp = score_for_vmp(rec)
    dex2c = score_for_dex2c(rec)
    level, phase, _score, reasons, _phase_scores = recommend_level_for_method(rec)

    assert "vmp-structural-risk" in vmp.reasons
    assert "vmp-structural-risk" in dex2c.reasons
    assert extract.score > vmp.score
    assert extract.score > dex2c.score
    assert (level, phase) == (1, "extract")
    assert "vmp-structural-risk" in reasons


def test_try_catch_and_fill_array_payloads_are_kept_out_of_heavy_phases():
    rec = _rec(
        "Lcom/example/app/FlagDecoder;",
        "decodeFlagTable",
        "()[B",
        code_bytes=360,
        has_fill_array_data=True,
    )
    rec.tries_size = 1

    extract = score_for_extract(rec)
    vmp = score_for_vmp(rec)
    dex2c = score_for_dex2c(rec)
    level, phase, _score, reasons, _phase_scores = recommend_level_for_method(rec)

    assert "vmp-structural-risk" in vmp.reasons
    assert "vmp-structural-risk" in dex2c.reasons
    assert extract.score > vmp.score
    assert extract.score > dex2c.score
    assert (level, phase) == (1, "extract")
    assert "vmp-structural-risk" in reasons


def test_tiny_boolean_gate_avoids_dex2c_jni_overhead():
    rec = _rec(
        "Lcom/example/app/EntitlementGate;",
        "isPremium",
        "()Z",
        code_bytes=28,
    )

    extract = score_for_extract(rec)
    dex2c = score_for_dex2c(rec)
    level, phase, _score, reasons, _phase_scores = recommend_level_for_method(rec)

    assert "tiny-runtime-method" in dex2c.reasons
    assert extract.score > dex2c.score
    assert (level, phase) != (3, "dex2c")
    assert "tiny-runtime-method" in reasons


def test_worker_hot_callback_prefers_extract_over_dex2c():
    rec = _rec(
        "Lcom/example/app/AuthWorker;",
        "call",
        "()Z",
        code_bytes=300,
    )

    extract = score_for_extract(rec)
    dex2c = score_for_dex2c(rec)
    level, phase, _score, reasons, _phase_scores = recommend_level_for_method(rec)

    assert "performance-hot-risk" in dex2c.reasons
    assert extract.score > dex2c.score
    assert (level, phase) == (1, "extract")
    assert "performance-hot-risk" in reasons


def test_auto_protect_profiles_have_distinct_strengths_and_ndk_fallback():
    compat = resolve_auto_protect_profile("compat")
    balanced = resolve_auto_protect_profile("balanced")
    strong = resolve_auto_protect_profile("strong")
    extreme = resolve_auto_protect_profile("extreme")
    extract_only = resolve_auto_protect_profile("extreme", has_ndk=False)

    assert set(AUTO_PROTECT_PROFILES) == {"compat", "balanced", "strong", "extreme"}
    assert compat.vmp_count < balanced.vmp_count < strong.vmp_count < extreme.vmp_count
    assert compat.dex2c_count < balanced.dex2c_count < strong.dex2c_count < extreme.dex2c_count
    assert compat.min_score_dex2c > balanced.min_score_dex2c >= extreme.min_score_dex2c
    assert extract_only.vmp_count == 0
    assert extract_only.dex2c_count == 0
    assert extract_only.extract_count == extreme.extract_count
