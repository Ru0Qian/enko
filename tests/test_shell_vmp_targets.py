import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parent.parent
PACKER = ROOT / "packer"
JAVA_ROOT = ROOT / "shell-app" / "app" / "src" / "main" / "java"

if str(PACKER) not in sys.path:
    sys.path.insert(0, str(PACKER))

from harden_apk import (
    HardenError,
    NATIVE_LAYER_VMP_NAME,
    PAYLOAD_MAGIC,
    SHELL_VMP_TARGETS,
    VMP_BYTECODE_FORMAT_CAPABILITIES,
    VMP_OBFUSCATION_PRESETS,
    audit_vmp_blob_plaintext,
    build_security_report,
    build_method_protection_details,
    patch_manifest_debuggable,
    probe_ollvm_clang,
    read_runtime_config_example,
    resolve_extract_restore_options,
    resolve_vmp_obfuscation_options,
    wrap_payload_envelope,
)


def _source_for_descriptor(class_desc: str) -> str:
    assert class_desc.startswith("L") and class_desc.endswith(";")
    rel = Path(*class_desc[1:-1].split("/")).with_suffix(".java")
    path = JAVA_ROOT / rel
    assert path.exists(), f"missing shell VMP class source: {class_desc}"
    return path.read_text(encoding="utf-8")


def _declares_method(source: str, method_name: str) -> bool:
    pattern = re.compile(
        r"(?m)^\s*(?:public|private|protected)?\s*"
        r"(?:(?:static|final|synchronized)\s+)*"
        r"[\w<>\[\].?,\s]+\s+"
        + re.escape(method_name)
        + r"\s*\("
    )
    return bool(pattern.search(source))


def test_shell_vmp_targets_match_current_shell_sources():
    missing = []
    for class_desc, method_name, _sig in SHELL_VMP_TARGETS:
        source = _source_for_descriptor(class_desc)
        if not _declares_method(source, method_name):
            missing.append(f"{class_desc}->{method_name}")

    assert not missing, "stale shell VMP target(s): " + ", ".join(missing)


def test_shell_vmp_targets_do_not_protect_bootstrap_helpers():
    bootstrap_helpers = {
        ("Lcom/enko/shell/DexProtector;", "initShellVmp"),
        ("Lcom/enko/shell/ProxyApplication;", "loadRuntimeConfig"),
        ("Lcom/enko/shell/ProxyApplication;", "buildApkEntryIndex"),
        ("Lcom/enko/shell/ProxyApplication;", "readBlobFromNativeLayer"),
    }

    actual = {(class_desc, method_name) for class_desc, method_name, _ in SHELL_VMP_TARGETS}

    assert actual.isdisjoint(bootstrap_helpers)


def test_runtime_config_example_lists_shell_vmp_controls():
    example = read_runtime_config_example()

    assert "protectDexPages=<base64 utf8>" in example
    assert "extractOnDemand=<base64 utf8>" in example
    assert "shellVmpEnabled=<base64 utf8>" in example
    assert "commercialMode=<base64 utf8>" in example


def test_vmp_obfuscation_preset_fills_default_ratios():
    args = SimpleNamespace(
        vmp_dex_obfuscation_preset="light",
        vmp_dex_split_prob=None,
        vmp_dex_junk_ratio=None,
        vmp_dex_inline_junk_ratio=None,
    )

    resolve_vmp_obfuscation_options(args)

    expected = VMP_OBFUSCATION_PRESETS["light"]
    actual = (
        args.vmp_dex_split_prob,
        args.vmp_dex_junk_ratio,
        args.vmp_dex_inline_junk_ratio,
    )
    assert actual == expected
    assert args.vmp_dex_obfuscation_mode == "light"


def test_manifest_debuggable_is_forced_false():
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<application android:name=".App" android:debuggable="true" />'
        '</manifest>'
    )

    patched = patch_manifest_debuggable(manifest)

    assert 'android:debuggable="false"' in patched
    assert 'android:debuggable="true"' not in patched


def test_manifest_debuggable_false_is_injected_when_missing():
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<application android:name=".App" />'
        '</manifest>'
    )

    patched = patch_manifest_debuggable(manifest)

    assert '<application android:debuggable="false" android:name=".App"' in patched


def test_vmp_plaintext_audit_reports_clean_blob(tmp_path):
    abi_dir = tmp_path / "lib" / "arm64-v8a"
    abi_dir.mkdir(parents=True)
    (abi_dir / NATIVE_LAYER_VMP_NAME).write_bytes(b"\x00\x81\xfe\x13")

    audit = audit_vmp_blob_plaintext(
        tmp_path,
        payload_method_info=[
            {
                "class_desc": "Lcom/example/Secret;",
                "method_name": "verifyFlag",
                "signature": "(Ljava/lang/String;)Z",
            }
        ],
        shell_method_info=[],
    )

    assert audit["status"] == "clean"
    assert audit["checked_files"] == 1
    assert audit["hit_count"] == 0


def test_vmp_plaintext_audit_reports_descriptor_hit(tmp_path):
    abi_dir = tmp_path / "lib" / "arm64-v8a"
    abi_dir.mkdir(parents=True)
    (abi_dir / NATIVE_LAYER_VMP_NAME).write_bytes(b"...Lcom/example/Secret;...")

    audit = audit_vmp_blob_plaintext(
        tmp_path,
        payload_method_info=[
            {
                "class_desc": "Lcom/example/Secret;",
                "method_name": "verifyFlag",
                "signature": "(Ljava/lang/String;)Z",
            }
        ],
        shell_method_info=[],
    )

    assert audit["status"] == "plaintext-hit"
    assert audit["hit_count"] >= 1


def test_payload_envelope_hides_magic_and_adds_random_padding():
    inner = PAYLOAD_MAGIC + b"\x01" * 64
    metadata = {}

    wrapped = wrap_payload_envelope(inner, metadata=metadata)
    seed = int.from_bytes(wrapped[0:4], "big")
    encoded_len = int.from_bytes(wrapped[4:8], "big")
    decoded_len = encoded_len ^ seed ^ 0xA35F9C21

    assert PAYLOAD_MAGIC not in wrapped
    assert decoded_len == len(inner)
    assert metadata["format"] == "seeded-xor-v2-trailing-padding"
    assert 8 <= metadata["padding_length"] <= 95
    assert len(wrapped) == 8 + len(inner) + metadata["padding_length"]


def test_native_payload_envelope_accepts_trailing_padding():
    enko_gcm = (ROOT / "shell-app" / "app" / "src" / "main" / "cpp" / "enko_gcm.c").read_text(
        encoding="utf-8"
    )

    assert "inner_len > input_len - 8" in enko_gcm
    assert "input[i + 8] ^ mask" in enko_gcm


def test_parser_defaults_enable_light_vmp_obfuscation():
    from harden_apk import build_parser

    args = build_parser().parse_args([
        "--input-apk", "in.apk",
        "--shell-dex", "shell.dex",
        "--output-apk", "out.apk",
    ])
    resolve_vmp_obfuscation_options(args)

    assert args.vmp_dex_obfuscation_preset == "light"
    assert args.vmp_dex_obfuscation_mode == "light"
    assert (
        args.vmp_dex_split_prob,
        args.vmp_dex_junk_ratio,
        args.vmp_dex_inline_junk_ratio,
    ) == VMP_OBFUSCATION_PRESETS["light"]


def test_vmp_obfuscation_has_stable_downgrade_guard():
    source = (ROOT / "packer" / "harden_apk.py").read_text(encoding="utf-8")

    assert "retrying stable VMP obfuscation profile" in source
    assert "stable downgrade succeeded" in source
    assert '"effective_split_prob"' in source
    assert '"downgraded"' in source
    assert "plaintext_audit_required_clean" in source
    assert "VMP plaintext audit failed in required-clean mode" in source


def test_parser_defaults_to_external_original_signing_mode():
    from harden_apk import build_parser

    args = build_parser().parse_args([
        "--input-apk", "in.apk",
        "--shell-dex", "shell.dex",
        "--output-apk", "out.apk",
    ])
    sign_args = build_parser().parse_args([
        "--input-apk", "in.apk",
        "--shell-dex", "shell.dex",
        "--output-apk", "out.apk",
        "--sign",
        "--keystore", "release.jks",
        "--ks-pass", "pass",
        "--key-alias", "alias",
        "--key-pass", "pass",
    ])

    assert args.skip_sign is True
    assert sign_args.skip_sign is False


def test_parser_keeps_dex_page_protection_independent_from_emulator_check():
    from harden_apk import build_parser

    args = build_parser().parse_args([
        "--input-apk", "in.apk",
        "--shell-dex", "shell.dex",
        "--output-apk", "out.apk",
        "--disable-emulator-check",
    ])

    assert args.detect_emulator is False
    assert args.protect_dex_pages is True

    args = build_parser().parse_args([
        "--input-apk", "in.apk",
        "--shell-dex", "shell.dex",
        "--output-apk", "out.apk",
        "--no-protect-dex-pages",
    ])

    assert args.detect_emulator is True
    assert args.protect_dex_pages is False


def test_extract_restore_mode_defaults_follow_risk_profile():
    from harden_apk import build_parser

    strict_args = build_parser().parse_args([
        "--input-apk", "in.apk",
        "--shell-dex", "shell.dex",
        "--output-apk", "out.apk",
        "--risk-profile", "strict",
    ])
    compat_args = build_parser().parse_args([
        "--input-apk", "in.apk",
        "--shell-dex", "shell.dex",
        "--output-apk", "out.apk",
        "--risk-profile", "compat",
    ])
    forced_args = build_parser().parse_args([
        "--input-apk", "in.apk",
        "--shell-dex", "shell.dex",
        "--output-apk", "out.apk",
        "--risk-profile", "compat",
        "--extract-on-demand",
    ])

    resolve_extract_restore_options(strict_args)
    resolve_extract_restore_options(compat_args)
    resolve_extract_restore_options(forced_args)

    assert strict_args.extract_on_demand is True
    assert compat_args.extract_on_demand is False
    assert forced_args.extract_on_demand is True


def test_parser_exposes_auto_protect_profile_default():
    from harden_apk import build_parser

    args = build_parser().parse_args([
        "--input-apk", "in.apk",
        "--shell-dex", "shell.dex",
        "--output-apk", "out.apk",
    ])
    strong_args = build_parser().parse_args([
        "--input-apk", "in.apk",
        "--shell-dex", "shell.dex",
        "--output-apk", "out.apk",
        "--auto-protect-profile", "strong",
    ])

    assert args.auto_protect_profile == "balanced"
    assert strong_args.auto_protect_profile == "strong"


def test_shell_native_build_enables_ollvm_by_default():
    build_gradle = (ROOT / "shell-app" / "app" / "build.gradle").read_text(encoding="utf-8")
    cmake = (ROOT / "shell-app" / "app" / "src" / "main" / "cpp" / "CMakeLists.txt").read_text(encoding="utf-8")
    harden_apk = (ROOT / "packer" / "harden_apk.py").read_text(encoding="utf-8")

    assert "project.findProperty('enkoEnableOllvm') ?: 'true'" in build_gradle
    assert "-DENKO_OLLVM=ON" in build_gradle
    assert "-DENKO_OLLVM_CLANG=" in build_gradle
    assert "enko_anti_debug.c" in cmake
    assert "set(NDK_SRC_FILES enko_vmp.c enko_jni.c enko_key.c)" in cmake
    assert "SHELL_POLY_FIELD_NAMES" in harden_apk
    assert '"field_alias_count"' in harden_apk


def test_dex2c_libagpjnix_enables_ollvm_by_default():
    from harden_apk import build_parser

    args = build_parser().parse_args([
        "--input-apk", "in.apk",
        "--shell-dex", "shell.dex",
        "--output-apk", "out.apk",
    ])
    compiler = (ROOT / "packer" / "dex2c" / "compiler.py").read_text(encoding="utf-8")

    assert args.dex2c_ollvm is True
    assert args.dex2c_ollvm_required is False
    assert "ENKO_D2C_OLLVM" in compiler
    assert "Hikari obfuscate DEX2C: enko_dex2c.c" in compiler
    assert "-mllvm -enable-strcry" in compiler
    assert "ollvm_protected_libraries" in compiler
    assert "fallback_libraries" in compiler
    assert "retrying normal NDK compile" in compiler


def test_dex2c_ollvm_probe_detects_available_executable():
    probe = probe_ollvm_clang(sys.executable, requested=True, required=True)

    assert probe["available"] is True
    assert probe["preflight_status"] == "available"
    assert probe["version"]


def test_dex2c_ollvm_probe_allows_best_effort_missing_path(tmp_path):
    missing = tmp_path / "missing-clang.exe"

    probe = probe_ollvm_clang(str(missing), requested=True, required=False)

    assert probe["available"] is False
    assert probe["preflight_status"] == "missing"
    assert "not found" in probe["reason"]

    with pytest.raises(HardenError):
        probe_ollvm_clang(str(missing), requested=True, required=True)


def test_security_report_includes_dex2c_ollvm_preflight_result():
    args = SimpleNamespace(
        per_apk_key=True,
        risk_policy="warn",
        risk_profile="balanced",
        block_proxy_vpn=False,
        detect_emulator=True,
        detect_root=True,
        protect_dex_pages=True,
        extract_on_demand=True,
        vmp_fail_open=False,
        vmp_dex_fail_open=False,
        extract_fail_open=False,
        dex2c_fail_open=False,
        skip_zipalign=False,
        commercial_mode=False,
        auto_protect_profile="balanced",
        vmp_dex_split_prob=0.08,
        vmp_dex_junk_ratio=0.02,
        vmp_dex_inline_junk_ratio=0.04,
        vmp_dex_obfuscation_mode="light",
        vmp_dex_obfuscation_report={
            "effective": {
                "split_prob": 0.0,
                "junk_ratio": 0.0,
                "inline_junk_ratio": 0.0,
            },
            "downgraded": True,
            "downgrade_reason": "opaque split rejected sample method",
        },
        vmp_shell_dex=True,
        dex2c_ollvm=True,
        dex2c_ollvm_required=False,
        dex2c_ollvm_clang="D:/tool/hikari/bin/clang.exe",
        dex2c_ollvm_probe={
            "available": True,
            "version": "Hikari clang version 19.0.0",
            "preflight_status": "available",
            "reason": "",
        },
        dex2c_ollvm_build_report={
            "ollvm_protected_libraries": ["lib/arm64-v8a/libagpjnix.so"],
            "ollvm_protected_abis": ["arm64-v8a"],
            "fallback_libraries": [],
            "fallback_abis": [],
            "fallback_used": False,
            "per_abi": [
                {
                    "abi": "arm64-v8a",
                    "library": "libagpjnix.so",
                    "path": "lib/arm64-v8a/libagpjnix.so",
                    "mode": "ollvm",
                    "ollvm_protected": True,
                }
            ],
        },
    )

    report = build_security_report(
        args,
        signing_enabled=False,
        sign_cert_sha256="",
        extract_enabled=False,
        vmp_dex_enabled=False,
        dex2c_enabled=True,
        extract_compiled_count=0,
        vmp_compiled_count=0,
        d2c_compiled_count=1,
        extract_requested_count=0,
        vmp_requested_count=0,
        d2c_requested_count=1,
        protectable_method_count=20,
        flutter_mode=False,
        native_core_profile={"flutter_detected": False, "abis": ["arm64-v8a"]},
    )

    obf = report["method_protection"]["dex2c_native_obfuscation"]
    assert obf["target_library"] == "libagpjnix.so"
    assert obf["ollvm_available"] is True
    assert obf["ollvm_version"] == "Hikari clang version 19.0.0"
    assert obf["ollvm_effective"] is True
    assert obf["ollvm_protected_libraries"] == ["lib/arm64-v8a/libagpjnix.so"]
    assert obf["fallback_used"] is False
    assert obf["per_abi"][0]["mode"] == "ollvm"
    assert obf["preflight_status"] == "available"
    vmp_obf = report["method_protection"]["vmp_obfuscation"]
    assert vmp_obf["string_pool_format_version"] == 4
    assert vmp_obf["string_pool_decryption_mode"] == "load-time-per-vmp-context"
    assert vmp_obf["identifier_plaintext_audit"] is True
    assert vmp_obf["downgraded"] is True
    assert vmp_obf["effective_split_prob"] == 0.0
    assert vmp_obf["downgrade_reason"] == "opaque split rejected sample method"
    vmp_format = report["method_protection"]["vmp_bytecode_format"]
    assert vmp_format == VMP_BYTECODE_FORMAT_CAPABILITIES
    assert vmp_format["instruction_encoding"] == "fixed8"
    assert vmp_format["instruction_width_bytes"] == 8
    assert vmp_format["field_layout_randomized"] is False
    assert vmp_format["variable_length_supported"] is False
    assert vmp_format["semantic_alias_handlers"] is True
    assert vmp_format["semantic_alias_handler_variants"] == {
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
    }
    assert vmp_format["semantic_alias_implementation"] == "native-multi-shape-int-binop-v2"
    assert vmp_format["semantic_alias_implementation_shapes"] == 17


def test_native_risk_bit_8_is_mapped_to_system_integrity_reason():
    anti_debug_c = (ROOT / "shell-app" / "app" / "src" / "main" / "cpp" / "enko_anti_debug.c").read_text(
        encoding="utf-8"
    )
    anti_debug_h = (ROOT / "shell-app" / "app" / "src" / "main" / "cpp" / "enko_anti_debug.h").read_text(
        encoding="utf-8"
    )
    enko_jni = (ROOT / "shell-app" / "app" / "src" / "main" / "cpp" / "enko_jni.c").read_text(encoding="utf-8")
    native_bridge = (JAVA_ROOT / "com" / "enko" / "shell" / "NativeBridge.java").read_text(encoding="utf-8")
    integrity_gate = (JAVA_ROOT / "com" / "enko" / "shell" / "IntegrityGate.java").read_text(encoding="utf-8")

    assert "check_system_integrity_indicators" in anti_debug_c
    assert "flags |= 256" in anti_debug_c
    assert 'strcmp(reason, "system-integrity-anomaly")' in anti_debug_c
    assert "bit 8: system integrity anomaly detected" in anti_debug_h
    assert "(native_flags & 256) != 0" in enko_jni
    assert "(nativeFlags & 256) != 0" in integrity_gate
    assert "bit 8 = system integrity anomaly" in native_bridge


def test_hook_framework_detection_covers_modern_injection_chains():
    anti_debug_c = (ROOT / "shell-app" / "app" / "src" / "main" / "cpp" / "enko_anti_debug.c").read_text(
        encoding="utf-8"
    )
    java_hook_detector = (JAVA_ROOT / "com" / "enko" / "shell" / "JavaHookDetector.java").read_text(
        encoding="utf-8"
    )

    assert "contains_hook_framework_keyword" in anti_debug_c
    for keyword in ["lsposed", "lspatch", "riru", "zygisk", "dobby", "whale"]:
        assert f'"{keyword}"' in anti_debug_c
    for keyword in ["kernelsu", "apatch"]:
        assert f'"{keyword}"' in anti_debug_c

    for marker in [
        "org.lsposed.lspatch",
        "libzygisk",
        "liblspatch",
        "persist.lsposed.version",
        "/data/adb/modules/zygisk_lsposed",
    ]:
        assert marker in java_hook_detector


def test_vmp_add_int_aliases_have_dedicated_native_handlers():
    enko_vmp_c = (ROOT / "shell-app" / "app" / "src" / "main" / "cpp" / "enko_vmp.c").read_text(
        encoding="utf-8"
    )
    vmp_compiler = (ROOT / "packer" / "vmp_compiler.py").read_text(encoding="utf-8")

    assert "[VMP_BINOP_ALIAS1] = &&VMP_BINOP_ALIAS1_LABEL" in enko_vmp_c
    assert "[VMP_BINOP_LIT_ALIAS1] = &&VMP_BINOP_LIT_ALIAS1_LABEL" in enko_vmp_c
    for macro in [
        "VMP_ADD_INT_ALIAS_U32(BINOP_ALIAS1)",
        "VMP_ADD_INT_ALIAS_COMMUTE(BINOP_ALIAS2)",
        "VMP_ADD_INT_ALIAS_WIDE(BINOP_ALIAS3)",
        "VMP_ADD_INT_ALIAS_SALTED(BINOP_ALIAS4)",
        "VMP_ADD_INT_ALIAS_SPLIT16(BINOP_ALIAS5)",
        "VMP_ADD_INT_ALIAS_NEGSUB(BINOP_ALIAS6)",
        "VMP_ADD_INT_ALIAS_VOLATILE_ZERO(BINOP_ALIAS7)",
        "VMP_ADD_INT_ALIAS_SPLIT_RHS(BINOP_ALIAS8)",
        "VMP_ADD_INT_ALIAS_WIDE(BINOP_LIT_ALIAS8)",
        "VMP_SUB_INT_ALIAS_U32(SUB_ALIAS1)",
        "VMP_SUB_INT_ALIAS_ADDNEG(SUB_ALIAS2)",
        "VMP_SUB_INT_ALIAS_SALTED(SUB_ALIAS3)",
        "VMP_AND_INT_ALIAS_DEMORGAN(AND_ALIAS1)",
        "VMP_AND_INT_ALIAS_MASKED(AND_ALIAS2)",
        "VMP_OR_INT_ALIAS_DEMORGAN(OR_ALIAS1)",
        "VMP_OR_INT_ALIAS_SPLIT(OR_ALIAS2)",
        "VMP_XOR_INT_ALIAS_ORAND(XOR_ALIAS1)",
        "VMP_XOR_INT_ALIAS_SALTED(XOR_ALIAS2)",
    ]:
        assert macro in enko_vmp_c
    assert "[VMP_UNOP_ALIAS1] = &&VMP_SUB_ALIAS1_LABEL" in enko_vmp_c
    assert "[VMP_UNOP_ALIAS4] = &&VMP_AND_ALIAS1_LABEL" in enko_vmp_c
    assert "[VMP_IF_ALIAS1] = &&VMP_OR_ALIAS1_LABEL" in enko_vmp_c
    assert "[VMP_IF_ALIAS3] = &&VMP_XOR_ALIAS1_LABEL" in enko_vmp_c
    assert "case VMP_BINOP_ALIAS10:" in enko_vmp_c
    assert "case VMP_BINOP_LIT_ALIAS8:" in enko_vmp_c
    assert "_assign([0x90], VmpOp.ADD_INT, _BINOP_ALIASES)" in vmp_compiler
    assert "_assign([0x91], VmpOp.SUB_INT, _SUB_INT_ALIASES)" in vmp_compiler
    assert "_assign([0x95], VmpOp.AND_INT, _AND_INT_ALIASES)" in vmp_compiler
    assert "_assign([0x96], VmpOp.OR_INT, _OR_INT_ALIASES)" in vmp_compiler
    assert "_assign([0x97], VmpOp.XOR_INT, _XOR_INT_ALIASES)" in vmp_compiler
    assert "_assign([0xD0], VmpOp.ADD_INT, _BINOP_LIT_ALIASES)" in vmp_compiler


def test_method_protection_details_report_requested_compiled_and_auto_reasons():
    details = build_method_protection_details(
        protection_map_path="protect.txt",
        extract_methods_path="",
        vmp_dex_methods_path="",
        dex2c_methods_path="",
        auto_protect_report={
            "enabled": True,
            "profile": "balanced",
            "selected": {
                "dex2c": [
                    {
                        "spec": "Lcom/example/Gate;->verify()Z",
                        "score": 42,
                        "reasons": ["security-keywords"],
                    }
                ]
            },
        },
        extract_spec=[("Lcom/example/Gate;", "slowPath", "()V")],
        vmp_spec=[("Lcom/example/Gate;", "verify", "()Z")],
        dex2c_spec=[("Lcom/example/Gate;", "nativeGate", "()Z")],
        vmp_method_info=[
            {
                "class_desc": "Lcom/example/Gate;",
                "method_name": "verify",
                "signature": "()Z",
                "method_id": 7,
                "dex_index": 0,
                "method_idx": 12,
                "is_static": True,
            }
        ],
        shell_vmp_method_info=[],
        extract_compiled_count=1,
        dex2c_compiled_count=1,
    )

    assert details["sources"]["protection_map"] is True
    assert details["requested"]["extract"][0]["spec"] == "Lcom/example/Gate;->slowPath()V"
    assert details["compiled"]["vmp_dex"]["methods"][0]["method_id"] == 7
    assert details["compiled"]["dex2c"]["target_library"] == "libagpjnix.so"
    assert details["auto_protect"]["profile"] == "balanced"
