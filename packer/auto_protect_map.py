#!/usr/bin/env python3
"""Generate a baseline protection-map from an APK without AI.

This script performs local static heuristics over classes*.dex and emits a
protection-map file consumable by packer/harden_apk.py.
"""

from __future__ import annotations

import argparse
import json
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from dex_parser import ACC_ABSTRACT, ACC_NATIVE, DexFile, parse_dex


ACC_SYNCHRONIZED = 0x0020
ACC_DECLARED_SYNCHRONIZED = 0x00020000

SYSTEM_PREFIXES = (
    "Landroid/",
    "Landroidx/",
    "Ljava/",
    "Ljavax/",
    "Lkotlin/",
    "Lkotlinx/",
    "Ldalvik/",
    "Ljunit/",
    "Lorg/apache/",
)

FLUTTER_FRAMEWORK_PREFIXES = (
    "Lio/flutter/embedding/",
    "Lio/flutter/plugin/",
    "Lio/flutter/view/",
    "Lio/flutter/util/",
    "Lio/flutter/app/",
)

SECURITY_KEYWORDS = (
    "flag",
    "verify",
    "check",
    "sign",
    "signature",
    "license",
    "auth",
    "token",
    "secret",
    "crypto",
    "encrypt",
    "decrypt",
    "hash",
    "hmac",
    "integrity",
    "tamper",
    "risk",
    "policy",
    "root",
    "emulator",
    "frida",
    "hook",
    "debug",
    "attest",
    "cert",
    "checksum",
    "shield",
    "protect",
    "password",
    "passwd",
    "pin",
    "otp",
    "session",
    "premium",
    "vip",
    "trial",
    "pay",
    "payment",
    "purchase",
    "order",
    "serial",
    "activation",
    "unlock",
    "entitle",
)

FLUTTER_BRIDGE_KEYWORDS = (
    "flutter",
    "plugin",
    "channel",
    "methodchannel",
    "eventchannel",
    "message",
    "messenger",
    "platformview",
    "webview",
    "firebase",
    "auth",
    "login",
    "token",
    "biometric",
    "camera",
    "location",
    "map",
    "billing",
    "purchase",
    "payment",
    "notify",
    "notification",
    "deep",
    "share",
    "intent",
    "url",
    "push",
)

FLUTTER_PACKAGE_HINTS = (
    ".plugins.",
    ".plugin.",
    ".webview",
    ".firebase",
    ".billing",
    ".biometric",
    ".camera",
    ".location",
    ".notification",
    ".push",
    ".auth",
    ".login",
    ".share",
    ".url",
    ".maps",
)

FLUTTER_SIGNATURE_HINTS = (
    "Lio/flutter/plugin/common/MethodCall;",
    "Lio/flutter/plugin/common/MethodChannel$Result;",
    "Lio/flutter/plugin/common/BinaryMessenger;",
    "Lio/flutter/plugin/common/EventChannel$EventSink;",
    "Lio/flutter/plugin/platform/PlatformView;",
    "Lio/flutter/embedding/engine/plugins/FlutterPlugin$FlutterPluginBinding;",
)

FLUTTER_UI_NOISE_KEYWORDS = (
    "windowinsets",
    "accessibility",
    "viewgroup",
    "adapterview",
    "layout",
    "drawable",
    "toolbar",
    "popup",
    "spinner",
    "listview",
    "canvas",
    "outline",
    "menu",
    "tooltip",
    "textview",
    "imageview",
    "scroll",
    "touch",
    "window",
    "decor",
    "insets",
)

HOT_METHODS = (
    "oncreate",
    "onresume",
    "onstart",
    "onstop",
    "ondestroy",
    "ondraw",
    "dispatch",
    "onreceive",
    "onbind",
    "onlayout",
    "onclick",
    "onmeasure",
    "onbindviewholder",
    "getview",
    "run",
    "call",
    "invoke",
    "apply",
    "accept",
    "emit",
    "onnext",
    "onchanged",
)

PERFORMANCE_HOT_METHODS = (
    "run",
    "call",
    "invoke",
    "apply",
    "accept",
    "emit",
    "onnext",
    "onchanged",
    "compare",
    "equals",
    "hashcode",
    "tostring",
    "iterator",
    "hasnext",
    "next",
    "size",
    "length",
)

PERFORMANCE_CLASS_KEYWORDS = (
    "adapter",
    "viewholder",
    "runnable",
    "thread",
    "worker",
    "executor",
    "scheduler",
    "handler",
    "listener",
    "callback",
    "observer",
    "flow",
    "stream",
)

UI_LIFECYCLE_METHODS = (
    "oncreate",
    "onresume",
    "onpause",
    "onstart",
    "onstop",
    "ondestroy",
    "onactivityresult",
    "onrequestpermissionsresult",
    "onsaveinstancestate",
    "onrestoreinstancestate",
    "onnewintent",
    "onconfigurationchanged",
    "onclick",
    "ontouch",
    "ondraw",
    "onmeasure",
    "onlayout",
    "onbindviewholder",
    "getitemcount",
    "getview",
)

UI_CLASS_KEYWORDS = (
    "activity",
    "fragment",
    "view",
    "adapter",
    "viewholder",
    "recyclerview",
    "service",
    "receiver",
    "provider",
    "dialog",
)

REFLECTION_KEYWORDS = (
    "reflect",
    "classloader",
    "loadclass",
    "forname",
    "getmethod",
    "getdeclaredmethod",
    "getfield",
    "getdeclaredfield",
    "invoke",
    "proxy",
)

REFLECTION_SIGNATURE_HINTS = (
    "Ljava/lang/Class;",
    "Ljava/lang/ClassLoader;",
    "Ljava/lang/reflect/",
    "Ljava/lang/reflect/Method;",
    "Ljava/lang/reflect/Field;",
)

JNI_BRIDGE_KEYWORDS = (
    "jni",
    "native",
    "loadlibrary",
    "systemload",
    "dlopen",
    "ndk",
)

BRIDGE_METHODS = (
    "handle",
    "dispatch",
    "route",
    "callback",
    "intercept",
    "request",
    "response",
)

DEX2C_HINTS = (
    "is",
    "has",
    "can",
    "allow",
    "deny",
    "should",
    "verify",
    "check",
    "validate",
)


@dataclass
class MethodRecord:
    dex_name: str
    class_desc: str
    method_name: str
    signature: str
    access_flags: int
    code_bytes: int
    registers_size: int = 0
    outs_size: int = 0
    tries_size: int = 0
    has_monitor: bool = False
    has_switch: bool = False
    has_fill_array_data: bool = False
    invoke_count: int = 0

    @property
    def spec(self) -> str:
        return f"{self.class_desc}->{self.method_name}{self.signature}"

    @property
    def lowered(self) -> str:
        return f"{self.class_desc}.{self.method_name}".lower()

    @property
    def package_name(self) -> str:
        body = self.class_desc[1:].split(";")[0]
        segs = body.split("/")
        if len(segs) <= 1:
            return body.replace("/", ".")
        return ".".join(segs[:-1])


@dataclass
class RankedMethod:
    rec: MethodRecord
    score: int
    reasons: list[str]


@dataclass(frozen=True)
class AutoProtectProfile:
    name: str
    label: str
    extract_count: int
    vmp_count: int
    dex2c_count: int
    min_score_extract: int
    min_score_vmp: int
    min_score_dex2c: int


AUTO_PROTECT_PROFILES: dict[str, AutoProtectProfile] = {
    "compat": AutoProtectProfile(
        name="compat",
        label="compatibility-first",
        extract_count=14,
        vmp_count=6,
        dex2c_count=1,
        min_score_extract=10,
        min_score_vmp=34,
        min_score_dex2c=42,
    ),
    "balanced": AutoProtectProfile(
        name="balanced",
        label="balanced",
        extract_count=10,
        vmp_count=24,
        dex2c_count=4,
        min_score_extract=12,
        min_score_vmp=20,
        min_score_dex2c=25,
    ),
    "strong": AutoProtectProfile(
        name="strong",
        label="strong-protection",
        extract_count=18,
        vmp_count=40,
        dex2c_count=8,
        min_score_extract=10,
        min_score_vmp=18,
        min_score_dex2c=22,
    ),
    "extreme": AutoProtectProfile(
        name="extreme",
        label="extreme-protection",
        extract_count=28,
        vmp_count=72,
        dex2c_count=16,
        min_score_extract=8,
        min_score_vmp=15,
        min_score_dex2c=20,
    ),
}


# --------- helpers ---------


def _contains_any(text: str, words: Iterable[str]) -> list[str]:
    t = text.lower()
    return [w for w in words if w in t]


def resolve_auto_protect_profile(
    name: str | None,
    *,
    has_ndk: bool = True,
) -> AutoProtectProfile:
    key = (name or "balanced").strip().lower()
    if key not in AUTO_PROTECT_PROFILES:
        raise ValueError(
            "unknown auto-protect profile: "
            f"{name!r}; expected one of {', '.join(sorted(AUTO_PROTECT_PROFILES))}"
        )

    profile = AUTO_PROTECT_PROFILES[key]
    if has_ndk:
        return profile

    return AutoProtectProfile(
        name=profile.name,
        label=profile.label + "-extract-only",
        extract_count=profile.extract_count,
        vmp_count=0,
        dex2c_count=0,
        min_score_extract=profile.min_score_extract,
        min_score_vmp=profile.min_score_vmp,
        min_score_dex2c=profile.min_score_dex2c,
    )


def _return_type(signature: str) -> str:
    idx = signature.rfind(")")
    if idx < 0 or idx + 1 >= len(signature):
        return ""
    return signature[idx + 1 :]


def _bool_like(rec: MethodRecord) -> bool:
    ret = _return_type(rec.signature)
    if ret in ("Z", "I"):
        return True
    name = rec.method_name.lower()
    return name.startswith(("is", "has", "can", "allow", "deny", "should"))


def _is_system_class(class_desc: str) -> bool:
    return class_desc.startswith(SYSTEM_PREFIXES)


def _starts_with_any(text: str, prefixes: Iterable[str]) -> bool:
    return any(text.startswith(prefix) for prefix in prefixes)


def _simple_class_name(class_desc: str) -> str:
    body = class_desc[1:].split(";")[0]
    return body.split("/")[-1]


def _looks_compiler_artifact(rec: MethodRecord) -> bool:
    cls = _simple_class_name(rec.class_desc)
    name = rec.method_name
    if "$" in cls:
        return True
    if name.startswith("lambda$") or name.startswith("access$"):
        return True
    if cls.isdigit():
        return True
    return False


def _looks_too_obfuscated(rec: MethodRecord) -> bool:
    cls = _simple_class_name(rec.class_desc)
    if len(cls) <= 2 and cls.isalpha():
        return True
    if len(rec.method_name) <= 2 and rec.method_name.isalpha():
        return True
    return False


def _is_flutter_framework_class(class_desc: str) -> bool:
    return _starts_with_any(class_desc, FLUTTER_FRAMEWORK_PREFIXES)


def _has_flutter_bridge_hint(rec: MethodRecord) -> bool:
    lowered = rec.lowered
    if _contains_any(lowered, FLUTTER_BRIDGE_KEYWORDS):
        return True
    if any(hint in rec.signature for hint in FLUTTER_SIGNATURE_HINTS):
        return True
    if any(hint in rec.package_name.lower() for hint in FLUTTER_PACKAGE_HINTS):
        return True
    return False


def _has_flutter_ui_noise(rec: MethodRecord) -> bool:
    return bool(_contains_any(rec.lowered, FLUTTER_UI_NOISE_KEYWORDS))


def _payload_width_code_units(insns: bytes, pos_cu: int, total_cu: int) -> int:
    byte_off = pos_cu * 2
    if byte_off + 2 > len(insns):
        return 0
    ident = int.from_bytes(insns[byte_off: byte_off + 2], "little")
    if ident == 0x0100:
        if byte_off + 4 > len(insns):
            return 0
        size = int.from_bytes(insns[byte_off + 2: byte_off + 4], "little")
        width = 4 + size * 2
    elif ident == 0x0200:
        if byte_off + 4 > len(insns):
            return 0
        size = int.from_bytes(insns[byte_off + 2: byte_off + 4], "little")
        width = 2 + size * 4
    elif ident == 0x0300:
        if byte_off + 8 > len(insns):
            return 0
        element_width = int.from_bytes(insns[byte_off + 2: byte_off + 4], "little")
        size = int.from_bytes(insns[byte_off + 4: byte_off + 8], "little")
        width = 4 + ((element_width * size + 1) // 2)
    else:
        return 0
    return width if pos_cu + width <= total_cu else 0


def _scan_instruction_shape(insns: bytes) -> tuple[bool, bool, bool, int]:
    has_monitor = False
    has_switch = False
    has_fill_array_data = False
    invoke_count = 0
    total_cu = len(insns) // 2
    pos = 0
    while pos < total_cu:
        payload_width = _payload_width_code_units(insns, pos, total_cu)
        if payload_width:
            pos += payload_width
            continue
        off = pos * 2
        opcode = insns[off]
        if opcode in (0x1D, 0x1E):  # monitor-enter / monitor-exit
            has_monitor = True
        if opcode in (0x2B, 0x2C):  # packed-switch / sparse-switch
            has_switch = True
        if opcode == 0x26:  # fill-array-data
            has_fill_array_data = True
        if 0x6E <= opcode <= 0x78:  # invoke-kind family, best-effort scan
            invoke_count += 1
        pos += 1
    return has_monitor, has_switch, has_fill_array_data, invoke_count


def _is_ui_lifecycle_or_hot_callback(rec: MethodRecord) -> bool:
    lower_name = rec.method_name.lower()
    lowered = rec.lowered
    simple_class = _simple_class_name(rec.class_desc).lower()
    return (
        bool(_contains_any(lower_name, UI_LIFECYCLE_METHODS))
        or bool(_contains_any(simple_class, UI_CLASS_KEYWORDS))
        or bool(_contains_any(lowered, FLUTTER_UI_NOISE_KEYWORDS))
    )


def _has_reflection_risk(rec: MethodRecord) -> bool:
    lowered = rec.lowered
    return (
        bool(_contains_any(lowered, REFLECTION_KEYWORDS))
        or any(hint in rec.signature for hint in REFLECTION_SIGNATURE_HINTS)
    )


def _has_jni_bridge_risk(rec: MethodRecord) -> bool:
    return bool(_contains_any(rec.lowered, JNI_BRIDGE_KEYWORDS))


def _has_sync_risk(rec: MethodRecord) -> bool:
    return bool(
        rec.has_monitor
        or (rec.access_flags & ACC_SYNCHRONIZED)
        or (rec.access_flags & ACC_DECLARED_SYNCHRONIZED)
    )


def _has_vmp_structural_risk(rec: MethodRecord) -> bool:
    return bool(
        rec.tries_size > 0
        or rec.has_switch
        or rec.has_fill_array_data
        or rec.has_monitor
    )


def _is_tiny_runtime_method(rec: MethodRecord) -> bool:
    return rec.code_bytes <= 64


def _has_performance_hot_risk(rec: MethodRecord) -> bool:
    name = rec.method_name.lower()
    simple_class = _simple_class_name(rec.class_desc).lower()
    if name in PERFORMANCE_HOT_METHODS:
        return True
    if name.startswith(("get", "set")) and rec.code_bytes <= 96:
        return True
    if bool(_contains_any(simple_class, PERFORMANCE_CLASS_KEYWORDS)) and rec.code_bytes <= 768:
        return True
    return False


def _apply_compatibility_risk_bias(
    rec: MethodRecord,
    score: int,
    reasons: list[str],
    *,
    phase: str,
) -> tuple[int, list[str]]:
    if _is_ui_lifecycle_or_hot_callback(rec):
        if phase in ("vmp", "dex2c"):
            score -= 35 if phase == "vmp" else 32
        else:
            score += 4
        reasons.append("ui-lifecycle-or-hot-callback")

    if _has_reflection_risk(rec):
        if phase in ("vmp", "dex2c"):
            score -= 70
        else:
            score += 8
        reasons.append("reflection-risk")

    if _has_jni_bridge_risk(rec):
        if phase in ("vmp", "dex2c"):
            score -= 60
        else:
            score += 6
        reasons.append("jni-bridge-risk")

    if _has_sync_risk(rec):
        if phase in ("vmp", "dex2c"):
            score -= 75
        else:
            score += 4
        reasons.append("synchronized-or-monitor")

    if _has_vmp_structural_risk(rec):
        if phase == "vmp":
            score -= 45
        elif phase == "dex2c":
            score -= 75
        else:
            score += 6
        reasons.append("vmp-structural-risk")

    if rec.invoke_count >= 40 and phase in ("vmp", "dex2c"):
        score -= 10
        reasons.append("invoke-dense")

    if _is_tiny_runtime_method(rec):
        if phase == "dex2c":
            score -= 90
        elif phase == "vmp":
            score -= 22
        else:
            score += 2
        reasons.append("tiny-runtime-method")

    if _has_performance_hot_risk(rec):
        if phase == "dex2c":
            score -= 60
        elif phase == "vmp":
            score -= 28
        else:
            score += 5
        reasons.append("performance-hot-risk")

    return score, reasons


def _apply_flutter_bias(
    rec: MethodRecord,
    score: int,
    reasons: list[str],
    *,
    phase: str,
    flutter_mode: bool,
) -> tuple[int, list[str]]:
    if not flutter_mode:
        return score, reasons

    lowered = rec.lowered
    package_name = rec.package_name.lower()
    signature = rec.signature

    if _is_flutter_framework_class(rec.class_desc):
        score -= 45
        reasons.append("flutter-framework")
        return score, reasons

    if "generatedpluginregistrant" in lowered:
        score -= 18
        reasons.append("flutter-generated-glue")

    bridge_words = _contains_any(lowered, FLUTTER_BRIDGE_KEYWORDS)
    if bridge_words:
        score += 16 if phase == "dex2c" else 14 if phase == "vmp" else 10
        reasons.append(f"flutter-bridge:{','.join(sorted(set(bridge_words))[:4])}")

    if any(hint in signature for hint in FLUTTER_SIGNATURE_HINTS):
        score += 18 if phase == "dex2c" else 16 if phase == "vmp" else 12
        reasons.append("flutter-bridge-signature")

    if any(hint in package_name for hint in FLUTTER_PACKAGE_HINTS):
        score += 10 if phase == "dex2c" else 8 if phase == "vmp" else 6
        reasons.append("flutter-plugin-package")

    if not bridge_words and not any(hint in signature for hint in FLUTTER_SIGNATURE_HINTS):
        if _has_flutter_ui_noise(rec):
            score -= 18 if phase == "dex2c" else 16 if phase == "vmp" else 12
            reasons.append("flutter-ui-noise")

    return score, reasons


def _in_selected_package(class_desc: str, include_packages: list[str], exclude_prefixes: list[str]) -> bool:
    if any(class_desc.startswith(p) for p in exclude_prefixes):
        return False
    if not include_packages:
        return not _is_system_class(class_desc)
    slash_desc = class_desc
    return any(slash_desc.startswith(f"L{pkg.replace('.', '/')}/") for pkg in include_packages)


def _infer_top_packages(
    methods: list[MethodRecord],
    topn: int = 3,
    *,
    exclude_prefixes: Iterable[str] = (),
) -> list[str]:
    counter: Counter[str] = Counter()
    for m in methods:
        if _is_system_class(m.class_desc):
            continue
        if _starts_with_any(m.class_desc, exclude_prefixes):
            continue
        pkg = m.package_name
        if not pkg:
            continue
        segs = pkg.split(".")
        if len(segs) >= 3:
            key = ".".join(segs[:3])
        else:
            key = pkg
        counter[key] += 1
    return [pkg for pkg, _ in counter.most_common(topn)]


def _infer_top_flutter_packages(
    methods: list[MethodRecord],
    topn: int = 3,
    *,
    exclude_prefixes: Iterable[str] = (),
) -> list[str]:
    counter: Counter[str] = Counter()
    for m in methods:
        if _is_system_class(m.class_desc):
            continue
        if _starts_with_any(m.class_desc, exclude_prefixes):
            continue
        pkg = m.package_name
        if not pkg:
            continue

        segs = pkg.split(".")
        key = ".".join(segs[:3]) if len(segs) >= 3 else pkg
        score = 1

        if _has_flutter_bridge_hint(m):
            score += 10
        bridge_words = _contains_any(m.lowered, FLUTTER_BRIDGE_KEYWORDS)
        if bridge_words:
            score += 6
        if any(hint in m.signature for hint in FLUTTER_SIGNATURE_HINTS):
            score += 8
        if _contains_any(m.lowered, SECURITY_KEYWORDS):
            score += 3
        if _has_flutter_ui_noise(m) and not _has_flutter_bridge_hint(m):
            score -= 4
        if _looks_compiler_artifact(m):
            score -= 3
        if _looks_too_obfuscated(m):
            score -= 1
        if score > 0:
            counter[key] += score

    return [pkg for pkg, _ in counter.most_common(topn)]


# --------- collection ---------


def collect_methods_from_apk(apk_path: Path) -> list[MethodRecord]:
    records: list[MethodRecord] = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        dex_names = sorted(n for n in zf.namelist() if n.startswith("classes") and n.endswith(".dex"))
        if not dex_names:
            raise RuntimeError(f"no classes*.dex found in {apk_path}")

        for dex_name in dex_names:
            dex_data = zf.read(dex_name)
            dex = parse_dex(dex_data)
            records.extend(_collect_methods_from_dex(dex_name, dex))
    return records


def _collect_methods_from_dex(dex_name: str, dex: DexFile) -> list[MethodRecord]:
    out: list[MethodRecord] = []
    for cls in dex.class_defs:
        if cls.class_data is None:
            continue
        class_desc = dex.type_name(cls.class_idx)
        for em in cls.class_data.direct_methods + cls.class_data.virtual_methods:
            if em.code is None:
                continue
            if em.access_flags & ACC_NATIVE:
                continue
            if em.access_flags & ACC_ABSTRACT:
                continue
            name = dex.method_name(em.method_idx)
            if name.startswith("<"):
                continue
            sig = dex.method_signature(em.method_idx)
            has_monitor, has_switch, has_fill_array_data, invoke_count = _scan_instruction_shape(em.code.insns)
            out.append(
                MethodRecord(
                    dex_name=dex_name,
                    class_desc=class_desc,
                    method_name=name,
                    signature=sig,
                    access_flags=em.access_flags,
                    code_bytes=em.code.insns_size * 2,
                    registers_size=em.code.registers_size,
                    outs_size=em.code.outs_size,
                    tries_size=em.code.tries_size,
                    has_monitor=has_monitor,
                    has_switch=has_switch,
                    has_fill_array_data=has_fill_array_data,
                    invoke_count=invoke_count,
                )
            )
    return out


# --------- ranking ---------


def score_for_vmp(rec: MethodRecord, *, flutter_mode: bool = False) -> RankedMethod:
    score = 0
    reasons: list[str] = []

    words = _contains_any(rec.lowered, SECURITY_KEYWORDS)
    if words:
        score += 40
        reasons.append(f"security-keywords:{','.join(sorted(set(words))[:4])}")

    if 48 <= rec.code_bytes <= 2200:
        score += 20
        reasons.append("size-good")
    elif rec.code_bytes < 24:
        score -= 12
        reasons.append("size-too-small")
    elif rec.code_bytes > 5000:
        score -= 20
        reasons.append("size-too-large")

    if _bool_like(rec):
        score += 8
        reasons.append("bool-like")

    if rec.tries_size > 0:
        score -= 6
        reasons.append("try-catch")

    if rec.registers_size >= 24 or rec.outs_size >= 8:
        score -= 8
        reasons.append("wide-frame")

    hot = _contains_any(rec.method_name, HOT_METHODS)
    if hot:
        score -= 25
        reasons.append("hot-path")

    bridge = _contains_any(rec.method_name, BRIDGE_METHODS)
    if bridge and rec.code_bytes >= 80:
        score += 8
        reasons.append(f"bridge:{','.join(sorted(set(bridge))[:3])}")

    if rec.method_name.lower().startswith(("get", "set")) and rec.code_bytes < 64:
        score -= 10
        reasons.append("trivial-accessor")

    if _looks_compiler_artifact(rec):
        score -= 18
        reasons.append("compiler-artifact")
    elif _looks_too_obfuscated(rec):
        score -= 8
        reasons.append("obfuscated-name")

    score, reasons = _apply_compatibility_risk_bias(
        rec, score, reasons, phase="vmp"
    )
    score, reasons = _apply_flutter_bias(
        rec, score, reasons, phase="vmp", flutter_mode=flutter_mode
    )

    return RankedMethod(rec=rec, score=score, reasons=reasons)


def score_for_dex2c(rec: MethodRecord, *, flutter_mode: bool = False) -> RankedMethod:
    score = 0
    reasons: list[str] = []

    words = _contains_any(rec.lowered, SECURITY_KEYWORDS)
    if words:
        score += 35
        reasons.append("security-keywords")

    lower_name = rec.method_name.lower()
    if lower_name.startswith(DEX2C_HINTS):
        score += 25
        reasons.append("gate-prefix")

    if _bool_like(rec):
        score += 20
        reasons.append("bool-like")

    if 16 <= rec.code_bytes <= 900:
        score += 20
        reasons.append("size-good")
    elif rec.code_bytes < 16:
        score -= 14
        reasons.append("size-too-small")
    elif rec.code_bytes > 2000:
        score -= 20
        reasons.append("size-too-large")

    if rec.tries_size > 0:
        score -= 10
        reasons.append("try-catch")

    if rec.registers_size >= 20 or rec.outs_size >= 8:
        score -= 10
        reasons.append("wide-frame")

    if _contains_any(lower_name, HOT_METHODS):
        score -= 24
        reasons.append("hot-path")

    if _looks_compiler_artifact(rec):
        score -= 20
        reasons.append("compiler-artifact")
    elif _looks_too_obfuscated(rec):
        score -= 8
        reasons.append("obfuscated-name")

    score, reasons = _apply_compatibility_risk_bias(
        rec, score, reasons, phase="dex2c"
    )
    score, reasons = _apply_flutter_bias(
        rec, score, reasons, phase="dex2c", flutter_mode=flutter_mode
    )

    return RankedMethod(rec=rec, score=score, reasons=reasons)


def score_for_extract(rec: MethodRecord, *, flutter_mode: bool = False) -> RankedMethod:
    score = 0
    reasons: list[str] = []

    if 24 <= rec.code_bytes <= 2600:
        score += 20
        reasons.append("size-good")

    words = _contains_any(rec.lowered, SECURITY_KEYWORDS)
    if words:
        score += 8
        reasons.append("security-related")

    if _contains_any(rec.method_name.lower(), HOT_METHODS):
        score += 8
        reasons.append("flow-obfuscation")

    if rec.tries_size > 0:
        score += 4
        reasons.append("try-catch-safe")

    if rec.registers_size >= 24 or rec.outs_size >= 8:
        score += 3
        reasons.append("large-frame-safe")

    if rec.code_bytes > 5000:
        score -= 20
        reasons.append("size-too-large")

    if _looks_compiler_artifact(rec):
        score -= 16
        reasons.append("compiler-artifact")
    elif _looks_too_obfuscated(rec):
        score -= 6
        reasons.append("obfuscated-name")

    score, reasons = _apply_compatibility_risk_bias(
        rec, score, reasons, phase="extract"
    )
    score, reasons = _apply_flutter_bias(
        rec, score, reasons, phase="extract", flutter_mode=flutter_mode
    )

    return RankedMethod(rec=rec, score=score, reasons=reasons)


PHASE_LEVELS = {
    "extract": 1,
    "vmp": 2,
    "dex2c": 3,
}

LEVEL_PHASES = {v: k for k, v in PHASE_LEVELS.items()}

DEFAULT_PHASE_MIN_SCORES = {
    "extract": 8,
    "vmp": 15,
    "dex2c": 20,
}


def score_all_phases(rec: MethodRecord, *, flutter_mode: bool = False) -> dict[str, RankedMethod]:
    """Return per-phase scores for UI analysis and smart selection."""
    return {
        "extract": score_for_extract(rec, flutter_mode=flutter_mode),
        "vmp": score_for_vmp(rec, flutter_mode=flutter_mode),
        "dex2c": score_for_dex2c(rec, flutter_mode=flutter_mode),
    }


def recommend_level_for_method(
    rec: MethodRecord,
    *,
    flutter_mode: bool = False,
    enabled_phases: dict[str, bool] | None = None,
    min_scores: dict[str, int] | None = None,
) -> tuple[int, str, int, list[str], dict[str, RankedMethod]]:
    """Pick the safest high-value protection phase for one method.

    DEX2C and VMP get a small tie-break bonus because they are stronger, but
    phase-specific score thresholds still keep tiny accessors and hot UI paths
    out of the automatic selection.
    """
    phase_scores = score_all_phases(rec, flutter_mode=flutter_mode)
    enabled = enabled_phases or {"extract": True, "vmp": True, "dex2c": True}
    thresholds = {**DEFAULT_PHASE_MIN_SCORES, **(min_scores or {})}
    phase_bonus = {"extract": 0, "vmp": 5, "dex2c": 4}
    best_phase = ""
    best_key: tuple[int, int, int, str] | None = None

    for phase, ranked in phase_scores.items():
        if not enabled.get(phase, True):
            continue
        if ranked.score < thresholds.get(phase, 0):
            continue
        key = (ranked.score + phase_bonus.get(phase, 0), ranked.score, ranked.rec.code_bytes, phase)
        if best_key is None or key > best_key:
            best_key = key
            best_phase = phase

    if not best_phase:
        return 0, "none", 0, [], phase_scores

    ranked = phase_scores[best_phase]
    return PHASE_LEVELS[best_phase], best_phase, ranked.score, ranked.reasons, phase_scores


# --------- selection ---------


def _select_diverse_ranked(
    ranked: list[RankedMethod],
    target_count: int,
    selected_specs: set[str],
    *,
    base_class_counts: Counter[str] | None = None,
    base_package_counts: Counter[str] | None = None,
    preferred_class_cap: int,
    class_penalty: int,
    package_penalty: int,
) -> list[RankedMethod]:
    if target_count <= 0:
        return []

    class_counts: Counter[str] = Counter(base_class_counts or {})
    package_counts: Counter[str] = Counter(base_package_counts or {})
    selected: list[RankedMethod] = []

    available_class_count = len(
        {
            r.rec.class_desc
            for r in ranked
            if r.rec.spec not in selected_specs
        }
    )
    class_cap = max(1, preferred_class_cap)
    max_cap = max(class_cap, min(max(target_count, 1), max(available_class_count, 1)))

    while len(selected) < target_count:
        best_idx: int | None = None
        best_key: tuple[float, int, int, int, int, int, str] | None = None

        for idx, ranked_method in enumerate(ranked):
            rec = ranked_method.rec
            if rec.spec in selected_specs:
                continue
            cls = rec.class_desc
            pkg = rec.package_name
            if class_counts[cls] >= class_cap:
                continue

            adjusted = float(ranked_method.score)
            adjusted -= float(class_counts[cls] * class_penalty)
            adjusted -= float(package_counts[pkg] * package_penalty)

            candidate_key = (
                adjusted,
                1 if class_counts[cls] == 0 else 0,
                1 if package_counts[pkg] == 0 else 0,
                -class_counts[cls],
                -package_counts[pkg],
                rec.code_bytes,
                rec.spec,
            )
            if best_key is None or candidate_key > best_key:
                best_key = candidate_key
                best_idx = idx

        if best_idx is None:
            if class_cap < max_cap:
                class_cap += 1
                continue
            break

        picked = ranked[best_idx]
        selected.append(picked)
        selected_specs.add(picked.rec.spec)
        class_counts[picked.rec.class_desc] += 1
        package_counts[picked.rec.package_name] += 1

    return selected


def _selection_counters(
    ranked_methods: list[RankedMethod],
) -> tuple[Counter[str], Counter[str]]:
    class_counts: Counter[str] = Counter()
    package_counts: Counter[str] = Counter()
    for ranked_method in ranked_methods:
        class_counts[ranked_method.rec.class_desc] += 1
        package_counts[ranked_method.rec.package_name] += 1
    return class_counts, package_counts


def _summarize_selection(ranked_methods: list[RankedMethod]) -> dict[str, object]:
    class_counts, package_counts = _selection_counters(ranked_methods)
    flutter_bridge_hits = sum(1 for ranked_method in ranked_methods if _has_flutter_bridge_hint(ranked_method.rec))
    flutter_ui_noise_hits = sum(1 for ranked_method in ranked_methods if _has_flutter_ui_noise(ranked_method.rec))
    return {
        "methods": len(ranked_methods),
        "classes": len(class_counts),
        "packages": len(package_counts),
        "flutter_bridge_hits": flutter_bridge_hits,
        "flutter_ui_noise_hits": flutter_ui_noise_hits,
        "top_classes": class_counts.most_common(5),
        "top_packages": package_counts.most_common(5),
    }


def pick_methods(
    methods: list[MethodRecord],
    include_packages: list[str],
    exclude_prefixes: list[str],
    vmp_count: int,
    dex2c_count: int,
    extract_count: int,
    min_score_vmp: int,
    min_score_dex2c: int,
    min_score_extract: int,
    *,
    flutter_mode: bool = False,
) -> tuple[list[RankedMethod], list[RankedMethod], list[RankedMethod]]:
    candidates = [
        m
        for m in methods
        if _in_selected_package(m.class_desc, include_packages, exclude_prefixes)
    ]

    d2c_ranked = sorted(
        (
            r
            for r in (score_for_dex2c(m, flutter_mode=flutter_mode) for m in candidates)
            if r.score >= min_score_dex2c
        ),
        key=lambda r: (-r.score, -r.rec.code_bytes, r.rec.spec),
    )

    selected_specs: set[str] = set()
    global_class_counts: Counter[str] = Counter()
    global_package_counts: Counter[str] = Counter()

    d2c_selected = _select_diverse_ranked(
        d2c_ranked,
        dex2c_count,
        selected_specs,
        preferred_class_cap=1,
        class_penalty=18,
        package_penalty=4,
    )
    d2c_class_counts, d2c_package_counts = _selection_counters(d2c_selected)
    global_class_counts.update(d2c_class_counts)
    global_package_counts.update(d2c_package_counts)

    vmp_ranked = sorted(
        (
            r
            for r in (score_for_vmp(m, flutter_mode=flutter_mode) for m in candidates)
            if r.score >= min_score_vmp
        ),
        key=lambda r: (-r.score, -r.rec.code_bytes, r.rec.spec),
    )
    vmp_selected = _select_diverse_ranked(
        vmp_ranked,
        vmp_count,
        selected_specs,
        base_class_counts=global_class_counts,
        base_package_counts=global_package_counts,
        preferred_class_cap=1,
        class_penalty=14,
        package_penalty=4,
    )
    vmp_class_counts, vmp_package_counts = _selection_counters(vmp_selected)
    global_class_counts.update(vmp_class_counts)
    global_package_counts.update(vmp_package_counts)

    extract_ranked = sorted(
        (
            r
            for r in (score_for_extract(m, flutter_mode=flutter_mode) for m in candidates)
            if r.score >= min_score_extract
        ),
        key=lambda r: (-r.score, -r.rec.code_bytes, r.rec.spec),
    )
    extract_selected = _select_diverse_ranked(
        extract_ranked,
        extract_count,
        selected_specs,
        base_class_counts=global_class_counts,
        base_package_counts=global_package_counts,
        preferred_class_cap=2,
        class_penalty=10,
        package_penalty=3,
    )

    return extract_selected, vmp_selected, d2c_selected


# --------- output ---------


def write_map(
    out_path: Path,
    include_packages: list[str],
    extract_selected: list[RankedMethod],
    vmp_selected: list[RankedMethod],
    d2c_selected: list[RankedMethod],
) -> None:
    lines: list[str] = []
    lines.append("# Auto-generated protection map")
    if include_packages:
        lines.append(f"# include-packages: {', '.join(include_packages)}")
    lines.append("# level: 0=none, 1=extract, 2=vmp, 3=dex2c")
    lines.append("")

    lines.append("# Phase 4.1 Extract")
    for r in extract_selected:
        lines.append(f"{r.rec.spec} 1")
    lines.append("")

    lines.append("# Phase 4.3 VMP DEX")
    for r in vmp_selected:
        lines.append(f"{r.rec.spec} 2")
    lines.append("")

    lines.append("# Phase 4.2 DEX2C")
    for r in d2c_selected:
        lines.append(f"{r.rec.spec} 3")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def write_report(
    report_path: Path,
    mode: str,
    profile: str,
    include_packages: list[str],
    exclude_prefixes: list[str],
    methods_total: int,
    methods_scoped: int,
    extract_selected: list[RankedMethod],
    vmp_selected: list[RankedMethod],
    d2c_selected: list[RankedMethod],
) -> None:
    payload = {
        "mode": mode,
        "profile": profile,
        "include_packages": include_packages,
        "exclude_prefixes": exclude_prefixes,
        "methods_total": methods_total,
        "methods_scoped": methods_scoped,
        "compiled_target": {
            "extract": len(extract_selected),
            "vmp": len(vmp_selected),
            "dex2c": len(d2c_selected),
        },
        "coverage": {
            "extract": _summarize_selection(extract_selected),
            "vmp": _summarize_selection(vmp_selected),
            "dex2c": _summarize_selection(d2c_selected),
            "all_selected": _summarize_selection(
                extract_selected + vmp_selected + d2c_selected
            ),
        },
        "selected": {
            "extract": [
                {
                    "spec": r.rec.spec,
                    "dex": r.rec.dex_name,
                    "score": r.score,
                    "code_bytes": r.rec.code_bytes,
                    "reasons": r.reasons,
                }
                for r in extract_selected
            ],
            "vmp": [
                {
                    "spec": r.rec.spec,
                    "dex": r.rec.dex_name,
                    "score": r.score,
                    "code_bytes": r.rec.code_bytes,
                    "reasons": r.reasons,
                }
                for r in vmp_selected
            ],
            "dex2c": [
                {
                    "spec": r.rec.spec,
                    "dex": r.rec.dex_name,
                    "score": r.score,
                    "code_bytes": r.rec.code_bytes,
                    "reasons": r.reasons,
                }
                for r in d2c_selected
            ],
        },
    }
    report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


# --------- CLI ---------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Generate protection-map from APK using local heuristics.")
    p.add_argument("--input-apk", required=True, help="target APK path")
    p.add_argument("--output-map", required=True, help="output protection-map path")
    p.add_argument(
        "--include-package",
        action="append",
        default=[],
        help="include Java package prefix (repeatable), e.g. com.example.app",
    )
    p.add_argument(
        "--exclude-prefix",
        action="append",
        default=[],
        help="exclude class descriptor prefix, e.g. Lcom/google/",
    )
    p.add_argument("--vmp-count", type=int, default=None, help="target VMP method count")
    p.add_argument("--dex2c-count", type=int, default=None, help="target DEX2C method count")
    p.add_argument("--extract-count", type=int, default=None, help="target extract method count")
    p.add_argument("--min-score-vmp", type=int, default=None, help="minimum VMP score")
    p.add_argument("--min-score-dex2c", type=int, default=None, help="minimum DEX2C score")
    p.add_argument("--min-score-extract", type=int, default=None, help="minimum extract score")
    p.add_argument(
        "--profile",
        default="balanced",
        choices=sorted(AUTO_PROTECT_PROFILES),
        help="smart selection profile: compat, balanced, strong, or extreme",
    )
    p.add_argument(
        "--report-json",
        default="",
        help="optional report JSON path with selected methods and reasons",
    )
    p.add_argument(
        "--flutter-mode",
        action="store_true",
        help="prefer Flutter plugin/channel bridge code and exclude core Flutter framework packages by default",
    )
    return p


def main() -> int:
    args = build_parser().parse_args()

    apk_path = Path(args.input_apk).resolve()
    out_map = Path(args.output_map).resolve()
    report_json = Path(args.report_json).resolve() if args.report_json else None

    if not apk_path.exists() or not apk_path.is_file():
        raise SystemExit(f"input apk not found: {apk_path}")

    methods = collect_methods_from_apk(apk_path)
    exclude_prefixes = list(args.exclude_prefix)
    if args.flutter_mode:
        for prefix in FLUTTER_FRAMEWORK_PREFIXES:
            if prefix not in exclude_prefixes:
                exclude_prefixes.append(prefix)

    if args.flutter_mode:
        inferred = _infer_top_flutter_packages(methods, exclude_prefixes=exclude_prefixes)
    else:
        inferred = _infer_top_packages(methods, exclude_prefixes=exclude_prefixes)
    include_packages = list(args.include_package)
    if not include_packages:
        include_packages = inferred
    profile = resolve_auto_protect_profile(args.profile, has_ndk=True)

    extract_selected, vmp_selected, d2c_selected = pick_methods(
        methods=methods,
        include_packages=include_packages,
        exclude_prefixes=exclude_prefixes,
        vmp_count=max(0, args.vmp_count if args.vmp_count is not None else profile.vmp_count),
        dex2c_count=max(0, args.dex2c_count if args.dex2c_count is not None else profile.dex2c_count),
        extract_count=max(0, args.extract_count if args.extract_count is not None else profile.extract_count),
        min_score_vmp=args.min_score_vmp if args.min_score_vmp is not None else profile.min_score_vmp,
        min_score_dex2c=args.min_score_dex2c if args.min_score_dex2c is not None else profile.min_score_dex2c,
        min_score_extract=args.min_score_extract if args.min_score_extract is not None else profile.min_score_extract,
        flutter_mode=bool(args.flutter_mode),
    )

    methods_scoped = len(
        [
            m
            for m in methods
            if _in_selected_package(m.class_desc, include_packages, exclude_prefixes)
        ]
    )

    out_map.parent.mkdir(parents=True, exist_ok=True)
    write_map(out_map, include_packages, extract_selected, vmp_selected, d2c_selected)

    if report_json:
        report_json.parent.mkdir(parents=True, exist_ok=True)
        write_report(
            report_path=report_json,
            mode="flutter" if args.flutter_mode else "default",
            profile=profile.name,
            include_packages=include_packages,
            exclude_prefixes=exclude_prefixes,
            methods_total=len(methods),
            methods_scoped=methods_scoped,
            extract_selected=extract_selected,
            vmp_selected=vmp_selected,
            d2c_selected=d2c_selected,
        )

    print(f"[*] methods total: {len(methods)}")
    print(f"[*] methods in scope: {methods_scoped}")
    print(f"[*] mode: {'flutter' if args.flutter_mode else 'default'}")
    print(f"[*] smart profile: {profile.name} ({profile.label})")
    print(f"[*] include-packages: {', '.join(include_packages) if include_packages else '(all non-system)'}")
    if exclude_prefixes:
        print(f"[*] exclude-prefixes: {', '.join(exclude_prefixes)}")
    print(f"[*] selected: extract={len(extract_selected)}, vmp={len(vmp_selected)}, dex2c={len(d2c_selected)}")
    all_summary = _summarize_selection(extract_selected + vmp_selected + d2c_selected)
    print(
        f"[*] selection coverage: classes={all_summary['classes']}, "
        f"packages={all_summary['packages']}"
    )
    if args.flutter_mode:
        print(
            f"[*] flutter bridge hits: {all_summary['flutter_bridge_hits']} "
            f"(ui-noise hits {all_summary['flutter_ui_noise_hits']})"
        )
    print(f"[ok] protection-map written: {out_map}")
    if report_json:
        print(f"[ok] report written: {report_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
