"""Generate per-method VMP JNI stub .so and compile with Android NDK.

Each VMP-protected method gets a thin JNI native stub that packs its typed
arguments into a ``jvalue`` array and calls ``enko_vmp_dispatch_jvalue`` in the
main ``libagpcore.so`` via a cached function pointer.  The stubs are compiled into
``libagpstub.so`` and placed into the APK's ``lib/<abi>/`` directories.
At runtime, ``enko_vmp_register_natives`` will ``dlopen`` the stub library and
call ``enko_vmp_stub_init`` to register the per-method natives.
"""

from __future__ import annotations

import platform
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Dalvik descriptor → JNI C type / jvalue field
# ---------------------------------------------------------------------------

_JNI_TYPE: dict[str, str] = {
    "Z": "jboolean",
    "B": "jbyte",
    "C": "jchar",
    "S": "jshort",
    "I": "jint",
    "J": "jlong",
    "F": "jfloat",
    "D": "jdouble",
    "V": "void",
}

_JVALUE_FIELD: dict[str, str] = {
    "Z": "z",
    "B": "b",
    "C": "c",
    "S": "s",
    "I": "i",
    "J": "j",
    "F": "f",
    "D": "d",
}

_UNBOX_FN: dict[str, str] = {
    "Z": "_ub_bool",
    "B": "_ub_byte",
    "C": "_ub_char",
    "S": "_ub_short",
    "I": "_ub_int",
    "J": "_ub_long",
    "F": "_ub_float",
    "D": "_ub_double",
}

_ABI_TARGET: dict[str, str] = {
    "armeabi-v7a": "armv7-none-linux-androideabi21",
    "arm64-v8a": "aarch64-none-linux-android21",
    "x86": "i686-none-linux-android21",
    "x86_64": "x86_64-none-linux-android21",
}

VMP_STUB_SO_NAME = "libagpstub.so"


# ---------------------------------------------------------------------------
# Signature parsing helpers
# ---------------------------------------------------------------------------

def _parse_params(sig: str) -> list[str]:
    """Parse a Dalvik method signature into a list of parameter descriptors."""
    lp = sig.index("(")
    rp = sig.index(")")
    s = sig[lp + 1 : rp]
    params: list[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c in "ZBCSIJFD":
            params.append(c)
            i += 1
        elif c == "L":
            end = s.index(";", i)
            params.append(s[i : end + 1])
            i = end + 1
        elif c == "[":
            start = i
            while i < len(s) and s[i] == "[":
                i += 1
            if i < len(s):
                if s[i] == "L":
                    end = s.index(";", i)
                    params.append(s[start : end + 1])
                    i = end + 1
                else:
                    params.append(s[start : i + 1])
                    i += 1
        else:
            i += 1
    return params


def _return_desc(sig: str) -> str:
    return sig[sig.index(")") + 1 :]


def _c_type(desc: str) -> str:
    return _JNI_TYPE.get(desc[0], "jobject")


def _jval_field(desc: str) -> str:
    return _JVALUE_FIELD.get(desc[0], "l")


def _desc_to_dot(class_desc: str) -> str:
    if class_desc.startswith("L") and class_desc.endswith(";"):
        return class_desc[1:-1].replace("/", ".")
    return class_desc


# ---------------------------------------------------------------------------
# C source generation
# ---------------------------------------------------------------------------

_C_PREAMBLE = r"""#include <jni.h>
#include <string.h>

typedef jobject (*vmp_dispatch_fn)(JNIEnv *, int, int, jobject, jvalue *, int);
static vmp_dispatch_fn g_dispatch = NULL;

/* Cached unbox method IDs */
static jmethodID g_mid_intValue, g_mid_longValue, g_mid_floatValue, g_mid_doubleValue;
static jmethodID g_mid_booleanValue, g_mid_charValue, g_mid_byteValue, g_mid_shortValue;

static jint    _ub_int(JNIEnv *e, jobject o)  { return  o ? (*e)->CallIntMethod(e, o, g_mid_intValue) : 0; }
static jlong   _ub_long(JNIEnv *e, jobject o) { return  o ? (*e)->CallLongMethod(e, o, g_mid_longValue) : 0; }
static jfloat  _ub_float(JNIEnv *e, jobject o){ return  o ? (*e)->CallFloatMethod(e, o, g_mid_floatValue) : 0; }
static jdouble _ub_double(JNIEnv *e, jobject o){return  o ? (*e)->CallDoubleMethod(e, o, g_mid_doubleValue) : 0; }
static jboolean _ub_bool(JNIEnv *e, jobject o){ return  o ? (*e)->CallBooleanMethod(e, o, g_mid_booleanValue) : 0; }
static jchar   _ub_char(JNIEnv *e, jobject o) { return  o ? (*e)->CallCharMethod(e, o, g_mid_charValue) : 0; }
static jbyte   _ub_byte(JNIEnv *e, jobject o) { return  o ? (*e)->CallByteMethod(e, o, g_mid_byteValue) : 0; }
static jshort  _ub_short(JNIEnv *e, jobject o){ return  o ? (*e)->CallShortMethod(e, o, g_mid_shortValue) : 0; }

/* Class resolution via ClassLoader */
static jclass _find_cls(JNIEnv *env, jobject loader, jmethodID mid, const char *dot) {
    jstring jn = (*env)->NewStringUTF(env, dot);
    if (!jn) return NULL;
    jobject c = (*env)->CallObjectMethod(env, loader, mid, jn);
    (*env)->DeleteLocalRef(env, jn);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return NULL; }
    return (jclass) c;
}

"""


def generate_stub_source(method_info_list: list[dict[str, Any]]) -> str:
    """Generate a complete C source file with per-method JNI stubs.

    Each *method_info* dict has: ``method_id``, ``class_desc``, ``method_name``,
    ``signature``, ``is_static``.
    """
    lines: list[str] = [_C_PREAMBLE]

    # ── Per-method stubs ──
    lines.append("/* ── Per-method JNI stubs ── */\n")
    for mi in method_info_list:
        mid = mi["method_id"]
        sig = mi["signature"]
        is_static = mi["is_static"]
        params = _parse_params(sig)
        ret = _return_desc(sig)
        ret_c = _c_type(ret)

        # Build C parameter list
        fp = ["JNIEnv *env"]
        fp.append("jclass _cls" if is_static else "jobject thiz")
        for pi, pd in enumerate(params):
            fp.append(f"{_c_type(pd)} p{pi}")

        lines.append(f"static {ret_c} _s{mid}({', '.join(fp)}) {{")

        nparams = len(params)
        if nparams > 0:
            lines.append(f"    jvalue a[{nparams}];")
            for pi, pd in enumerate(params):
                lines.append(f"    a[{pi}].{_jval_field(pd)} = p{pi};")
        else:
            lines.append("    jvalue *a = NULL;")

        thiz_arg = "NULL" if is_static else "thiz"
        is_s = 1 if is_static else 0
        call = f"g_dispatch(env, {mid}, {is_s}, {thiz_arg}, a, {nparams})"

        if ret == "V":
            lines.append(f"    {call};")
        elif ret[0] in ("L", "["):
            lines.append(f"    return {call};")
        else:
            ub = _UNBOX_FN.get(ret[0], "_ub_int")
            lines.append(f"    return {ub}(env, {call});")

        lines.append("}\n")

    # ── Init function ──
    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for mi in method_info_list:
        by_class[mi["class_desc"]].append(mi)

    lines.append("__attribute__((visibility(\"default\")))")
    lines.append("int enko_vmp_stub_init(JNIEnv *env, void *dispatch_ptr, jobject loader) {")
    lines.append("    g_dispatch = (vmp_dispatch_fn) dispatch_ptr;")
    lines.append("")
    lines.append("    /* Cache unbox method IDs */")
    lines.append('    jclass numCls = (*env)->FindClass(env, "java/lang/Number");')
    lines.append("    if (!numCls) return -1;")
    lines.append('    g_mid_intValue    = (*env)->GetMethodID(env, numCls, "intValue",    "()I");')
    lines.append('    g_mid_longValue   = (*env)->GetMethodID(env, numCls, "longValue",   "()J");')
    lines.append('    g_mid_floatValue  = (*env)->GetMethodID(env, numCls, "floatValue",  "()F");')
    lines.append('    g_mid_doubleValue = (*env)->GetMethodID(env, numCls, "doubleValue", "()D");')
    lines.append('    g_mid_byteValue   = (*env)->GetMethodID(env, numCls, "byteValue",   "()B");')
    lines.append('    g_mid_shortValue  = (*env)->GetMethodID(env, numCls, "shortValue",  "()S");')
    lines.append("    (*env)->DeleteLocalRef(env, numCls);")
    lines.append('    jclass boolCls = (*env)->FindClass(env, "java/lang/Boolean");')
    lines.append("    if (!boolCls) return -1;")
    lines.append('    g_mid_booleanValue = (*env)->GetMethodID(env, boolCls, "booleanValue", "()Z");')
    lines.append("    (*env)->DeleteLocalRef(env, boolCls);")
    lines.append('    jclass charCls = (*env)->FindClass(env, "java/lang/Character");')
    lines.append("    if (!charCls) return -1;")
    lines.append('    g_mid_charValue = (*env)->GetMethodID(env, charCls, "charValue", "()C");')
    lines.append("    (*env)->DeleteLocalRef(env, charCls);")
    lines.append("")
    lines.append("    /* Resolve ClassLoader.loadClass */")
    lines.append('    jclass loaderCls = (*env)->FindClass(env, "java/lang/ClassLoader");')
    lines.append("    if (!loaderCls) return -1;")
    lines.append('    jmethodID mid_lc = (*env)->GetMethodID(env, loaderCls, "loadClass",')
    lines.append('                           "(Ljava/lang/String;)Ljava/lang/Class;");')
    lines.append("    (*env)->DeleteLocalRef(env, loaderCls);")
    lines.append("    if (!mid_lc) return -1;")
    lines.append("")
    lines.append("    int total = 0;")

    for ci, (class_desc, methods) in enumerate(by_class.items()):
        dot_name = _desc_to_dot(class_desc)
        lines.append(f'    /* {class_desc} */')
        lines.append("    {")
        lines.append(f'        jclass c = _find_cls(env, loader, mid_lc, "{dot_name}");')
        lines.append("        if (c) {")
        lines.append(f"            JNINativeMethod m[] = {{")
        for mi in methods:
            mn = mi["method_name"]
            ms = mi["signature"]
            mid = mi["method_id"]
            lines.append(f'                {{"{mn}", "{ms}", (void *)_s{mid}}},')
        lines.append("            };")
        lines.append(f"            if ((*env)->RegisterNatives(env, c, m, {len(methods)}) == 0) {{")
        lines.append(f"                total += {len(methods)};")
        lines.append("            } else {")
        lines.append("                if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);")
        lines.append("            }")
        lines.append("            (*env)->DeleteLocalRef(env, c);")
        lines.append("        }")
        lines.append("    }")

    lines.append("    return total;")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# NDK compilation
# ---------------------------------------------------------------------------

def _ndk_host_tag() -> str:
    s = platform.system().lower()
    if s == "windows":
        return "windows-x86_64"
    elif s == "darwin":
        return "darwin-x86_64"
    return "linux-x86_64"


def _ndk_clang(ndk_path: str) -> Path:
    host = _ndk_host_tag()
    base = Path(ndk_path) / "toolchains" / "llvm" / "prebuilt" / host / "bin"
    if platform.system().lower() == "windows":
        for name in ("clang.exe", "clang.cmd"):
            p = base / name
            if p.exists():
                return p
        return base / "clang.exe"  # fallback
    return base / "clang"


def compile_stub_so(
    c_source: str, ndk_path: str, decoded_apk_dir: Path,
    lib_name: str = VMP_STUB_SO_NAME,
) -> int:
    """Compile the stub C source to a shared library for every ABI in the APK.

    Returns the number of ABIs for which a ``.so`` was produced.
    """
    lib_root = decoded_apk_dir / "lib"
    if not lib_root.exists():
        return 0

    abi_dirs = sorted([p for p in lib_root.iterdir() if p.is_dir()])
    if not abi_dirs:
        return 0

    clang = _ndk_clang(ndk_path)
    if not clang.exists():
        raise RuntimeError(f"NDK clang not found at {clang}")

    compiled = 0
    with tempfile.TemporaryDirectory(prefix="enko_vmp_stub_") as tmp:
        src_path = Path(tmp) / "enko_vmp_stub.c"
        src_path.write_text(c_source, encoding="utf-8")

        for abi_dir in abi_dirs:
            abi = abi_dir.name
            target = _ABI_TARGET.get(abi)
            if not target:
                print(f"[!] VMP stub: unsupported ABI {abi}, skipping")
                continue

            out_so = abi_dir / lib_name
            cmd = [
                str(clang),
                f"--target={target}",
                "-shared",
                "-fPIC",
                "-O2",
                "-Wall",
                "-Wno-unused-function",
                "-fstack-protector-strong",
                "-D_FORTIFY_SOURCE=2",
                "-Wl,-z,relro",
                "-Wl,-z,now",
                "-Wl,-z,noexecstack",
                "-o",
                str(out_so),
                str(src_path),
            ]
            print(f"[*] VMP stub: compiling for {abi}...")
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                print(f"[!] VMP stub compile failed for {abi}:")
                if result.stderr:
                    for line in result.stderr.strip().splitlines()[:10]:
                        print(f"  | {line}")
                continue

            compiled += 1
            size = out_so.stat().st_size if out_so.exists() else 0
            print(f"[*] VMP stub: {out_so.name} for {abi} ({size} bytes)")

    return compiled


def build_vmp_stubs(
    method_info_list: list[dict[str, Any]], ndk_path: str, decoded_apk_dir: Path,
    lib_name: str = VMP_STUB_SO_NAME,
) -> int:
    """Generate and compile VMP JNI stubs.

    Returns the number of ABIs for which the stub library was produced.
    """
    if not method_info_list:
        return 0

    c_source = generate_stub_source(method_info_list)
    return compile_stub_so(c_source, ndk_path, decoded_apk_dir, lib_name=lib_name)
