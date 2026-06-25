"""Dalvik → C/JNI translator.

Converts individual methods from Dalvik bytecode into C functions
that reproduce the same semantics via JNI API calls.

The generated C code is compiled with NDK into ``libagpjnix.so``.
At runtime, ``RegisterNatives`` binds the ACC_NATIVE-marked DEX methods
to the translated JNI functions.
"""
from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field
from typing import Iterator

import sys
from pathlib import Path

# Ensure sibling packer modules are importable.
_packer_dir = str(Path(__file__).resolve().parent.parent)
if _packer_dir not in sys.path:
    sys.path.insert(0, _packer_dir)

from dex_parser import (
    DexFile, CodeItem, EncodedCatchHandler, EncodedMethod, NO_INDEX,
)
from vmp_compiler import _FMT, _u16le, _s16le, _u32le, _s32le

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class D2CMethod:
    """One translated method."""
    class_desc: str        # e.g. "Lcom/example/Foo;"
    method_name: str
    signature: str         # e.g. "(II)V"
    is_static: bool
    func_name: str         # randomized C function name
    c_body: str            # complete C function body (source code)
    jni_sig: str           # JNI signature string


@dataclass
class D2CResult:
    methods: list[D2CMethod] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rand_name() -> str:
    return f"enko_d2c_{os.urandom(4).hex()}"


def _desc_to_jni_type(desc: str) -> str:
    """Convert a single type descriptor to C/JNI type."""
    if not desc:
        return "jobject"
    c = desc[0]
    _MAP = {
        "V": "void", "Z": "jboolean", "B": "jbyte", "C": "jchar",
        "S": "jshort", "I": "jint", "J": "jlong", "F": "jfloat",
        "D": "jdouble",
    }
    if c in _MAP:
        return _MAP[c]
    if c == "L" or c == "[":
        return "jobject"
    return "jobject"


def _desc_is_wide(desc: str) -> bool:
    return bool(desc and desc[0] in ("J", "D"))


def _desc_is_void(desc: str) -> bool:
    return desc == "V"


def _desc_is_ref(desc: str) -> bool:
    return bool(desc and desc[0] in ("L", "["))


def _iter_param_descs(sig: str) -> Iterator[str]:
    """Yield individual parameter type descriptors from a method signature ``(...)R``."""
    if not sig or sig[0] != "(":
        return
    i = 1
    while i < len(sig) and sig[i] != ")":
        start = i
        while sig[i] == "[":
            i += 1
        if sig[i] == "L":
            end = sig.index(";", i) + 1
            yield sig[start:end]
            i = end
        else:
            yield sig[start:i + 1]
            i += 1


def _return_desc(sig: str) -> str:
    """Extract return type descriptor from ``(...)R``."""
    idx = sig.index(")")
    return sig[idx + 1:]


def _jni_call_variant(ret_desc: str) -> str:
    """Return the JNI Call*Method suffix for a return type."""
    _MAP = {
        "V": "Void", "Z": "Boolean", "B": "Byte", "C": "Char",
        "S": "Short", "I": "Int", "J": "Long", "F": "Float", "D": "Double",
    }
    if ret_desc and ret_desc[0] in _MAP:
        return _MAP[ret_desc[0]]
    return "Object"


def _jni_field_variant(type_desc: str) -> str:
    _MAP = {
        "Z": "Boolean", "B": "Byte", "C": "Char",
        "S": "Short", "I": "Int", "J": "Long", "F": "Float", "D": "Double",
    }
    if type_desc and type_desc[0] in _MAP:
        return _MAP[type_desc[0]]
    return "Object"


def _reg_field(desc: str) -> str:
    """Return the vmp_reg_t union field name for a type descriptor."""
    c = desc[0] if desc else "I"
    _MAP = {
        "V": "i", "Z": "i", "B": "i", "C": "i", "S": "i", "I": "i",
        "J": "j", "F": "f", "D": "d", "L": "l", "[": "l",
    }
    return _MAP.get(c, "i")


def _desc_to_jni_slash(desc: str) -> str:
    """Convert ``Lcom/example/Foo;`` → ``com/example/Foo``."""
    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1]
    return desc


def _emit_default_return(lines: list[str], ret_desc: str) -> None:
    """Emit a return statement appropriate for the return type."""
    if _desc_is_void(ret_desc):
        lines.append(f"        return;")
    elif _desc_is_ref(ret_desc):
        lines.append(f"        return NULL;")
    else:
        lines.append(f"        return 0;")


def _translate_filled_new_array_35c(lines: list[str], dex: DexFile, insns: bytes, pos: int, word0: int, byte_off: int) -> None:
    a_count = (word0 >> 12) & 0x0F
    type_idx = _u16le(insns, byte_off + 2)
    regs_word = _u16le(insns, byte_off + 4)
    c = regs_word & 0x0F; d = (regs_word >> 4) & 0x0F
    e = (regs_word >> 8) & 0x0F; f = (regs_word >> 12) & 0x0F
    g = (word0 >> 8) & 0x0F
    arg_regs = [c, d, e, f, g][:a_count]
    type_desc = dex.type_name(type_idx)
    elem = type_desc[1:] if type_desc.startswith('[') else type_desc
    _P = {'I':('NewIntArray','SetIntArrayRegion','jint','i'),
          'J':('NewLongArray','SetLongArrayRegion','jlong','j'),
          'F':('NewFloatArray','SetFloatArrayRegion','jfloat','f'),
          'D':('NewDoubleArray','SetDoubleArrayRegion','jdouble','d'),
          'Z':('NewBooleanArray','SetBooleanArrayRegion','jboolean','i'),
          'B':('NewByteArray','SetByteArrayRegion','jbyte','i'),
          'C':('NewCharArray','SetCharArrayRegion','jchar','i'),
          'S':('NewShortArray','SetShortArrayRegion','jshort','i')}
    if elem in _P:
        nf, sf, et, rf = _P[elem]
        lines.append(f"    {{ jarray _a = (jarray)(*env)->{nf}(env, {a_count});")
        for i, ri in enumerate(arg_regs):
            lines.append(f"      {{ {et} _v = ({et})r[{ri}].{rf}; (*env)->{sf}(env, _a, {i}, 1, &_v); }}")
        lines.append(f"      _result.l = (jobject)_a; }}")
    else:
        en = _desc_to_jni_slash(elem) if elem.startswith('L') else elem
        lines.append(f'    {{ jclass _ec = d2c_find_class(env, "{en}");')
        lines.append(f"      jobjectArray _a = (*env)->NewObjectArray(env, {a_count}, _ec, NULL);")
        for i, ri in enumerate(arg_regs):
            lines.append(f"      (*env)->SetObjectArrayElement(env, _a, {i}, r[{ri}].l);")
        lines.append(f"      (*env)->DeleteLocalRef(env, _ec); _result.l = (jobject)_a; }}")
    lines.append(f"    if ((*env)->ExceptionCheck(env)) goto _exc_handler;")


def _translate_filled_new_array_3rc(lines: list[str], dex: DexFile, insns: bytes, pos: int, word0: int, byte_off: int) -> None:
    a_count = (word0 >> 8) & 0xFF
    type_idx = _u16le(insns, byte_off + 2)
    start_reg = _u16le(insns, byte_off + 4)
    type_desc = dex.type_name(type_idx)
    elem = type_desc[1:] if type_desc.startswith('[') else type_desc
    _P = {'I':('NewIntArray','SetIntArrayRegion','jint','i'),
          'J':('NewLongArray','SetLongArrayRegion','jlong','j'),
          'F':('NewFloatArray','SetFloatArrayRegion','jfloat','f'),
          'D':('NewDoubleArray','SetDoubleArrayRegion','jdouble','d'),
          'Z':('NewBooleanArray','SetBooleanArrayRegion','jboolean','i'),
          'B':('NewByteArray','SetByteArrayRegion','jbyte','i'),
          'C':('NewCharArray','SetCharArrayRegion','jchar','i'),
          'S':('NewShortArray','SetShortArrayRegion','jshort','i')}
    if elem in _P:
        nf, sf, et, rf = _P[elem]
        lines.append(f"    {{ jarray _a = (jarray)(*env)->{nf}(env, {a_count});")
        for i in range(a_count):
            ri = start_reg + i
            lines.append(f"      {{ {et} _v = ({et})r[{ri}].{rf}; (*env)->{sf}(env, _a, {i}, 1, &_v); }}")
        lines.append(f"      _result.l = (jobject)_a; }}")
    else:
        en = _desc_to_jni_slash(elem) if elem.startswith('L') else elem
        lines.append(f'    {{ jclass _ec = d2c_find_class(env, "{en}");')
        lines.append(f"      jobjectArray _a = (*env)->NewObjectArray(env, {a_count}, _ec, NULL);")
        for i in range(a_count):
            ri = start_reg + i
            lines.append(f"      (*env)->SetObjectArrayElement(env, _a, {i}, r[{ri}].l);")
        lines.append(f"      (*env)->DeleteLocalRef(env, _ec); _result.l = (jobject)_a; }}")
    lines.append(f"    if ((*env)->ExceptionCheck(env)) goto _exc_handler;")


def _translate_fill_array_data(lines: list[str], dex: DexFile, insns: bytes, pos: int, word0: int, byte_off: int) -> None:
    a = (word0 >> 8) & 0xFF
    off_lo = _u16le(insns, byte_off + 2); off_hi = _u16le(insns, byte_off + 4)
    off = off_lo | (off_hi << 16)
    if off & 0x80000000: off -= 0x100000000
    ppos = (pos + off) * 2
    ew = _u16le(insns, ppos + 2)  # element width
    size = _u32le(insns, ppos + 4)
    doff = ppos + 8
    if ew == 1:
        vals = ', '.join(f'0x{insns[doff + i]:02x}' for i in range(size))
        lines.append(f"    {{ static const jbyte _d[] = {{ {vals} }};")
        lines.append(f"      (*env)->SetByteArrayRegion(env, (jbyteArray)r[{a}].l, 0, {size}, _d); }}")
    elif ew == 2:
        vals = ', '.join(str(_s16le(insns, doff + i*2)) for i in range(size))
        lines.append(f"    {{ static const jshort _d[] = {{ {vals} }};")
        lines.append(f"      (*env)->SetShortArrayRegion(env, (jshortArray)r[{a}].l, 0, {size}, _d); }}")
    elif ew == 4:
        vals = ', '.join(str(_s32le(insns, doff + i*4)) for i in range(size))
        lines.append(f"    {{ static const jint _d[] = {{ {vals} }};")
        lines.append(f"      (*env)->SetIntArrayRegion(env, (jintArray)r[{a}].l, 0, {size}, _d); }}")
    elif ew == 8:
        parts = []
        for i in range(size):
            lo = _u32le(insns, doff + i*8); hi = _u32le(insns, doff + i*8 + 4)
            parts.append(f"{lo | (hi << 32)}LL")
        vals = ', '.join(parts)
        lines.append(f"    {{ static const jlong _d[] = {{ {vals} }};")
        lines.append(f"      (*env)->SetLongArrayRegion(env, (jlongArray)r[{a}].l, 0, {size}, _d); }}")
    else:
        raise NotImplementedError(f"fill-array-data elem_width={ew} at pos={pos}")
    lines.append(f"    if ((*env)->ExceptionCheck(env)) goto _exc_handler;")


# ---------------------------------------------------------------------------
# Eligibility scan
# ---------------------------------------------------------------------------

# Dalvik opcodes the DEX2C translator does not (yet) emit C/JNI code for.
# Methods containing any of these are routed away from DEX2C — they should
# fall back to VMP or method-extract, both of which handle these opcodes.
# Keeping this list explicit (instead of relying on the translator raising
# NotImplementedError mid-way) lets the caller log a clean reason and pick
# an alternate protection level instead of silently dropping the method.
_D2C_UNSUPPORTED_OPCODES: dict[int, str] = {
    0xFA: "invoke-polymorphic",
    0xFB: "invoke-polymorphic/range",
    0xFC: "invoke-custom",
    0xFD: "invoke-custom/range",
    0xFE: "const-method-handle",
    0xFF: "const-method-type",
}


def method_d2c_eligibility(code: "CodeItem | None") -> tuple[bool, str]:
    """Return (eligible, reason). reason is empty when eligible.

    Walks the instruction stream looking for opcodes the DEX2C translator
    cannot produce C code for. We use vmp_compiler._FMT for instruction
    widths so the walker stays in sync with the same table VMP uses.
    """
    if code is None or code.insns_size == 0:
        return False, "no code"
    insns = code.insns
    pos = 0
    while pos < code.insns_size:
        byte_off = pos * 2
        if byte_off + 2 > len(insns):
            return False, "truncated insn stream"
        word0 = _u16le(insns, byte_off)
        opcode = word0 & 0xFF
        if opcode in _D2C_UNSUPPORTED_OPCODES:
            return False, _D2C_UNSUPPORTED_OPCODES[opcode]
        fmt = _FMT.get(opcode)
        if fmt is None:
            return False, f"unknown opcode 0x{opcode:02x}"
        pos += fmt[1]
    return True, ""


# ---------------------------------------------------------------------------
# Core translator
# ---------------------------------------------------------------------------

def translate_method(
    dex: DexFile,
    method_idx: int,
    em: EncodedMethod,
    func_name: str | None = None,
) -> D2CMethod:
    """Translate one Dalvik method to a C/JNI function."""
    mid = dex.method_ids[method_idx]
    class_desc = dex.type_name(mid.class_idx)
    method_name = dex.strings[mid.name_idx]
    signature = dex.method_signature(method_idx)
    is_static = bool(em.access_flags & 0x0008)
    code = em.code
    assert code is not None

    fname = func_name or _rand_name()

    # Build parameter list for C function.
    param_descs = list(_iter_param_descs(signature))
    ret_desc = _return_desc(signature)
    jni_ret = _desc_to_jni_type(ret_desc)

    # Build C parameter list: (JNIEnv *env, jobject/jclass, ...)
    c_params = ["JNIEnv *env"]
    if is_static:
        c_params.append("jclass _clz")
    else:
        c_params.append("jobject _thiz")

    for i, pd in enumerate(param_descs):
        c_params.append(f"{_desc_to_jni_type(pd)} _p{i}")

    c_proto = f"static {jni_ret} {fname}({', '.join(c_params)})"

    # Build function body.
    lines: list[str] = []
    lines.append(f"{c_proto} {{")
    lines.append(f"    (void)env;")
    if is_static:
        lines.append(f"    (void)_clz;")
    else:
        lines.append(f"    (void)_thiz;")

    # Register file: use a union type for each register.
    num_regs = code.registers_size
    lines.append(f"    /* {num_regs} registers */")
    lines.append(f"    jvalue r[{max(num_regs, 1)}];")
    lines.append(f"    memset(r, 0, sizeof(r));")

    # Map incoming parameters to registers (Dalvik convention: params at end).
    param_start = num_regs - code.ins_size
    reg_idx = param_start
    if not is_static:
        lines.append(f"    r[{reg_idx}].l = _thiz;")
        reg_idx += 1
    for i, pd in enumerate(param_descs):
        rf = _reg_field(pd)
        lines.append(f"    r[{reg_idx}].{rf} = _p{i};")
        reg_idx += 2 if _desc_is_wide(pd) else 1

    # Exception handling state.
    lines.append(f"    jobject _exc = NULL;")
    lines.append(f"    jvalue _result; memset(&_result, 0, sizeof(_result));")
    has_tries = bool(code.tries)
    if has_tries:
        lines.append(f"    jint _pc = 0;")
    lines.append("")

    # Track which registers hold object references for if-eq/if-ne semantics.
    ref_regs: set[int] = set()
    _ri = param_start
    if not is_static:
        ref_regs.add(_ri)
        _ri += 1
    for _pd in param_descs:
        if _desc_is_ref(_pd):
            ref_regs.add(_ri)
        _ri += 2 if _desc_is_wide(_pd) else 1

    # Translate each Dalvik instruction to C code.
    insns = code.insns
    pos = 0  # position in code units
    while pos < code.insns_size:
        byte_off = pos * 2
        word0 = _u16le(insns, byte_off)
        opcode = word0 & 0xFF

        lines.append(f"  L_{pos}:;")  # label for goto targets
        if has_tries:
            lines.append(f"    _pc = {pos};")

        fmt_info = _FMT.get(opcode)
        if fmt_info is None:
            raise NotImplementedError(f"unknown opcode 0x{opcode:02x} at insn_pos={pos}")

        fmt, width = fmt_info
        _translate_insn(lines, dex, insns, pos, opcode, fmt, width, code, is_static, ret_desc, ref_regs)
        _update_ref_regs(ref_regs, dex, insns, pos, opcode, word0, byte_off)
        pos += width

    # Fallthrough return (should not normally be reached).
    lines.append(f"  L_{code.insns_size}:;")
    if _desc_is_void(ret_desc):
        lines.append(f"    return;")
    elif _desc_is_ref(ret_desc):
        lines.append(f"    return NULL;")
    else:
        lines.append(f"    return 0;")

    # Exception handler with try/catch dispatch.
    lines.append(f"  _exc_handler:;")
    lines.append(f"    _exc = (*env)->ExceptionOccurred(env);")
    lines.append(f"    if (!_exc) {{")
    _emit_default_return(lines, ret_desc)
    lines.append(f"    }}")
    lines.append(f"    (*env)->ExceptionClear(env);")

    if has_tries:
        # Build handler_off → EncodedCatchHandler lookup.
        _handler_by_off: dict[int, EncodedCatchHandler] = {}
        for _ech in code.catch_handlers:
            _handler_by_off[_ech._list_offset] = _ech
        # Dispatch based on _pc and try ranges.
        for _ti, _try in enumerate(code.tries):
            _end = _try.start_addr + _try.insn_count
            lines.append(f"    if (_pc >= {_try.start_addr} && _pc < {_end}) goto _try_{_ti}_dispatch;")

    # No matching try block: re-throw.
    lines.append(f"    (*env)->Throw(env, (jthrowable)_exc);")
    _emit_default_return(lines, ret_desc)

    if has_tries:
        # Per-try-block dispatch labels.
        for _ti, _try in enumerate(code.tries):
            lines.append(f"  _try_{_ti}_dispatch:;")
            _catch_entry = _handler_by_off.get(_try.handler_off)
            if _catch_entry:
                for _ch in _catch_entry.handlers:
                    _tn = _desc_to_jni_slash(dex.type_name(_ch.type_idx))
                    lines.append(f'    {{ jclass _hc = d2c_find_class(env, "{_tn}");')
                    lines.append(f'      if ((*env)->IsInstanceOf(env, _exc, _hc)) {{')
                    lines.append(f'        (*env)->DeleteLocalRef(env, _hc);')
                    lines.append(f'        goto L_{_ch.addr};')
                    lines.append(f'      }}')
                    lines.append(f'      (*env)->DeleteLocalRef(env, _hc); }}')
                if _catch_entry.catch_all_addr >= 0:
                    lines.append(f"    goto L_{_catch_entry.catch_all_addr};")
                else:
                    lines.append(f"    (*env)->Throw(env, (jthrowable)_exc);")
                    _emit_default_return(lines, ret_desc)
            else:
                lines.append(f"    (*env)->Throw(env, (jthrowable)_exc);")
                _emit_default_return(lines, ret_desc)

    lines.append(f"}}")

    return D2CMethod(
        class_desc=class_desc,
        method_name=method_name,
        signature=signature,
        is_static=is_static,
        func_name=fname,
        c_body="\n".join(lines),
        jni_sig=signature,
    )


# ---------------------------------------------------------------------------
# Per-instruction translation
# ---------------------------------------------------------------------------

def _update_ref_regs(
    ref_regs: set[int],
    dex: DexFile,
    insns: bytes,
    pos: int,
    opcode: int,
    word0: int,
    byte_off: int,
) -> None:
    """Update *ref_regs* after an instruction is emitted."""
    # Instructions whose destination is always an object reference.
    _REF_DEST_11x = {0x0C, 0x0D}  # move-result-object, move-exception
    _REF_DEST_21c = {0x1A, 0x1B, 0x1C, 0x22}  # const-string, const-class, new-instance
    _REF_DEST_22c_new_array = 0x23

    # move-object (12x / 22x / 32x) — destination is ref
    if opcode in (0x07, 0x08, 0x09):
        if opcode == 0x07:  # 12x
            a = (word0 >> 8) & 0x0F
        elif opcode == 0x08:  # 22x
            a = (word0 >> 8) & 0xFF
        else:  # 32x
            a = _u16le(insns, byte_off + 2)
        ref_regs.add(a)
        return

    # move-result-object, move-exception
    if opcode in _REF_DEST_11x:
        a = (word0 >> 8) & 0xFF
        ref_regs.add(a)
        return

    # const-string, const-string/jumbo, const-class, new-instance
    if opcode in _REF_DEST_21c:
        a = (word0 >> 8) & 0xFF
        ref_regs.add(a)
        return

    # new-array (22c)
    if opcode == _REF_DEST_22c_new_array:
        a = (word0 >> 8) & 0x0F
        ref_regs.add(a)
        return

    # aget-object (23x) — destination is ref
    if opcode == 0x46:
        a = (word0 >> 8) & 0xFF
        ref_regs.add(a)
        return

    # iget-object (0x54), sget-object (0x62)
    if opcode == 0x54:
        a = (word0 >> 8) & 0x0F
        ref_regs.add(a)
        return
    if opcode == 0x62:
        a = (word0 >> 8) & 0xFF
        ref_regs.add(a)
        return

    # --- Instructions whose dest is NOT a ref — discard from ref_regs ---
    # move (12x / 22x / 32x)
    if opcode in (0x01, 0x02, 0x03):
        if opcode == 0x01:
            a = (word0 >> 8) & 0x0F
        elif opcode == 0x02:
            a = (word0 >> 8) & 0xFF
        else:
            a = _u16le(insns, byte_off + 2)
        ref_regs.discard(a)
        return
    # move-wide
    if opcode in (0x04, 0x05, 0x06):
        if opcode == 0x04:
            a = (word0 >> 8) & 0x0F
        elif opcode == 0x05:
            a = (word0 >> 8) & 0xFF
        else:
            a = _u16le(insns, byte_off + 2)
        ref_regs.discard(a)
        ref_regs.discard(a + 1)
        return
    # move-result, move-result-wide
    if opcode in (0x0A, 0x0B):
        a = (word0 >> 8) & 0xFF
        ref_regs.discard(a)
        if opcode == 0x0B:
            ref_regs.discard(a + 1)
        return
    # const, const-wide → dest is int/long
    if 0x12 <= opcode <= 0x19:
        a = (word0 >> 8) & (0x0F if opcode == 0x12 else 0xFF)
        ref_regs.discard(a)
        return
    # instance-of, array-length → dest is int
    if opcode == 0x20:
        a = (word0 >> 8) & 0x0F
        ref_regs.discard(a)
        return
    if opcode == 0x21:
        a = (word0 >> 8) & 0x0F
        ref_regs.discard(a)
        return
    # aget non-object, iget non-object, sget non-object, binops, unops → dest not ref
    if (0x44 <= opcode <= 0x4A) and opcode != 0x46:
        a = (word0 >> 8) & 0xFF
        ref_regs.discard(a)
        return
    if (0x52 <= opcode <= 0x58) and opcode != 0x54:
        a = (word0 >> 8) & 0x0F
        ref_regs.discard(a)
        return
    if (0x60 <= opcode <= 0x66) and opcode != 0x62:
        a = (word0 >> 8) & 0xFF
        ref_regs.discard(a)
        return
    if 0x7B <= opcode <= 0x8F:
        a = (word0 >> 8) & 0x0F
        ref_regs.discard(a)
        return
    if 0x90 <= opcode <= 0xAF:
        a = (word0 >> 8) & 0xFF
        ref_regs.discard(a)
        return
    if 0xB0 <= opcode <= 0xCF:
        a = (word0 >> 8) & 0x0F
        ref_regs.discard(a)
        return
    if 0xD0 <= opcode <= 0xE2:
        a = (word0 >> 8) & (0x0F if 0xD0 <= opcode <= 0xD7 else 0xFF)
        ref_regs.discard(a)
        return
    # cmp → dest is int
    if 0x2D <= opcode <= 0x31:
        a = (word0 >> 8) & 0xFF
        ref_regs.discard(a)
        return


def _translate_insn(
    lines: list[str],
    dex: DexFile,
    insns: bytes,
    pos: int,
    opcode: int,
    fmt: str,
    width: int,
    code: CodeItem,
    is_static: bool,
    ret_desc: str,
    ref_regs: set[int] | None = None,
) -> None:
    """Append C lines for one Dalvik instruction."""
    byte_off = pos * 2
    word0 = _u16le(insns, byte_off)

    # NOP
    if opcode == 0x00:
        lines.append(f"    /* nop */")
        return

    # ── Return ──
    if opcode == 0x0E:  # return-void
        if _desc_is_void(ret_desc):
            lines.append(f"    return;")
        else:
            # Some obfuscated inputs contain malformed return-void opcodes in
            # non-void methods. Emit a typed default return so generated C
            # stays compilable instead of failing the whole DEX2C batch.
            lines.append(f"    /* malformed return-void in non-void method */")
            _emit_default_return(lines, ret_desc)
        return
    if opcode == 0x0F:  # return (32-bit)
        a = (word0 >> 8) & 0xFF
        if ret_desc and ret_desc[0] == "F":
            lines.append(f"    return r[{a}].f;")
        else:
            lines.append(f"    return r[{a}].i;")
        return
    if opcode == 0x10:  # return-wide (64-bit)
        a = (word0 >> 8) & 0xFF
        if ret_desc and ret_desc[0] == "D":
            lines.append(f"    return r[{a}].d;")
        else:
            lines.append(f"    return r[{a}].j;")
        return
    if opcode == 0x11:  # return-object
        a = (word0 >> 8) & 0xFF
        lines.append(f"    return r[{a}].l;")
        return

    # ── Const ──
    if opcode == 0x12:  # const/4
        a = (word0 >> 8) & 0x0F
        b = (word0 >> 12) & 0x0F
        if b & 0x8:
            b -= 16
        lines.append(f"    r[{a}].i = {b};")
        return
    if opcode == 0x13:  # const/16
        a = (word0 >> 8) & 0xFF
        b = _s16le(insns, byte_off + 2)
        lines.append(f"    r[{a}].i = {b};")
        return
    if opcode == 0x14:  # const
        a = (word0 >> 8) & 0xFF
        lo = _u16le(insns, byte_off + 2)
        hi = _u16le(insns, byte_off + 4)
        val = lo | (hi << 16)
        if val & 0x80000000:
            val -= 0x100000000
        lines.append(f"    r[{a}].i = {val};")
        return
    if opcode == 0x15:  # const/high16
        a = (word0 >> 8) & 0xFF
        b = _s16le(insns, byte_off + 2)
        lines.append(f"    r[{a}].i = {b << 16};")
        return

    # ── Const-wide ──
    if opcode in (0x16, 0x17, 0x18, 0x19):
        a = (word0 >> 8) & 0xFF
        if opcode == 0x16:
            val = _s16le(insns, byte_off + 2)
            lines.append(f"    r[{a}].j = (jlong){val}LL;")
        elif opcode == 0x17:
            lo = _u16le(insns, byte_off + 2)
            hi = _u16le(insns, byte_off + 4)
            val = lo | (hi << 16)
            if val & 0x80000000:
                val -= 0x100000000
            lines.append(f"    r[{a}].j = (jlong){val}LL;")
        elif opcode == 0x18:
            val = 0
            for i in range(4):
                val |= _u16le(insns, byte_off + 2 + i * 2) << (i * 16)
            lines.append(f"    r[{a}].j = (jlong){val}LL;")
        elif opcode == 0x19:
            b = _s16le(insns, byte_off + 2)
            lines.append(f"    r[{a}].j = (jlong){b}LL << 48;")
        return

    # ── Const-string ──
    if opcode in (0x1A, 0x1B):
        a = (word0 >> 8) & 0xFF
        if opcode == 0x1A:
            idx = _u16le(insns, byte_off + 2)
        else:
            lo = _u16le(insns, byte_off + 2)
            hi = _u16le(insns, byte_off + 4)
            idx = lo | (hi << 16)
        s = dex.strings[idx] if idx < len(dex.strings) else ""
        escaped = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
        lines.append(f'    r[{a}].l = (*env)->NewStringUTF(env, "{escaped}");')
        return

    # ── Move ──
    if opcode in (0x01, 0x02, 0x03,  # move
                  0x04, 0x05, 0x06,  # move-wide
                  0x07, 0x08, 0x09):  # move-object
        if fmt == "12x":
            a = (word0 >> 8) & 0x0F
            b = (word0 >> 12) & 0x0F
        elif fmt == "22x":
            a = (word0 >> 8) & 0xFF
            b = _u16le(insns, byte_off + 2)
        else:
            a = _u16le(insns, byte_off + 2)
            b = _u16le(insns, byte_off + 4)
        lines.append(f"    r[{a}] = r[{b}];")
        return

    # ── Move-result ──
    if opcode in (0x0A, 0x0B, 0x0C):
        a = (word0 >> 8) & 0xFF
        lines.append(f"    r[{a}] = _result;")
        return
    if opcode == 0x0D:  # move-exception
        a = (word0 >> 8) & 0xFF
        lines.append(f"    r[{a}].l = _exc;")
        lines.append(f"    _exc = NULL;")
        return

    # ── Goto ──
    if opcode == 0x28:
        a = (word0 >> 8) & 0xFF
        if a & 0x80:
            a -= 256
        target = pos + a
        lines.append(f"    goto L_{target};")
        return
    if opcode == 0x29:
        target = pos + _s16le(insns, byte_off + 2)
        lines.append(f"    goto L_{target};")
        return
    if opcode == 0x2A:
        lo = _u16le(insns, byte_off + 2)
        hi = _u16le(insns, byte_off + 4)
        off = lo | (hi << 16)
        if off & 0x80000000:
            off -= 0x100000000
        target = pos + off
        lines.append(f"    goto L_{target};")
        return

    # ── If-test (22t) ──
    if 0x32 <= opcode <= 0x37:
        a = (word0 >> 8) & 0x0F
        b = (word0 >> 12) & 0x0F
        target = pos + _s16le(insns, byte_off + 2)
        _rr = ref_regs or set()
        # if-eq / if-ne with object references → IsSameObject
        if opcode == 0x32 and a in _rr and b in _rr:
            lines.append(f"    if ((*env)->IsSameObject(env, r[{a}].l, r[{b}].l)) goto L_{target};")
        elif opcode == 0x33 and a in _rr and b in _rr:
            lines.append(f"    if (!(*env)->IsSameObject(env, r[{a}].l, r[{b}].l)) goto L_{target};")
        else:
            ops = {0x32: "==", 0x33: "!=", 0x34: "<", 0x35: ">=", 0x36: ">", 0x37: "<="}
            op = ops[opcode]
            lines.append(f"    if (r[{a}].i {op} r[{b}].i) goto L_{target};")
        return

    # ── If-testz (21t) ──
    if 0x38 <= opcode <= 0x3D:
        a = (word0 >> 8) & 0xFF
        target = pos + _s16le(insns, byte_off + 2)
        _rr = ref_regs or set()
        # if-eqz / if-nez on object reference → compare .l with NULL
        if opcode == 0x38 and a in _rr:
            lines.append(f"    if (r[{a}].l == NULL) goto L_{target};")
        elif opcode == 0x39 and a in _rr:
            lines.append(f"    if (r[{a}].l != NULL) goto L_{target};")
        else:
            ops = {0x38: "==", 0x39: "!=", 0x3A: "<", 0x3B: ">=", 0x3C: ">", 0x3D: "<="}
            op = ops[opcode]
            lines.append(f"    if (r[{a}].i {op} 0) goto L_{target};")
        return

    # ── New-instance (21c) ──
    if opcode == 0x22:
        a = (word0 >> 8) & 0xFF
        type_idx = _u16le(insns, byte_off + 2)
        type_name = _desc_to_jni_slash(dex.type_name(type_idx))
        lines.append(f'    {{ jclass _c = d2c_find_class(env, "{type_name}");')
        lines.append(f'      r[{a}].l = (*env)->AllocObject(env, _c);')
        lines.append(f"      (*env)->DeleteLocalRef(env, _c); }}")
        lines.append(f"    if ((*env)->ExceptionCheck(env)) goto _exc_handler;")
        return

    # ── Throw ──
    if opcode == 0x27:
        a = (word0 >> 8) & 0xFF
        lines.append(f"    (*env)->Throw(env, (jthrowable)r[{a}].l);")
        lines.append(f"    goto _exc_handler;")
        return

    # ── Invoke-kind (35c) ──
    if 0x6E <= opcode <= 0x72:
        _translate_invoke_35c(lines, dex, insns, pos, opcode, word0, byte_off)
        return

    # ── Invoke-kind/range (3rc) ──
    if 0x74 <= opcode <= 0x78:
        _translate_invoke_3rc(lines, dex, insns, pos, opcode, word0, byte_off)
        return

    # ── Iget/iput (22c) ──
    if 0x52 <= opcode <= 0x5F:
        _translate_ifield(lines, dex, insns, pos, opcode, word0, byte_off)
        return

    # ── Sget/sput (21c) ──
    if 0x60 <= opcode <= 0x6D:
        _translate_sfield(lines, dex, insns, pos, opcode, word0, byte_off)
        return

    # ── Array-length (12x) ──
    if opcode == 0x21:
        a = (word0 >> 8) & 0x0F
        b = (word0 >> 12) & 0x0F
        lines.append(f"    r[{a}].i = (*env)->GetArrayLength(env, (jarray)r[{b}].l);")
        return

    # ── Binop/2addr (12x) ──
    if 0xB0 <= opcode <= 0xCF:
        _translate_binop_2addr(lines, opcode, word0)
        return

    # ── Binop (23x) ──
    if 0x90 <= opcode <= 0xAF:
        _translate_binop_23x(lines, insns, byte_off, opcode, word0)
        return

    # ── Binop/lit16 (22s) ──
    if 0xD0 <= opcode <= 0xD7:
        _translate_binop_lit16(lines, insns, byte_off, opcode, word0)
        return

    # ── Binop/lit8 (22b) ──
    if 0xD8 <= opcode <= 0xE2:
        _translate_binop_lit8(lines, insns, byte_off, opcode, word0)
        return

    # ── Unary ops (12x) ──
    if 0x7B <= opcode <= 0x8F:
        _translate_unop(lines, opcode, word0)
        return

    # ── Const-class (21c) ──
    if opcode == 0x1C:
        a = (word0 >> 8) & 0xFF
        type_idx = _u16le(insns, byte_off + 2)
        type_name = _desc_to_jni_slash(dex.type_name(type_idx))
        lines.append(f'    r[{a}].l = d2c_find_class(env, "{type_name}");')
        lines.append(f"    if ((*env)->ExceptionCheck(env)) goto _exc_handler;")
        return

    # ── Check-cast (21c) ──
    if opcode == 0x1F:
        a = (word0 >> 8) & 0xFF
        type_idx = _u16le(insns, byte_off + 2)
        type_name = _desc_to_jni_slash(dex.type_name(type_idx))
        lines.append(f'    {{ jclass _cc = d2c_find_class(env, "{type_name}");')
        lines.append(f'      if (r[{a}].l != NULL && !(*env)->IsInstanceOf(env, r[{a}].l, _cc)) {{')
        lines.append(f'        (*env)->DeleteLocalRef(env, _cc);')
        lines.append(f'        jclass _cce = d2c_find_class(env, "java/lang/ClassCastException");')
        lines.append(f'        (*env)->ThrowNew(env, _cce, NULL);')
        lines.append(f'        (*env)->DeleteLocalRef(env, _cce);')
        _emit_default_return(lines, ret_desc)
        lines.append(f'      }}')
        lines.append(f'      (*env)->DeleteLocalRef(env, _cc); }}')
        return

    # ── Instance-of (22c) ──
    if opcode == 0x20:
        a = (word0 >> 8) & 0x0F
        b = (word0 >> 12) & 0x0F
        type_idx = _u16le(insns, byte_off + 2)
        type_name = _desc_to_jni_slash(dex.type_name(type_idx))
        lines.append(f'    {{ jclass _cc = d2c_find_class(env, "{type_name}");')
        lines.append(f'      r[{a}].i = (*env)->IsInstanceOf(env, r[{b}].l, _cc);')
        lines.append(f'      (*env)->DeleteLocalRef(env, _cc); }}')
        return

    # ── Monitor-enter / monitor-exit (11x) ──
    if opcode == 0x1D:
        a = (word0 >> 8) & 0xFF
        lines.append(f"    (*env)->MonitorEnter(env, r[{a}].l);")
        lines.append(f"    if ((*env)->ExceptionCheck(env)) goto _exc_handler;")
        return
    if opcode == 0x1E:
        a = (word0 >> 8) & 0xFF
        lines.append(f"    (*env)->MonitorExit(env, r[{a}].l);")
        lines.append(f"    if ((*env)->ExceptionCheck(env)) goto _exc_handler;")
        return

    # ── New-array (22c) ──
    if opcode == 0x23:
        a = (word0 >> 8) & 0x0F
        b = (word0 >> 12) & 0x0F
        type_idx = _u16le(insns, byte_off + 2)
        type_desc_val = dex.type_name(type_idx)
        elem = type_desc_val[1:] if type_desc_val.startswith('[') else type_desc_val
        _P = {'I':'NewIntArray','J':'NewLongArray','F':'NewFloatArray','D':'NewDoubleArray',
              'Z':'NewBooleanArray','B':'NewByteArray','C':'NewCharArray','S':'NewShortArray'}
        if elem in _P:
            lines.append(f"    r[{a}].l = (*env)->{_P[elem]}(env, r[{b}].i);")
        else:
            en = _desc_to_jni_slash(elem) if elem.startswith('L') else elem
            lines.append(f'    {{ jclass _ec = d2c_find_class(env, "{en}");')
            lines.append(f'      r[{a}].l = (*env)->NewObjectArray(env, r[{b}].i, _ec, NULL);')
            lines.append(f'      (*env)->DeleteLocalRef(env, _ec); }}')
        lines.append(f"    if ((*env)->ExceptionCheck(env)) goto _exc_handler;")
        return

    # ── Aget (23x) ──
    if 0x44 <= opcode <= 0x4A:
        a = (word0 >> 8) & 0xFF
        w1 = _u16le(insns, byte_off + 2); b = w1 & 0xFF; c_reg = (w1 >> 8) & 0xFF
        if opcode == 0x46:  # aget-object
            lines.append(f"    r[{a}].l = (*env)->GetObjectArrayElement(env, (jobjectArray)r[{b}].l, r[{c_reg}].i);")
        else:
            _AG = {0x44:("Int","jintArray","jint","i"),0x45:("Long","jlongArray","jlong","j"),
                   0x47:("Boolean","jbooleanArray","jboolean","i"),0x48:("Byte","jbyteArray","jbyte","i"),
                   0x49:("Char","jcharArray","jchar","i"),0x4A:("Short","jshortArray","jshort","i")}
            vn,at,et,rf = _AG[opcode]; jt = "jint" if rf=="i" else "jlong"
            lines.append(f"    {{ {et} _v; (*env)->Get{vn}ArrayRegion(env, ({at})r[{b}].l, r[{c_reg}].i, 1, &_v); r[{a}].{rf} = ({jt})_v; }}")
        lines.append(f"    if ((*env)->ExceptionCheck(env)) goto _exc_handler;")
        return

    # ── Aput (23x) ──
    if 0x4B <= opcode <= 0x51:
        a = (word0 >> 8) & 0xFF
        w1 = _u16le(insns, byte_off + 2); b = w1 & 0xFF; c_reg = (w1 >> 8) & 0xFF
        if opcode == 0x4D:  # aput-object
            lines.append(f"    (*env)->SetObjectArrayElement(env, (jobjectArray)r[{b}].l, r[{c_reg}].i, r[{a}].l);")
        else:
            _AP = {0x4B:("Int","jintArray","jint","i"),0x4C:("Long","jlongArray","jlong","j"),
                   0x4E:("Boolean","jbooleanArray","jboolean","i"),0x4F:("Byte","jbyteArray","jbyte","i"),
                   0x50:("Char","jcharArray","jchar","i"),0x51:("Short","jshortArray","jshort","i")}
            vn,at,et,rf = _AP[opcode]
            lines.append(f"    {{ {et} _v = ({et})r[{a}].{rf}; (*env)->Set{vn}ArrayRegion(env, ({at})r[{b}].l, r[{c_reg}].i, 1, &_v); }}")
        lines.append(f"    if ((*env)->ExceptionCheck(env)) goto _exc_handler;")
        return

    # ── Cmp (23x) ──
    if 0x2D <= opcode <= 0x31:
        a = (word0 >> 8) & 0xFF
        w1 = _u16le(insns, byte_off + 2); b = w1 & 0xFF; c_reg = (w1 >> 8) & 0xFF
        if opcode == 0x31:  # cmp-long
            lines.append(f"    r[{a}].i = (r[{b}].j < r[{c_reg}].j) ? -1 : ((r[{b}].j > r[{c_reg}].j) ? 1 : 0);")
        elif opcode in (0x2D, 0x2F):  # cmpl-float / cmpl-double (NaN→-1)
            rf = 'f' if opcode == 0x2D else 'd'
            lines.append(f"    r[{a}].i = (r[{b}].{rf} > r[{c_reg}].{rf}) ? 1 : ((r[{b}].{rf} == r[{c_reg}].{rf}) ? 0 : -1);")
        else:  # 0x2E, 0x30: cmpg-float / cmpg-double (NaN→1)
            rf = 'f' if opcode == 0x2E else 'd'
            lines.append(f"    r[{a}].i = (r[{b}].{rf} < r[{c_reg}].{rf}) ? -1 : ((r[{b}].{rf} == r[{c_reg}].{rf}) ? 0 : 1);")
        return

    # ── Packed-switch (31t) ──
    if opcode == 0x2B:
        a = (word0 >> 8) & 0xFF
        off_lo = _u16le(insns, byte_off + 2); off_hi = _u16le(insns, byte_off + 4)
        sw_off = off_lo | (off_hi << 16)
        if sw_off & 0x80000000: sw_off -= 0x100000000
        ppos = (pos + sw_off) * 2
        size = _u16le(insns, ppos + 2); first_key = _s32le(insns, ppos + 4)
        lines.append(f"    switch (r[{a}].i) {{")
        for i in range(size):
            tgt = pos + _s32le(insns, ppos + 8 + i * 4)
            lines.append(f"      case {first_key + i}: goto L_{tgt};")
        lines.append(f"    }}")
        return

    # ── Sparse-switch (31t) ──
    if opcode == 0x2C:
        a = (word0 >> 8) & 0xFF
        off_lo = _u16le(insns, byte_off + 2); off_hi = _u16le(insns, byte_off + 4)
        sw_off = off_lo | (off_hi << 16)
        if sw_off & 0x80000000: sw_off -= 0x100000000
        ppos = (pos + sw_off) * 2
        size = _u16le(insns, ppos + 2)
        kb = ppos + 4; tb = kb + size * 4
        for i in range(size):
            key = _s32le(insns, kb + i * 4); tgt = pos + _s32le(insns, tb + i * 4)
            pref = "    if" if i == 0 else "    else if"
            lines.append(f"{pref} (r[{a}].i == {key}) goto L_{tgt};")
        return

    # ── Filled-new-array (35c) ──
    if opcode == 0x24:
        _translate_filled_new_array_35c(lines, dex, insns, pos, word0, byte_off)
        return

    # ── Filled-new-array/range (3rc) ──
    if opcode == 0x25:
        _translate_filled_new_array_3rc(lines, dex, insns, pos, word0, byte_off)
        return

    # ── Fill-array-data (31t) ──
    if opcode == 0x26:
        _translate_fill_array_data(lines, dex, insns, pos, word0, byte_off)
        return

    raise NotImplementedError(f"unhandled opcode 0x{opcode:02x} fmt={fmt} at insn_pos={pos}")


# ---------------------------------------------------------------------------
# Invoke helpers
# ---------------------------------------------------------------------------

def _translate_invoke_35c(lines: list[str], dex: DexFile, insns: bytes, pos: int, opcode: int, word0: int, byte_off: int) -> None:
    a_count = (word0 >> 12) & 0x0F
    method_idx = _u16le(insns, byte_off + 2)
    regs_word = _u16le(insns, byte_off + 4)

    mid = dex.method_ids[method_idx]
    cls_name = _desc_to_jni_slash(dex.type_name(mid.class_idx))
    m_name = dex.strings[mid.name_idx]
    m_sig = dex.method_signature(method_idx)
    ret_d = _return_desc(m_sig)

    # Unpack arg registers.
    c = regs_word & 0x0F
    d = (regs_word >> 4) & 0x0F
    e = (regs_word >> 8) & 0x0F
    f = (regs_word >> 12) & 0x0F
    g = (word0 >> 8) & 0x0F
    arg_regs = [c, d, e, f, g][:a_count]

    call_variant = _jni_call_variant(ret_d)
    is_static_call = opcode == 0x71
    is_nonvirtual = opcode in (0x6F, 0x70)  # invoke-super, invoke-direct

    lines.append(f'    {{ /* invoke {cls_name}->{m_name}{m_sig} */')
    lines.append(f'      jclass _ic = d2c_find_class(env, "{cls_name}");')

    if is_static_call:
        lines.append(f'      jmethodID _im = (*env)->GetStaticMethodID(env, _ic, "{m_name}", "{m_sig}");')
    else:
        lines.append(f'      jmethodID _im = (*env)->GetMethodID(env, _ic, "{m_name}", "{m_sig}");')

    # Build arg string.
    param_descs = list(_iter_param_descs(m_sig))
    args_str = ""
    arg_idx = 1 if not is_static_call else 0  # skip receiver for instance calls
    for pd in param_descs:
        ri = arg_regs[arg_idx] if arg_idx < len(arg_regs) else 0
        rf = _reg_field(pd)
        args_str += f", r[{ri}].{rf}"
        arg_idx += 2 if _desc_is_wide(pd) else 1

    if is_static_call:
        if _desc_is_void(ret_d):
            lines.append(f'      (*env)->CallStatic{call_variant}Method(env, _ic, _im{args_str});')
        else:
            rf = _reg_field(ret_d)
            lines.append(f'      _result.{rf} = (*env)->CallStatic{call_variant}Method(env, _ic, _im{args_str});')
    elif is_nonvirtual:
        obj_reg = arg_regs[0] if arg_regs else 0
        if _desc_is_void(ret_d):
            lines.append(f'      (*env)->CallNonvirtual{call_variant}Method(env, r[{obj_reg}].l, _ic, _im{args_str});')
        else:
            rf = _reg_field(ret_d)
            lines.append(f'      _result.{rf} = (*env)->CallNonvirtual{call_variant}Method(env, r[{obj_reg}].l, _ic, _im{args_str});')
    else:
        obj_reg = arg_regs[0] if arg_regs else 0
        if _desc_is_void(ret_d):
            lines.append(f'      (*env)->Call{call_variant}Method(env, r[{obj_reg}].l, _im{args_str});')
        else:
            rf = _reg_field(ret_d)
            lines.append(f'      _result.{rf} = (*env)->Call{call_variant}Method(env, r[{obj_reg}].l, _im{args_str});')

    lines.append(f"      (*env)->DeleteLocalRef(env, _ic);")
    lines.append(f"    }}")
    lines.append(f"    if ((*env)->ExceptionCheck(env)) goto _exc_handler;")


def _translate_invoke_3rc(lines: list[str], dex: DexFile, insns: bytes, pos: int, opcode: int, word0: int, byte_off: int) -> None:
    a_count = (word0 >> 8) & 0xFF
    method_idx = _u16le(insns, byte_off + 2)
    start_reg = _u16le(insns, byte_off + 4)

    mid = dex.method_ids[method_idx]
    cls_name = _desc_to_jni_slash(dex.type_name(mid.class_idx))
    m_name = dex.strings[mid.name_idx]
    m_sig = dex.method_signature(method_idx)
    ret_d = _return_desc(m_sig)
    call_variant = _jni_call_variant(ret_d)
    is_static_call = opcode == 0x77
    is_nonvirtual = opcode in (0x75, 0x76)  # invoke-super/range, invoke-direct/range

    lines.append(f'    {{ /* invoke/range {cls_name}->{m_name}{m_sig} */')
    lines.append(f'      jclass _ic = d2c_find_class(env, "{cls_name}");')

    if is_static_call:
        lines.append(f'      jmethodID _im = (*env)->GetStaticMethodID(env, _ic, "{m_name}", "{m_sig}");')
    else:
        lines.append(f'      jmethodID _im = (*env)->GetMethodID(env, _ic, "{m_name}", "{m_sig}");')

    param_descs = list(_iter_param_descs(m_sig))
    args_str = ""
    ri = start_reg + (0 if is_static_call else 1)
    for pd in param_descs:
        rf = _reg_field(pd)
        args_str += f", r[{ri}].{rf}"
        ri += 2 if _desc_is_wide(pd) else 1

    if is_static_call:
        if _desc_is_void(ret_d):
            lines.append(f'      (*env)->CallStatic{call_variant}Method(env, _ic, _im{args_str});')
        else:
            rf = _reg_field(ret_d)
            lines.append(f'      _result.{rf} = (*env)->CallStatic{call_variant}Method(env, _ic, _im{args_str});')
    elif is_nonvirtual:
        if _desc_is_void(ret_d):
            lines.append(f'      (*env)->CallNonvirtual{call_variant}Method(env, r[{start_reg}].l, _ic, _im{args_str});')
        else:
            rf = _reg_field(ret_d)
            lines.append(f'      _result.{rf} = (*env)->CallNonvirtual{call_variant}Method(env, r[{start_reg}].l, _ic, _im{args_str});')
    else:
        if _desc_is_void(ret_d):
            lines.append(f'      (*env)->Call{call_variant}Method(env, r[{start_reg}].l, _im{args_str});')
        else:
            rf = _reg_field(ret_d)
            lines.append(f'      _result.{rf} = (*env)->Call{call_variant}Method(env, r[{start_reg}].l, _im{args_str});')

    lines.append(f"      (*env)->DeleteLocalRef(env, _ic);")
    lines.append(f"    }}")
    lines.append(f"    if ((*env)->ExceptionCheck(env)) goto _exc_handler;")


# ---------------------------------------------------------------------------
# Field access helpers
# ---------------------------------------------------------------------------

def _translate_ifield(lines: list[str], dex: DexFile, insns: bytes, pos: int, opcode: int, word0: int, byte_off: int) -> None:
    a = (word0 >> 8) & 0x0F
    b = (word0 >> 12) & 0x0F
    field_idx = _u16le(insns, byte_off + 2)
    fid = dex.field_ids[field_idx]
    cls_name = _desc_to_jni_slash(dex.type_name(fid.class_idx))
    f_name = dex.strings[fid.name_idx]
    f_type = dex.type_name(fid.type_idx)
    variant = _jni_field_variant(f_type)
    rf = _reg_field(f_type)
    is_get = 0x52 <= opcode <= 0x58

    lines.append(f'    {{ jclass _fc = d2c_find_class(env, "{cls_name}");')
    lines.append(f'      jfieldID _fid = (*env)->GetFieldID(env, _fc, "{f_name}", "{f_type}");')
    if is_get:
        lines.append(f'      r[{a}].{rf} = (*env)->Get{variant}Field(env, r[{b}].l, _fid);')
    else:
        lines.append(f'      (*env)->Set{variant}Field(env, r[{b}].l, _fid, r[{a}].{rf});')
    lines.append(f"      (*env)->DeleteLocalRef(env, _fc); }}")


def _translate_sfield(lines: list[str], dex: DexFile, insns: bytes, pos: int, opcode: int, word0: int, byte_off: int) -> None:
    a = (word0 >> 8) & 0xFF
    field_idx = _u16le(insns, byte_off + 2)
    fid = dex.field_ids[field_idx]
    cls_name = _desc_to_jni_slash(dex.type_name(fid.class_idx))
    f_name = dex.strings[fid.name_idx]
    f_type = dex.type_name(fid.type_idx)
    variant = _jni_field_variant(f_type)
    rf = _reg_field(f_type)
    is_get = 0x60 <= opcode <= 0x66

    lines.append(f'    {{ jclass _fc = d2c_find_class(env, "{cls_name}");')
    lines.append(f'      jfieldID _fid = (*env)->GetStaticFieldID(env, _fc, "{f_name}", "{f_type}");')
    if is_get:
        lines.append(f'      r[{a}].{rf} = (*env)->GetStatic{variant}Field(env, _fc, _fid);')
    else:
        lines.append(f'      (*env)->SetStatic{variant}Field(env, _fc, _fid, r[{a}].{rf});')
    lines.append(f"      (*env)->DeleteLocalRef(env, _fc); }}")


# ---------------------------------------------------------------------------
# Binop / unop helpers
# ---------------------------------------------------------------------------

_BINOP_23X = {
    0x90: ("+", "i"), 0x91: ("-", "i"), 0x92: ("*", "i"), 0x93: ("/", "i"), 0x94: ("%", "i"),
    0x95: ("&", "i"), 0x96: ("|", "i"), 0x97: ("^", "i"),
    0x98: ("<<", "i"), 0x99: (">>", "i"),
    0x9B: ("+", "j"), 0x9C: ("-", "j"), 0x9D: ("*", "j"), 0x9E: ("/", "j"), 0x9F: ("%", "j"),
    0xA0: ("&", "j"), 0xA1: ("|", "j"), 0xA2: ("^", "j"),
    0xA3: ("<<", "j"), 0xA4: (">>", "j"),
    0xA6: ("+", "f"), 0xA7: ("-", "f"), 0xA8: ("*", "f"), 0xA9: ("/", "f"),
    0xAB: ("+", "d"), 0xAC: ("-", "d"), 0xAD: ("*", "d"), 0xAE: ("/", "d"),
}

def _translate_binop_23x(lines: list[str], insns: bytes, byte_off: int, opcode: int, word0: int) -> None:
    a = (word0 >> 8) & 0xFF
    w1 = _u16le(insns, byte_off + 2)
    b = w1 & 0xFF
    c = (w1 >> 8) & 0xFF
    # ── Special cases ──
    # ushr-int (0x9A), ushr-long (0xA5)
    if opcode == 0x9A:
        lines.append(f"    r[{a}].i = (jint)((juint)r[{b}].i >> (r[{c}].i & 0x1F));")
        return
    if opcode == 0xA5:
        lines.append(f"    r[{a}].j = (jlong)((julong)r[{b}].j >> (r[{c}].i & 0x3F));")
        return
    # rem-float (0xAA), rem-double (0xAF)
    if opcode == 0xAA:
        lines.append(f"    r[{a}].f = fmodf(r[{b}].f, r[{c}].f);")
        return
    if opcode == 0xAF:
        lines.append(f"    r[{a}].d = fmod(r[{b}].d, r[{c}].d);")
        return
    info = _BINOP_23X.get(opcode)
    if not info:
        raise NotImplementedError(f"binop23x 0x{opcode:02x} not implemented")
    op, rf = info
    # div/rem zero check (int: 0x93/0x94, long: 0x9E/0x9F)
    if opcode in (0x93, 0x94):
        lines.append(f"    if (r[{c}].i == 0) {{ jclass _ae = d2c_find_class(env, \"java/lang/ArithmeticException\"); (*env)->ThrowNew(env, _ae, \"/ by zero\"); (*env)->DeleteLocalRef(env, _ae); goto _exc_handler; }}")
    elif opcode in (0x9E, 0x9F):
        lines.append(f"    if (r[{c}].j == 0) {{ jclass _ae = d2c_find_class(env, \"java/lang/ArithmeticException\"); (*env)->ThrowNew(env, _ae, \"/ by zero\"); (*env)->DeleteLocalRef(env, _ae); goto _exc_handler; }}")
    # shift masking
    if opcode in (0x98, 0x99):  # shl-int, shr-int
        lines.append(f"    r[{a}].{rf} = r[{b}].{rf} {op} (r[{c}].i & 0x1F);")
    elif opcode in (0xA3, 0xA4):  # shl-long, shr-long
        lines.append(f"    r[{a}].{rf} = r[{b}].{rf} {op} (r[{c}].i & 0x3F);")
    else:
        lines.append(f"    r[{a}].{rf} = r[{b}].{rf} {op} r[{c}].{rf};")


_BINOP_2ADDR = {
    0xB0: ("+", "i"), 0xB1: ("-", "i"), 0xB2: ("*", "i"), 0xB3: ("/", "i"), 0xB4: ("%", "i"),
    0xB5: ("&", "i"), 0xB6: ("|", "i"), 0xB7: ("^", "i"),
    0xB8: ("<<", "i"), 0xB9: (">>", "i"),
    0xBB: ("+", "j"), 0xBC: ("-", "j"), 0xBD: ("*", "j"), 0xBE: ("/", "j"), 0xBF: ("%", "j"),
    0xC0: ("&", "j"), 0xC1: ("|", "j"), 0xC2: ("^", "j"),
    0xC3: ("<<", "j"), 0xC4: (">>", "j"),
    0xC6: ("+", "f"), 0xC7: ("-", "f"), 0xC8: ("*", "f"), 0xC9: ("/", "f"),
    0xCB: ("+", "d"), 0xCC: ("-", "d"), 0xCD: ("*", "d"), 0xCE: ("/", "d"),
}

def _translate_binop_2addr(lines: list[str], opcode: int, word0: int) -> None:
    a = (word0 >> 8) & 0x0F
    b = (word0 >> 12) & 0x0F
    # ── Special cases ──
    if opcode == 0xBA:  # ushr-int/2addr
        lines.append(f"    r[{a}].i = (jint)((juint)r[{a}].i >> (r[{b}].i & 0x1F));")
        return
    if opcode == 0xC5:  # ushr-long/2addr
        lines.append(f"    r[{a}].j = (jlong)((julong)r[{a}].j >> (r[{b}].i & 0x3F));")
        return
    if opcode == 0xCA:  # rem-float/2addr
        lines.append(f"    r[{a}].f = fmodf(r[{a}].f, r[{b}].f);")
        return
    if opcode == 0xCF:  # rem-double/2addr
        lines.append(f"    r[{a}].d = fmod(r[{a}].d, r[{b}].d);")
        return
    info = _BINOP_2ADDR.get(opcode)
    if not info:
        raise NotImplementedError(f"binop2addr 0x{opcode:02x} not implemented")
    op, rf = info
    # div/rem zero check (int: 0xB3/0xB4, long: 0xBE/0xBF)
    if opcode in (0xB3, 0xB4):
        lines.append(f"    if (r[{b}].i == 0) {{ jclass _ae = d2c_find_class(env, \"java/lang/ArithmeticException\"); (*env)->ThrowNew(env, _ae, \"/ by zero\"); (*env)->DeleteLocalRef(env, _ae); goto _exc_handler; }}")
    elif opcode in (0xBE, 0xBF):
        lines.append(f"    if (r[{b}].j == 0) {{ jclass _ae = d2c_find_class(env, \"java/lang/ArithmeticException\"); (*env)->ThrowNew(env, _ae, \"/ by zero\"); (*env)->DeleteLocalRef(env, _ae); goto _exc_handler; }}")
    # shift masking
    if opcode in (0xB8, 0xB9):  # shl-int/2addr, shr-int/2addr
        lines.append(f"    r[{a}].{rf} = r[{a}].{rf} {op} (r[{b}].i & 0x1F);")
    elif opcode in (0xC3, 0xC4):  # shl-long/2addr, shr-long/2addr
        lines.append(f"    r[{a}].{rf} = r[{a}].{rf} {op} (r[{b}].i & 0x3F);")
    else:
        lines.append(f"    r[{a}].{rf} = r[{a}].{rf} {op} r[{b}].{rf};")


_BINOP_LIT16 = {
    0xD0: "+", 0xD1: "-", 0xD2: "*", 0xD3: "/", 0xD4: "%",
    0xD5: "&", 0xD6: "|", 0xD7: "^",
}

def _translate_binop_lit16(lines: list[str], insns: bytes, byte_off: int, opcode: int, word0: int) -> None:
    a = (word0 >> 8) & 0x0F
    b = (word0 >> 12) & 0x0F
    lit = _s16le(insns, byte_off + 2)
    # rsub-int (0xD1): result = lit - vB
    if opcode == 0xD1:
        lines.append(f"    r[{a}].i = {lit} - r[{b}].i;")
        return
    # div/rem zero check
    if opcode in (0xD3, 0xD4) and lit == 0:
        lines.append(f"    {{ jclass _ae = d2c_find_class(env, \"java/lang/ArithmeticException\"); (*env)->ThrowNew(env, _ae, \"/ by zero\"); (*env)->DeleteLocalRef(env, _ae); goto _exc_handler; }}")
        return
    op = _BINOP_LIT16.get(opcode, "+")
    lines.append(f"    r[{a}].i = r[{b}].i {op} {lit};")


_BINOP_LIT8 = {
    0xD8: "+", 0xD9: "-", 0xDA: "*", 0xDB: "/", 0xDC: "%",
    0xDD: "&", 0xDE: "|", 0xDF: "^",
    0xE0: "<<", 0xE1: ">>",
}

def _translate_binop_lit8(lines: list[str], insns: bytes, byte_off: int, opcode: int, word0: int) -> None:
    a = (word0 >> 8) & 0xFF
    w1 = _u16le(insns, byte_off + 2)
    b = w1 & 0xFF
    lit = (w1 >> 8) & 0xFF
    if lit & 0x80:
        lit -= 256
    # rsub-int/lit8 (0xD9): result = lit - vB
    if opcode == 0xD9:
        lines.append(f"    r[{a}].i = {lit} - r[{b}].i;")
        return
    # ushr-int/lit8 (0xE2)
    if opcode == 0xE2:
        lines.append(f"    r[{a}].i = (jint)((juint)r[{b}].i >> ({lit & 0x1F}));")
        return
    # div/rem zero check
    if opcode in (0xDB, 0xDC) and lit == 0:
        lines.append(f"    {{ jclass _ae = d2c_find_class(env, \"java/lang/ArithmeticException\"); (*env)->ThrowNew(env, _ae, \"/ by zero\"); (*env)->DeleteLocalRef(env, _ae); goto _exc_handler; }}")
        return
    # shift masking for lit8
    if opcode in (0xE0, 0xE1):  # shl-int/lit8, shr-int/lit8
        lines.append(f"    r[{a}].i = r[{b}].i {_BINOP_LIT8.get(opcode, '+')} ({lit & 0x1F});")
        return
    op = _BINOP_LIT8.get(opcode, "+")
    lines.append(f"    r[{a}].i = r[{b}].i {op} {lit};")


def _translate_unop(lines: list[str], opcode: int, word0: int) -> None:
    a = (word0 >> 8) & 0x0F
    b = (word0 >> 12) & 0x0F
    _UNOPS: dict[int, str] = {
        0x7B: f"r[{a}].i = -r[{b}].i;",
        0x7C: f"r[{a}].i = ~r[{b}].i;",
        0x7D: f"r[{a}].j = -r[{b}].j;",
        0x7E: f"r[{a}].j = ~r[{b}].j;",
        0x7F: f"r[{a}].f = -r[{b}].f;",
        0x80: f"r[{a}].d = -r[{b}].d;",
        0x81: f"r[{a}].j = (jlong)r[{b}].i;",
        0x82: f"r[{a}].f = (jfloat)r[{b}].i;",
        0x83: f"r[{a}].d = (jdouble)r[{b}].i;",
        0x84: f"r[{a}].i = (jint)r[{b}].j;",
        0x85: f"r[{a}].f = (jfloat)r[{b}].j;",
        0x86: f"r[{a}].d = (jdouble)r[{b}].j;",
        0x87: f"r[{a}].i = (jint)r[{b}].f;",
        0x88: f"r[{a}].j = (jlong)r[{b}].f;",
        0x89: f"r[{a}].d = (jdouble)r[{b}].f;",
        0x8A: f"r[{a}].i = (jint)r[{b}].d;",
        0x8B: f"r[{a}].j = (jlong)r[{b}].d;",
        0x8C: f"r[{a}].f = (jfloat)r[{b}].d;",
        0x8D: f"r[{a}].i = (jint)(jbyte)r[{b}].i;",
        0x8E: f"r[{a}].i = (jint)(jchar)(r[{b}].i & 0xFFFF);",
        0x8F: f"r[{a}].i = (jint)(jshort)r[{b}].i;",
    }
    stmt = _UNOPS.get(opcode, f"/* unop 0x{opcode:02x} not translated */")
    lines.append(f"    {stmt}")
