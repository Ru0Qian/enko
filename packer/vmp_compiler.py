"""Dalvik → VMP bytecode compiler.

Converts Dalvik method bytecodes into a custom VMP instruction set with
per-build random opcode shuffling.  Produces a serialised VMP blob that
the native interpreter can load at runtime.
"""
from __future__ import annotations

import os
import hashlib
import random
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from dex_parser import (
    CodeItem, DexFile, EncodedCatchHandler, EncodedMethod, NO_INDEX,
)

# ── VMP real-operation IDs (interpreter must use the same enum) ──────────

class VmpOp(IntEnum):
    NOP = 0
    MOVE = 1; MOVE_WIDE = 2; MOVE_OBJECT = 3
    MOVE_RESULT = 4; MOVE_RESULT_WIDE = 5; MOVE_RESULT_OBJECT = 6
    MOVE_EXCEPTION = 7
    RETURN_VOID = 8; RETURN = 9; RETURN_WIDE = 10; RETURN_OBJECT = 11
    CONST = 12; CONST_WIDE = 13; CONST_STRING = 14; CONST_CLASS = 15
    MONITOR_ENTER = 16; MONITOR_EXIT = 17
    CHECK_CAST = 18; INSTANCE_OF = 19
    NEW_INSTANCE = 20; NEW_ARRAY = 21; ARRAY_LENGTH = 22
    THROW = 23; GOTO = 24
    IF_EQ = 25; IF_NE = 26; IF_LT = 27; IF_GE = 28; IF_GT = 29; IF_LE = 30
    IF_EQZ = 31; IF_NEZ = 32; IF_LTZ = 33; IF_GEZ = 34; IF_GTZ = 35; IF_LEZ = 36
    AGET = 37; AGET_WIDE = 38; AGET_OBJECT = 39
    AGET_BOOLEAN = 40; AGET_BYTE = 41; AGET_CHAR = 42; AGET_SHORT = 43
    APUT = 44; APUT_WIDE = 45; APUT_OBJECT = 46
    APUT_BOOLEAN = 47; APUT_BYTE = 48; APUT_CHAR = 49; APUT_SHORT = 50
    IGET = 51; IGET_WIDE = 52; IGET_OBJECT = 53
    IGET_BOOLEAN = 54; IGET_BYTE = 55; IGET_CHAR = 56; IGET_SHORT = 57
    IPUT = 58; IPUT_WIDE = 59; IPUT_OBJECT = 60
    IPUT_BOOLEAN = 61; IPUT_BYTE = 62; IPUT_CHAR = 63; IPUT_SHORT = 64
    SGET = 65; SGET_WIDE = 66; SGET_OBJECT = 67
    SGET_BOOLEAN = 68; SGET_BYTE = 69; SGET_CHAR = 70; SGET_SHORT = 71
    SPUT = 72; SPUT_WIDE = 73; SPUT_OBJECT = 74
    SPUT_BOOLEAN = 75; SPUT_BYTE = 76; SPUT_CHAR = 77; SPUT_SHORT = 78
    INVOKE_VIRTUAL = 79; INVOKE_SUPER = 80; INVOKE_DIRECT = 81
    INVOKE_STATIC = 82; INVOKE_INTERFACE = 83
    NEG_INT = 84; NOT_INT = 85; NEG_LONG = 86; NOT_LONG = 87
    NEG_FLOAT = 88; NEG_DOUBLE = 89
    INT_TO_LONG = 90; INT_TO_FLOAT = 91; INT_TO_DOUBLE = 92
    LONG_TO_INT = 93; LONG_TO_FLOAT = 94; LONG_TO_DOUBLE = 95
    FLOAT_TO_INT = 96; FLOAT_TO_LONG = 97; FLOAT_TO_DOUBLE = 98
    DOUBLE_TO_INT = 99; DOUBLE_TO_LONG = 100; DOUBLE_TO_FLOAT = 101
    INT_TO_BYTE = 102; INT_TO_CHAR = 103; INT_TO_SHORT = 104
    ADD_INT = 105; SUB_INT = 106; MUL_INT = 107; DIV_INT = 108; REM_INT = 109
    AND_INT = 110; OR_INT = 111; XOR_INT = 112
    SHL_INT = 113; SHR_INT = 114; USHR_INT = 115
    ADD_LONG = 116; SUB_LONG = 117; MUL_LONG = 118; DIV_LONG = 119; REM_LONG = 120
    AND_LONG = 121; OR_LONG = 122; XOR_LONG = 123
    SHL_LONG = 124; SHR_LONG = 125; USHR_LONG = 126
    ADD_FLOAT = 127; SUB_FLOAT = 128; MUL_FLOAT = 129; DIV_FLOAT = 130; REM_FLOAT = 131
    ADD_DOUBLE = 132; SUB_DOUBLE = 133; MUL_DOUBLE = 134; DIV_DOUBLE = 135; REM_DOUBLE = 136
    CMP_LONG = 137; CMPG_FLOAT = 138; CMPL_FLOAT = 139
    CMPG_DOUBLE = 140; CMPL_DOUBLE = 141
    PACKED_SWITCH = 142; SPARSE_SWITCH = 143
    FILL_ARRAY_DATA = 144; FILLED_NEW_ARRAY = 145
    # invoke extra encodings: args packed in subsequent VMP insns
    INVOKE_ARGS = 146  # pseudo: carries register list for preceding invoke
    CONST_WIDE_HI32 = 147  # pseudo: carries high 32 bits of 64-bit const
    INVOKE_CUSTOM = 148     # invoke-custom (lambda / call-site)
    INVOKE_POLYMORPHIC = 149  # invoke-polymorphic (MethodHandle.invoke)

    # Alias opcodes (150-199): randomly assigned per-build to different
    # Dalvik opcodes that normally collapse into the same VMP op.
    # The interpreter maps them back to the canonical handler.
    BINOP_ALIAS1 = 150; BINOP_ALIAS2 = 151; BINOP_ALIAS3 = 152; BINOP_ALIAS4 = 153
    BINOP_ALIAS5 = 154; BINOP_ALIAS6 = 155; BINOP_ALIAS7 = 156; BINOP_ALIAS8 = 157
    BINOP_ALIAS9 = 158; BINOP_ALIAS10 = 159
    UNOP_ALIAS1 = 160; UNOP_ALIAS2 = 161; UNOP_ALIAS3 = 162; UNOP_ALIAS4 = 163
    UNOP_ALIAS5 = 164
    BINOP_LIT_ALIAS1 = 165; BINOP_LIT_ALIAS2 = 166; BINOP_LIT_ALIAS3 = 167
    BINOP_LIT_ALIAS4 = 168; BINOP_LIT_ALIAS5 = 169; BINOP_LIT_ALIAS6 = 170
    BINOP_LIT_ALIAS7 = 171; BINOP_LIT_ALIAS8 = 172
    IF_ALIAS1 = 173; IF_ALIAS2 = 174; IF_ALIAS3 = 175; IF_ALIAS4 = 176
    IF_ALIAS5 = 177; IF_ALIAS6 = 178
    IFZ_ALIAS1 = 179; IFZ_ALIAS2 = 180; IFZ_ALIAS3 = 181; IFZ_ALIAS4 = 182
    IFZ_ALIAS5 = 183; IFZ_ALIAS6 = 184
    AGET_ALIAS1 = 185; AGET_ALIAS2 = 186; AGET_ALIAS3 = 187; AGET_ALIAS4 = 188
    APUT_ALIAS1 = 189; APUT_ALIAS2 = 190; APUT_ALIAS3 = 191; APUT_ALIAS4 = 192
    IGET_ALIAS1 = 193; IGET_ALIAS2 = 194; IGET_ALIAS3 = 195
    IPUT_ALIAS1 = 196; IPUT_ALIAS2 = 197; IPUT_ALIAS3 = 198
    SGET_SPUT_ALIAS1 = 199
    OP_COUNT = 200


VMP_BLOB_MAGIC = b"M2vK7pQ9dL4\x00"
VMP_BLOB_VERSION = 4  # v4: encrypted string pool + v3 operand sentinels
VMP_BINOP_REG0_SENTINEL = 0x6E4B0001
VMP_BINOP_LIT_ZERO_SENTINEL = 0x6E4B0002

# ── Dalvik instruction format tables ─────────────────────────────────────
# Maps Dalvik opcode (0x00..0xFF) to (format_id, width_in_code_units).
# Only the opcodes we translate are listed; unknown → format "?" width 0.
# Format IDs: 10x 12x 11n 11x 10t 20t 22x 21t 21s 21h 21c 23x 22b 22t 22s 22c
#             30t 31i 31t 31c 35c 3rc 51l

_FMT = {}  # opcode -> (fmt_str, width)


def _reg(ops: range | list[int], fmt: str, w: int) -> None:
    for o in ops:
        _FMT[o] = (fmt, w)


# nop
_reg([0x00], "10x", 1)
# move family  12x
_reg([0x01], "12x", 1); _reg([0x04], "12x", 1); _reg([0x07], "12x", 1)
# move/from16  22x
_reg([0x02], "22x", 2); _reg([0x05], "22x", 2); _reg([0x08], "22x", 2)
# move/16  32x
_reg([0x03], "32x", 3); _reg([0x06], "32x", 3); _reg([0x09], "32x", 3)
# move-result 11x
_reg([0x0A, 0x0B, 0x0C, 0x0D], "11x", 1)
# return 11x / 10x
_reg([0x0E], "10x", 1); _reg([0x0F, 0x10, 0x11], "11x", 1)
# const/4 11n
_reg([0x12], "11n", 1)
# const/16 21s
_reg([0x13], "21s", 2)
# const 31i
_reg([0x14], "31i", 3)
# const/high16 21h
_reg([0x15], "21h", 2)
# const-wide/16 21s
_reg([0x16], "21s", 2)
# const-wide/32 31i
_reg([0x17], "31i", 3)
# const-wide 51l
_reg([0x18], "51l", 5)
# const-wide/high16 21h
_reg([0x19], "21h", 2)
# const-string 21c
_reg([0x1A], "21c", 2)
# const-string/jumbo 31c
_reg([0x1B], "31c", 3)
# const-class 21c
_reg([0x1C], "21c", 2)
# monitor-enter, monitor-exit 11x
_reg([0x1D, 0x1E], "11x", 1)
# check-cast 21c
_reg([0x1F], "21c", 2)
# instance-of 22c
_reg([0x20], "22c", 2)
# array-length 12x
_reg([0x21], "12x", 1)
# new-instance 21c
_reg([0x22], "21c", 2)
# new-array 22c
_reg([0x23], "22c", 2)
# filled-new-array 35c
_reg([0x24], "35c", 3)
# filled-new-array/range 3rc
_reg([0x25], "3rc", 3)
# fill-array-data 31t
_reg([0x26], "31t", 3)
# throw 11x
_reg([0x27], "11x", 1)
# goto 10t
_reg([0x28], "10t", 1)
# goto/16 20t
_reg([0x29], "20t", 2)
# goto/32 30t
_reg([0x2A], "30t", 3)
# packed-switch 31t
_reg([0x2B], "31t", 3)
# sparse-switch 31t
_reg([0x2C], "31t", 3)
# cmpkind 23x
_reg(range(0x2D, 0x32), "23x", 2)
# if-test 22t
_reg(range(0x32, 0x38), "22t", 2)
# if-testz 21t
_reg(range(0x38, 0x3E), "21t", 2)
# aget 23x
_reg(range(0x44, 0x4B), "23x", 2)
# aput 23x
_reg(range(0x4B, 0x52), "23x", 2)
# iget 22c
_reg(range(0x52, 0x59), "22c", 2)
# iput 22c
_reg(range(0x59, 0x60), "22c", 2)
# sget 21c
_reg(range(0x60, 0x67), "21c", 2)
# sput 21c
_reg(range(0x67, 0x6E), "21c", 2)
# invoke-kind 35c
_reg(range(0x6E, 0x73), "35c", 3)
# invoke-kind/range 3rc
_reg(range(0x74, 0x79), "3rc", 3)
# unop 12x
_reg(range(0x7B, 0x90), "12x", 1)
# binop 23x
_reg(range(0x90, 0xB0), "23x", 2)
# binop/2addr 12x
_reg(range(0xB0, 0xD0), "12x", 1)
# binop/lit16 22s
_reg(range(0xD0, 0xD8), "22s", 2)
# binop/lit8 22b
_reg(range(0xD8, 0xE3), "22b", 2)
# invoke-polymorphic (DEX 038+)
_reg([0xFA], "45cc", 4); _reg([0xFB], "4rcc", 4)
# invoke-custom (DEX 038+)
_reg([0xFC], "35c", 3); _reg([0xFD], "3rc", 3)


def _dalvik_insn_width(opcode: int) -> int:
    info = _FMT.get(opcode)
    return info[1] if info else 0


# ── Dalvik → VmpOp mapping ───────────────────────────────────────────────

# Alias pools: interpreter maps these back to the canonical handler.
_BINOP_ALIASES = [VmpOp(v) for v in range(150, 160)]   # BINOP_ALIAS1..10
_UNOP_ALIASES  = [VmpOp(v) for v in range(160, 165)]   # UNOP_ALIAS1..5
_BINOP_LIT_ALIASES = [VmpOp(v) for v in range(165, 173)]  # BINOP_LIT_ALIAS1..8
_IF_ALIASES    = [VmpOp(v) for v in range(173, 179)]   # IF_ALIAS1..6
_IFZ_ALIASES   = [VmpOp(v) for v in range(179, 185)]   # IFZ_ALIAS1..6
_AGET_ALIASES  = [VmpOp(v) for v in range(185, 189)]   # AGET_ALIAS1..4
_APUT_ALIASES  = [VmpOp(v) for v in range(189, 193)]   # APUT_ALIAS1..4
_IGET_ALIASES  = [VmpOp(v) for v in range(193, 196)]   # IGET_ALIAS1..3
_IPUT_ALIASES  = [VmpOp(v) for v in range(196, 199)]   # IPUT_ALIAS1..3
_SGET_SPUT_ALIASES = [VmpOp(199)]                       # SGET_SPUT_ALIAS1

# Semantic alias pools that are actually emitted by the compiler.  The enum
# names are historical; native dispatch below gives these opcodes their active
# meaning.  Keep high-risk opcodes (field/array/invoke/branch/div/rem/shift)
# out of this table.
_SUB_INT_ALIASES = [VmpOp.UNOP_ALIAS1, VmpOp.UNOP_ALIAS2, VmpOp.UNOP_ALIAS3]
_AND_INT_ALIASES = [VmpOp.UNOP_ALIAS4, VmpOp.UNOP_ALIAS5]
_OR_INT_ALIASES = [VmpOp.IF_ALIAS1, VmpOp.IF_ALIAS2]
_XOR_INT_ALIASES = [VmpOp.IF_ALIAS3, VmpOp.IF_ALIAS4]

# Canonical VMP ops that alias ops map back to (for the interpreter).
_ALIAS_CANONICAL: dict[VmpOp, VmpOp] = {}
for _a in _BINOP_ALIASES: _ALIAS_CANONICAL[_a] = VmpOp.ADD_INT
for _a in _SUB_INT_ALIASES: _ALIAS_CANONICAL[_a] = VmpOp.SUB_INT
for _a in _AND_INT_ALIASES: _ALIAS_CANONICAL[_a] = VmpOp.AND_INT
for _a in _OR_INT_ALIASES: _ALIAS_CANONICAL[_a] = VmpOp.OR_INT
for _a in _XOR_INT_ALIASES: _ALIAS_CANONICAL[_a] = VmpOp.XOR_INT
for _a in _BINOP_LIT_ALIASES: _ALIAS_CANONICAL[_a] = VmpOp.ADD_INT
for _a in _IF_ALIASES:
    _ALIAS_CANONICAL.setdefault(_a, VmpOp.IF_EQ)
for _a in _IFZ_ALIASES:   _ALIAS_CANONICAL[_a] = VmpOp.IF_EQZ
for _a in _AGET_ALIASES:  _ALIAS_CANONICAL[_a] = VmpOp.AGET
for _a in _APUT_ALIASES:  _ALIAS_CANONICAL[_a] = VmpOp.APUT
for _a in _IGET_ALIASES:  _ALIAS_CANONICAL[_a] = VmpOp.IGET
for _a in _IPUT_ALIASES:  _ALIAS_CANONICAL[_a] = VmpOp.IPUT
for _a in _SGET_SPUT_ALIASES: _ALIAS_CANONICAL[_a] = VmpOp.SGET


def generate_d2v_map(rng: random.Random | None = None) -> dict[int, VmpOp]:
    """Generate a per-build Dalvik→VMP opcode mapping with random aliases.

    Different Dalvik opcodes that typically collapse into the same VMP op
    (e.g. add-int/sub-int/mul-int → ADD_INT) are randomly assigned distinct
    alias opcodes, breaking the static 1:1 mapping.
    """
    rng = rng or random.Random()
    d2v: dict[int, VmpOp] = {}

    def _assign(dalvik_ops: list[int], canon: VmpOp, aliases: list[VmpOp]):
        """Assign each Dalvik op to either canon or a random alias."""
        pool = [canon] + aliases
        for d in dalvik_ops:
            d2v[d] = rng.choice(pool)

    def _assign_seq(dalvik_ops: list[int], vmp_op: VmpOp):
        for d in dalvik_ops:
            d2v[d] = vmp_op

    # Opcodes with fixed 1:1 mapping (no aliasing needed)
    d2v[0x00] = VmpOp.NOP
    _assign_seq([0x01, 0x02, 0x03], VmpOp.MOVE)
    _assign_seq([0x04, 0x05, 0x06], VmpOp.MOVE_WIDE)
    _assign_seq([0x07, 0x08, 0x09], VmpOp.MOVE_OBJECT)
    _assign_seq([0x0A], VmpOp.MOVE_RESULT)
    _assign_seq([0x0B], VmpOp.MOVE_RESULT_WIDE)
    _assign_seq([0x0C], VmpOp.MOVE_RESULT_OBJECT)
    _assign_seq([0x0D], VmpOp.MOVE_EXCEPTION)
    _assign_seq([0x0E], VmpOp.RETURN_VOID)
    _assign_seq([0x0F], VmpOp.RETURN)
    _assign_seq([0x10], VmpOp.RETURN_WIDE)
    _assign_seq([0x11], VmpOp.RETURN_OBJECT)
    _assign_seq([0x12, 0x13, 0x14, 0x15], VmpOp.CONST)
    _assign_seq([0x16, 0x17, 0x18, 0x19], VmpOp.CONST_WIDE)
    _assign_seq([0x1A, 0x1B], VmpOp.CONST_STRING)
    _assign_seq([0x1C], VmpOp.CONST_CLASS)
    _assign_seq([0x1D], VmpOp.MONITOR_ENTER)
    _assign_seq([0x1E], VmpOp.MONITOR_EXIT)
    _assign_seq([0x1F], VmpOp.CHECK_CAST)
    _assign_seq([0x20], VmpOp.INSTANCE_OF)
    _assign_seq([0x21], VmpOp.ARRAY_LENGTH)
    _assign_seq([0x22], VmpOp.NEW_INSTANCE)
    _assign_seq([0x23], VmpOp.NEW_ARRAY)
    _assign_seq([0x24, 0x25], VmpOp.FILLED_NEW_ARRAY)
    _assign_seq([0x26], VmpOp.FILL_ARRAY_DATA)
    _assign_seq([0x27], VmpOp.THROW)
    _assign_seq([0x28, 0x29, 0x2A], VmpOp.GOTO)
    _assign_seq([0x2B], VmpOp.PACKED_SWITCH)
    _assign_seq([0x2C], VmpOp.SPARSE_SWITCH)
    _assign_seq([0x2D], VmpOp.CMP_LONG)
    _assign_seq([0x2E], VmpOp.CMPG_FLOAT)
    _assign_seq([0x2F], VmpOp.CMPL_FLOAT)
    _assign_seq([0x30], VmpOp.CMPG_DOUBLE)
    _assign_seq([0x31], VmpOp.CMPL_DOUBLE)

    # IF/IFZ families: each Dalvik branch opcode maps 1:1 to its correct
    # VMP comparator. Aliasing is NOT used because the interpreter dispatches
    # each variant to a different handler (IF_EQ/NE/LT/GE/GT/LE).
    # IF family (0x32-0x37)
    _assign_seq([0x32], VmpOp.IF_EQ)
    _assign_seq([0x33], VmpOp.IF_NE)
    _assign_seq([0x34], VmpOp.IF_LT)
    _assign_seq([0x35], VmpOp.IF_GE)
    _assign_seq([0x36], VmpOp.IF_GT)
    _assign_seq([0x37], VmpOp.IF_LE)
    # IFZ family (0x38-0x3D)
    _assign_seq([0x38], VmpOp.IF_EQZ)
    _assign_seq([0x39], VmpOp.IF_NEZ)
    _assign_seq([0x3A], VmpOp.IF_LTZ)
    _assign_seq([0x3B], VmpOp.IF_GEZ)
    _assign_seq([0x3C], VmpOp.IF_GTZ)
    _assign_seq([0x3D], VmpOp.IF_LEZ)

    # AGET/APUT/IGET/IPUT/SGET/SPUT families: each Dalvik opcode maps 1:1 to
    # its correct VMP subtype. Aliasing is NOT used because the interpreter
    # derives the element kind from op - BASE_OP (e.g. VMP_AGET_BYTE - VMP_AGET
    # = VMP_KIND_BYTE). Using aliases would break the kind computation.
    # AGET family (0x44-0x4A)
    _assign_seq([0x44], VmpOp.AGET)
    _assign_seq([0x45], VmpOp.AGET_WIDE)
    _assign_seq([0x46], VmpOp.AGET_OBJECT)
    _assign_seq([0x47], VmpOp.AGET_BOOLEAN)
    _assign_seq([0x48], VmpOp.AGET_BYTE)
    _assign_seq([0x49], VmpOp.AGET_CHAR)
    _assign_seq([0x4A], VmpOp.AGET_SHORT)
    # APUT family (0x4B-0x51)
    _assign_seq([0x4B], VmpOp.APUT)
    _assign_seq([0x4C], VmpOp.APUT_WIDE)
    _assign_seq([0x4D], VmpOp.APUT_OBJECT)
    _assign_seq([0x4E], VmpOp.APUT_BOOLEAN)
    _assign_seq([0x4F], VmpOp.APUT_BYTE)
    _assign_seq([0x50], VmpOp.APUT_CHAR)
    _assign_seq([0x51], VmpOp.APUT_SHORT)
    # IGET family (0x52-0x58)
    _assign_seq([0x52], VmpOp.IGET)
    _assign_seq([0x53], VmpOp.IGET_WIDE)
    _assign_seq([0x54], VmpOp.IGET_OBJECT)
    _assign_seq([0x55], VmpOp.IGET_BOOLEAN)
    _assign_seq([0x56], VmpOp.IGET_BYTE)
    _assign_seq([0x57], VmpOp.IGET_CHAR)
    _assign_seq([0x58], VmpOp.IGET_SHORT)
    # IPUT family (0x59-0x5F)
    _assign_seq([0x59], VmpOp.IPUT)
    _assign_seq([0x5A], VmpOp.IPUT_WIDE)
    _assign_seq([0x5B], VmpOp.IPUT_OBJECT)
    _assign_seq([0x5C], VmpOp.IPUT_BOOLEAN)
    _assign_seq([0x5D], VmpOp.IPUT_BYTE)
    _assign_seq([0x5E], VmpOp.IPUT_CHAR)
    _assign_seq([0x5F], VmpOp.IPUT_SHORT)
    # SGET family (0x60-0x66)
    _assign_seq([0x60], VmpOp.SGET)
    _assign_seq([0x61], VmpOp.SGET_WIDE)
    _assign_seq([0x62], VmpOp.SGET_OBJECT)
    _assign_seq([0x63], VmpOp.SGET_BOOLEAN)
    _assign_seq([0x64], VmpOp.SGET_BYTE)
    _assign_seq([0x65], VmpOp.SGET_CHAR)
    _assign_seq([0x66], VmpOp.SGET_SHORT)
    # SPUT family (0x67-0x6D)
    _assign_seq([0x67], VmpOp.SPUT)
    _assign_seq([0x68], VmpOp.SPUT_WIDE)
    _assign_seq([0x69], VmpOp.SPUT_OBJECT)
    _assign_seq([0x6A], VmpOp.SPUT_BOOLEAN)
    _assign_seq([0x6B], VmpOp.SPUT_BYTE)
    _assign_seq([0x6C], VmpOp.SPUT_CHAR)
    _assign_seq([0x6D], VmpOp.SPUT_SHORT)

    _assign_seq([0x6E, 0x74], VmpOp.INVOKE_VIRTUAL)
    _assign_seq([0x6F, 0x75], VmpOp.INVOKE_SUPER)
    _assign_seq([0x70, 0x76], VmpOp.INVOKE_DIRECT)
    _assign_seq([0x71, 0x77], VmpOp.INVOKE_STATIC)
    _assign_seq([0x72, 0x78], VmpOp.INVOKE_INTERFACE)

    # Unary ops (0x7B-0x8F): each Dalvik opcode maps 1:1 to its correct VMP
    # subtype. Alias opcode space is reserved for low-risk int binop variants.
    _assign_seq([0x7B], VmpOp.NEG_INT)
    _assign_seq([0x7C], VmpOp.NOT_INT)
    _assign_seq([0x7D], VmpOp.NEG_LONG)
    _assign_seq([0x7E], VmpOp.NOT_LONG)
    _assign_seq([0x7F], VmpOp.NEG_FLOAT)
    _assign_seq([0x80], VmpOp.NEG_DOUBLE)
    _assign_seq([0x81], VmpOp.INT_TO_LONG)
    _assign_seq([0x82], VmpOp.INT_TO_FLOAT)
    _assign_seq([0x83], VmpOp.INT_TO_DOUBLE)
    _assign_seq([0x84], VmpOp.LONG_TO_INT)
    _assign_seq([0x85], VmpOp.LONG_TO_FLOAT)
    _assign_seq([0x86], VmpOp.LONG_TO_DOUBLE)
    _assign_seq([0x87], VmpOp.FLOAT_TO_INT)
    _assign_seq([0x88], VmpOp.FLOAT_TO_LONG)
    _assign_seq([0x89], VmpOp.FLOAT_TO_DOUBLE)
    _assign_seq([0x8A], VmpOp.DOUBLE_TO_INT)
    _assign_seq([0x8B], VmpOp.DOUBLE_TO_LONG)
    _assign_seq([0x8C], VmpOp.DOUBLE_TO_FLOAT)
    _assign_seq([0x8D], VmpOp.INT_TO_BYTE)
    _assign_seq([0x8E], VmpOp.INT_TO_CHAR)
    _assign_seq([0x8F], VmpOp.INT_TO_SHORT)

    # Binary ops 23x (0x90-0xAF): low-risk int ops may use semantic aliases;
    # exception-throwing and shift/mul ops stay 1:1.
    _assign([0x90], VmpOp.ADD_INT, _BINOP_ALIASES);    _assign([0x91], VmpOp.SUB_INT, _SUB_INT_ALIASES)
    _assign_seq([0x92], VmpOp.MUL_INT);    _assign_seq([0x93], VmpOp.DIV_INT)
    _assign_seq([0x94], VmpOp.REM_INT);    _assign([0x95], VmpOp.AND_INT, _AND_INT_ALIASES)
    _assign([0x96], VmpOp.OR_INT, _OR_INT_ALIASES);     _assign([0x97], VmpOp.XOR_INT, _XOR_INT_ALIASES)
    _assign_seq([0x98], VmpOp.SHL_INT);    _assign_seq([0x99], VmpOp.SHR_INT)
    _assign_seq([0x9A], VmpOp.USHR_INT)
    # long ops
    _assign_seq([0x9B], VmpOp.ADD_LONG);   _assign_seq([0x9C], VmpOp.SUB_LONG)
    _assign_seq([0x9D], VmpOp.MUL_LONG);   _assign_seq([0x9E], VmpOp.DIV_LONG)
    _assign_seq([0x9F], VmpOp.REM_LONG);   _assign_seq([0xA0], VmpOp.AND_LONG)
    _assign_seq([0xA1], VmpOp.OR_LONG);    _assign_seq([0xA2], VmpOp.XOR_LONG)
    _assign_seq([0xA3], VmpOp.SHL_LONG);   _assign_seq([0xA4], VmpOp.SHR_LONG)
    _assign_seq([0xA5], VmpOp.USHR_LONG)
    # float ops
    _assign_seq([0xA6], VmpOp.ADD_FLOAT);  _assign_seq([0xA7], VmpOp.SUB_FLOAT)
    _assign_seq([0xA8], VmpOp.MUL_FLOAT);  _assign_seq([0xA9], VmpOp.DIV_FLOAT)
    _assign_seq([0xAA], VmpOp.REM_FLOAT)
    # double ops
    _assign_seq([0xAB], VmpOp.ADD_DOUBLE); _assign_seq([0xAC], VmpOp.SUB_DOUBLE)
    _assign_seq([0xAD], VmpOp.MUL_DOUBLE); _assign_seq([0xAE], VmpOp.DIV_DOUBLE)
    _assign_seq([0xAF], VmpOp.REM_DOUBLE)

    # Binary ops /2addr (0xB0-0xCF): same op mapping as 23x, shifted by 0x20.
    # int/2addr
    _assign([0xB0], VmpOp.ADD_INT, _BINOP_ALIASES);    _assign([0xB1], VmpOp.SUB_INT, _SUB_INT_ALIASES)
    _assign_seq([0xB2], VmpOp.MUL_INT);    _assign_seq([0xB3], VmpOp.DIV_INT)
    _assign_seq([0xB4], VmpOp.REM_INT);    _assign([0xB5], VmpOp.AND_INT, _AND_INT_ALIASES)
    _assign([0xB6], VmpOp.OR_INT, _OR_INT_ALIASES);     _assign([0xB7], VmpOp.XOR_INT, _XOR_INT_ALIASES)
    _assign_seq([0xB8], VmpOp.SHL_INT);    _assign_seq([0xB9], VmpOp.SHR_INT)
    _assign_seq([0xBA], VmpOp.USHR_INT)
    # long/2addr
    _assign_seq([0xBB], VmpOp.ADD_LONG);   _assign_seq([0xBC], VmpOp.SUB_LONG)
    _assign_seq([0xBD], VmpOp.MUL_LONG);   _assign_seq([0xBE], VmpOp.DIV_LONG)
    _assign_seq([0xBF], VmpOp.REM_LONG);   _assign_seq([0xC0], VmpOp.AND_LONG)
    _assign_seq([0xC1], VmpOp.OR_LONG);    _assign_seq([0xC2], VmpOp.XOR_LONG)
    _assign_seq([0xC3], VmpOp.SHL_LONG);   _assign_seq([0xC4], VmpOp.SHR_LONG)
    _assign_seq([0xC5], VmpOp.USHR_LONG)
    # float/2addr
    _assign_seq([0xC6], VmpOp.ADD_FLOAT);  _assign_seq([0xC7], VmpOp.SUB_FLOAT)
    _assign_seq([0xC8], VmpOp.MUL_FLOAT);  _assign_seq([0xC9], VmpOp.DIV_FLOAT)
    _assign_seq([0xCA], VmpOp.REM_FLOAT)
    # double/2addr
    _assign_seq([0xCB], VmpOp.ADD_DOUBLE); _assign_seq([0xCC], VmpOp.SUB_DOUBLE)
    _assign_seq([0xCD], VmpOp.MUL_DOUBLE); _assign_seq([0xCE], VmpOp.DIV_DOUBLE)
    _assign_seq([0xCF], VmpOp.REM_DOUBLE)

    # Binary ops /lit16 (0xD0-0xD7)
    _assign([0xD0], VmpOp.ADD_INT, _BINOP_LIT_ALIASES)
    _assign([0xD1], VmpOp.SUB_INT, _SUB_INT_ALIASES)
    _assign_seq([0xD2], VmpOp.MUL_INT)
    _assign_seq([0xD3], VmpOp.DIV_INT)
    _assign_seq([0xD4], VmpOp.REM_INT)
    _assign([0xD5], VmpOp.AND_INT, _AND_INT_ALIASES)
    _assign([0xD6], VmpOp.OR_INT, _OR_INT_ALIASES)
    _assign([0xD7], VmpOp.XOR_INT, _XOR_INT_ALIASES)

    # Binary ops /lit8 (0xD8-0xE2)
    _assign([0xD8], VmpOp.ADD_INT, _BINOP_LIT_ALIASES);    _assign([0xD9], VmpOp.SUB_INT, _SUB_INT_ALIASES)
    _assign_seq([0xDA], VmpOp.MUL_INT);    _assign_seq([0xDB], VmpOp.DIV_INT)
    _assign_seq([0xDC], VmpOp.REM_INT);    _assign([0xDD], VmpOp.AND_INT, _AND_INT_ALIASES)
    _assign([0xDE], VmpOp.OR_INT, _OR_INT_ALIASES);     _assign([0xDF], VmpOp.XOR_INT, _XOR_INT_ALIASES)
    _assign_seq([0xE0], VmpOp.SHL_INT);    _assign_seq([0xE1], VmpOp.SHR_INT)
    _assign_seq([0xE2], VmpOp.USHR_INT)

    # invoke-polymorphic / invoke-custom
    d2v[0xFA] = VmpOp.INVOKE_POLYMORPHIC
    d2v[0xFB] = VmpOp.INVOKE_POLYMORPHIC
    d2v[0xFC] = VmpOp.INVOKE_CUSTOM
    d2v[0xFD] = VmpOp.INVOKE_CUSTOM

    return d2v

# Default mapping (no aliases) for fallback/module-level use
_d2v_default = generate_d2v_map(random.Random(0))


# ── VMP instruction ──────────────────────────────────────────────────────

@dataclass
class VmpInsn:
    """8-byte fixed-width VMP instruction."""
    real_op: int = 0   # VmpOp value (before shuffle)
    dst: int = 0
    src1: int = 0
    src2: int = 0
    imm: int = 0       # signed 32-bit

    def pack(self, shuffle: list[int]) -> bytes:
        shuffled_op = shuffle[self.real_op]
        return struct.pack("<BBBBi", shuffled_op, self.dst, self.src1, self.src2, _to_i32(self.imm))

    def pack_raw(self, shuffle: list[int]) -> bytes:
        shuffled_op = shuffle[self.real_op]
        return struct.pack("<BBBBi", shuffled_op, self.dst, self.src1, self.src2, _to_i32(self.imm))


# ── Reference pool ───────────────────────────────────────────────────────

class RefPool:
    """String pool + method/field/type reference pool for VMP blob."""

    def __init__(self) -> None:
        self._strings: list[str] = []
        self._string_map: dict[str, int] = {}

    def intern(self, s: str) -> int:
        if s in self._string_map:
            return self._string_map[s]
        idx = len(self._strings)
        self._strings.append(s)
        self._string_map[s] = idx
        return idx

    @property
    def strings(self) -> list[str]:
        return self._strings


# ── Dalvik instruction decoder ───────────────────────────────────────────

def _u16le(insns: bytes, off: int) -> int:
    val: int = struct.unpack_from("<H", insns, off)[0]
    return val

def _s16le(insns: bytes, off: int) -> int:
    val: int = struct.unpack_from("<h", insns, off)[0]
    return val

def _u32le(insns: bytes, off: int) -> int:
    val: int = struct.unpack_from("<I", insns, off)[0]
    return val

def _s32le(insns: bytes, off: int) -> int:
    val: int = struct.unpack_from("<i", insns, off)[0]
    return val

def _checked_i32(v: int, ctx: str) -> int:
    if v < -0x80000000 or v > 0x7FFFFFFF:
        raise ValueError(f"VMP {ctx} out of int32 range: {v}")
    return int(v)


def _read_u16_checked(insns: bytes, off: int, ctx: str) -> int:
    if off < 0 or off + 2 > len(insns):
        raise ValueError(f"VMP {ctx} out of range")
    return _u16le(insns, off)


def _read_u32_checked(insns: bytes, off: int, ctx: str) -> int:
    if off < 0 or off + 4 > len(insns):
        raise ValueError(f"VMP {ctx} out of range")
    return _u32le(insns, off)


def _read_s32_checked(insns: bytes, off: int, ctx: str) -> int:
    if off < 0 or off + 4 > len(insns):
        raise ValueError(f"VMP {ctx} out of range")
    return _s32le(insns, off)


def _ensure_spec_fits_pool(spec: str, ctx: str) -> str:
    if len(spec.encode("utf-8")) > 0xFFFF:
        raise ValueError(f"VMP {ctx} spec too large for string pool")
    return spec


def _payload_width_code_units(insns: bytes, pos_cu: int, total_cu: int) -> int:
    """Return pseudo-payload width at pos, or 0 when pos is a normal opcode."""
    byte_off = pos_cu * 2
    if byte_off + 2 > len(insns):
        return 0
    ident = _u16le(insns, byte_off)
    if ident == 0x0100:  # packed-switch-payload
        if byte_off + 4 > len(insns):
            return 0
        size = _u16le(insns, byte_off + 2)
        width = 4 + size * 2
    elif ident == 0x0200:  # sparse-switch-payload
        if byte_off + 4 > len(insns):
            return 0
        size = _u16le(insns, byte_off + 2)
        width = 2 + size * 4
    elif ident == 0x0300:  # fill-array-data-payload
        if byte_off + 8 > len(insns):
            return 0
        element_width = _u16le(insns, byte_off + 2)
        size = _u32le(insns, byte_off + 4)
        width = 4 + ((element_width * size + 1) // 2)
    else:
        return 0
    return width if pos_cu + width <= total_cu else 0


def _build_payload_spec(
    opcode: int,
    insns: bytes,
    insn_pos_cu: int,
    payload_pos_cu: int,
    off_to_idx: dict[int, int],
    vmp_idx: int,
) -> str:
    payload_byte_off = payload_pos_cu * 2

    if opcode == 0x2B:  # packed-switch
        ident = _read_u16_checked(insns, payload_byte_off, "packed-switch ident")
        if ident != 0x0100:
            raise ValueError(f"VMP packed-switch payload ident mismatch: {ident:#06x}")
        size = _read_u16_checked(insns, payload_byte_off + 2, "packed-switch size")
        first_key = _read_s32_checked(insns, payload_byte_off + 4, "packed-switch first_key")
        rel_targets: list[int] = []
        base = payload_byte_off + 8
        for i in range(size):
            dalvik_rel = _read_s32_checked(insns, base + i * 4, f"packed-switch target[{i}]")
            dalvik_target = insn_pos_cu + dalvik_rel
            target_vmp_idx = off_to_idx.get(dalvik_target, vmp_idx + 1)
            rel_targets.append(_checked_i32(target_vmp_idx - vmp_idx, f"packed-switch rel[{i}]"))
        targets_text = ",".join(str(x) for x in rel_targets)
        return _ensure_spec_fits_pool(f"PS|{first_key}|{targets_text}", "packed-switch")

    if opcode == 0x2C:  # sparse-switch
        ident = _read_u16_checked(insns, payload_byte_off, "sparse-switch ident")
        if ident != 0x0200:
            raise ValueError(f"VMP sparse-switch payload ident mismatch: {ident:#06x}")
        size = _read_u16_checked(insns, payload_byte_off + 2, "sparse-switch size")
        keys_base = payload_byte_off + 4
        targets_base = keys_base + size * 4
        items: list[str] = []
        for i in range(size):
            key = _read_s32_checked(insns, keys_base + i * 4, f"sparse-switch key[{i}]")
            dalvik_rel = _read_s32_checked(insns, targets_base + i * 4, f"sparse-switch target[{i}]")
            dalvik_target = insn_pos_cu + dalvik_rel
            target_vmp_idx = off_to_idx.get(dalvik_target, vmp_idx + 1)
            rel = _checked_i32(target_vmp_idx - vmp_idx, f"sparse-switch rel[{i}]")
            items.append(f"{key}:{rel}")
        return _ensure_spec_fits_pool(f"SS|{','.join(items)}", "sparse-switch")

    if opcode == 0x26:  # fill-array-data
        ident = _read_u16_checked(insns, payload_byte_off, "fill-array-data ident")
        if ident != 0x0300:
            raise ValueError(f"VMP fill-array-data payload ident mismatch: {ident:#06x}")
        elem_width = _read_u16_checked(insns, payload_byte_off + 2, "fill-array-data elem_width")
        elem_count = _read_u32_checked(insns, payload_byte_off + 4, "fill-array-data elem_count")
        if elem_width not in (1, 2, 4, 8):
            raise ValueError(f"VMP fill-array-data unsupported elem_width: {elem_width}")
        total_bytes = elem_width * elem_count
        data_off = payload_byte_off + 8
        if data_off < 0 or data_off + total_bytes > len(insns):
            raise ValueError("VMP fill-array-data raw payload out of range")
        raw = insns[data_off: data_off + total_bytes]
        spec = f"FA|{elem_width}|{elem_count}|{raw.hex()}"
        return _ensure_spec_fits_pool(spec, "fill-array-data")

    raise ValueError(f"VMP unsupported payload opcode: {opcode:#04x}")


def _encode_normal_src2(reg: int) -> tuple[int, int]:
    if reg == 0:
        return 0, VMP_BINOP_REG0_SENTINEL
    return reg & 0xFF, 0


def _encode_lit_imm(lit: int) -> int:
    return VMP_BINOP_LIT_ZERO_SENTINEL if lit == 0 else lit


def decode_dalvik_method(
    dex: DexFile,
    code: CodeItem,
    pool: RefPool,
    d2v: dict[int, VmpOp] | None = None,
) -> tuple[list[VmpInsn], dict[int, int]]:
    """Convert one method's Dalvik bytecode to VMP instruction list."""
    insns = code.insns
    result: list[VmpInsn] = []
    # Map from code-unit offset to VMP insn index for branch fixup.
    off_to_idx: dict[int, int] = {}
    # Deferred branch fixups: (vmp_insn_index, dalvik_branch_target_offset).
    branch_fixups: list[tuple[int, int]] = []
    # Deferred payload fixups for 31t payload opcodes:
    # (opcode, vmp_insn_index, insn_pos_cu, payload_pos_cu).
    payload_fixups: list[tuple[int, int, int, int]] = []

    pos = 0  # position in code units (each = 2 bytes)
    while pos < code.insns_size:
        byte_off = pos * 2
        word0 = _u16le(insns, byte_off)
        opcode = word0 & 0xFF

        payload_width = _payload_width_code_units(insns, pos, code.insns_size)
        if payload_width:
            pos += payload_width
            continue

        off_to_idx[pos] = len(result)

        fmt_info = _FMT.get(opcode)
        if fmt_info is None:
            # Unknown opcode → NOP
            result.append(VmpInsn(real_op=int(VmpOp.NOP)))
            pos += 1
            continue

        fmt, width = fmt_info
        if width <= 0 or byte_off + width * 2 > len(insns):
            raise ValueError(
                f"truncated opcode {opcode:#04x} ({fmt}) at code-unit {pos}, "
                f"need {width * 2} bytes from offset {byte_off}, have {len(insns) - byte_off}"
            )
        vmp_op_val = int(d2v.get(opcode, VmpOp.NOP)) if d2v else int(_d2v_default.get(opcode, VmpOp.NOP))

        if fmt == "10x":
            result.append(VmpInsn(real_op=vmp_op_val))
        elif fmt == "12x":
            a = (word0 >> 8) & 0x0F
            b = (word0 >> 12) & 0x0F
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, src1=b))
        elif fmt == "11n":
            a = (word0 >> 8) & 0x0F
            b = (word0 >> 12) & 0x0F
            if b & 0x8:
                b -= 16
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, imm=b))
        elif fmt == "11x":
            a = (word0 >> 8) & 0xFF
            result.append(VmpInsn(real_op=vmp_op_val, dst=a))
        elif fmt == "10t":
            a = (word0 >> 8) & 0xFF
            if a & 0x80:
                a -= 256
            target = pos + a
            idx = len(result)
            result.append(VmpInsn(real_op=vmp_op_val, imm=0))
            branch_fixups.append((idx, target))
        elif fmt == "20t":
            target = pos + _s16le(insns, byte_off + 2)
            idx = len(result)
            result.append(VmpInsn(real_op=vmp_op_val, imm=0))
            branch_fixups.append((idx, target))
        elif fmt == "22x":
            a = (word0 >> 8) & 0xFF
            b = _u16le(insns, byte_off + 2)
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, src1=b & 0xFF, src2=(b >> 8) & 0xFF))
        elif fmt == "32x":
            a = _u16le(insns, byte_off + 2)
            b = _u16le(insns, byte_off + 4)
            result.append(VmpInsn(real_op=vmp_op_val, dst=a & 0xFF, src1=b & 0xFF))
        elif fmt == "21s":
            a = (word0 >> 8) & 0xFF
            b = _s16le(insns, byte_off + 2)
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, imm=b))
        elif fmt == "21h":
            a = (word0 >> 8) & 0xFF
            b = _s16le(insns, byte_off + 2)
            if opcode == 0x15:
                result.append(VmpInsn(real_op=vmp_op_val, dst=a, imm=b << 16))
            else:
                result.append(VmpInsn(real_op=vmp_op_val, dst=a, imm=b))
        elif fmt == "21c":
            a = (word0 >> 8) & 0xFF
            idx_val = _u16le(insns, byte_off + 2)
            # Resolve reference to string pool
            ref_idx = _intern_dex_ref(dex, opcode, idx_val, pool)
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, imm=ref_idx))
        elif fmt == "21t":
            a = (word0 >> 8) & 0xFF
            target = pos + _s16le(insns, byte_off + 2)
            idx = len(result)
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, imm=0))
            branch_fixups.append((idx, target))
        elif fmt == "23x":
            a = (word0 >> 8) & 0xFF
            w1 = _u16le(insns, byte_off + 2)
            b = w1 & 0xFF
            c = (w1 >> 8) & 0xFF
            src2, mode_imm = _encode_normal_src2(c)
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, src1=b, src2=src2, imm=mode_imm))
        elif fmt == "22b":
            a = (word0 >> 8) & 0xFF
            w1 = _u16le(insns, byte_off + 2)
            b = w1 & 0xFF
            c = (w1 >> 8) & 0xFF
            if c & 0x80:
                c -= 256
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, src1=b, imm=_encode_lit_imm(c)))
        elif fmt == "22t":
            a = (word0 >> 8) & 0x0F
            b = (word0 >> 12) & 0x0F
            target = pos + _s16le(insns, byte_off + 2)
            idx = len(result)
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, src1=b, imm=0))
            branch_fixups.append((idx, target))
        elif fmt == "22s":
            a = (word0 >> 8) & 0x0F
            b = (word0 >> 12) & 0x0F
            c = _s16le(insns, byte_off + 2)
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, src1=b, imm=_encode_lit_imm(c)))
        elif fmt == "22c":
            a = (word0 >> 8) & 0x0F
            b = (word0 >> 12) & 0x0F
            idx_val = _u16le(insns, byte_off + 2)
            ref_idx = _intern_dex_ref(dex, opcode, idx_val, pool)
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, src1=b, imm=ref_idx))
        elif fmt == "30t":
            lo = _u16le(insns, byte_off + 2)
            hi = _u16le(insns, byte_off + 4)
            target = pos + (lo | (hi << 16))
            if target & 0x80000000:
                target -= 0x100000000
            idx = len(result)
            result.append(VmpInsn(real_op=vmp_op_val, imm=0))
            branch_fixups.append((idx, int(target)))
        elif fmt == "31i":
            a = (word0 >> 8) & 0xFF
            lo = _u16le(insns, byte_off + 2)
            hi = _u16le(insns, byte_off + 4)
            imm = lo | (hi << 16)
            if imm & 0x80000000:
                imm -= 0x100000000
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, imm=int(imm)))
        elif fmt == "31t":
            a = (word0 >> 8) & 0xFF
            lo = _u16le(insns, byte_off + 2)
            hi = _u16le(insns, byte_off + 4)
            branch_off = lo | (hi << 16)
            if branch_off & 0x80000000:
                branch_off -= 0x100000000
            idx = len(result)
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, imm=0))
            target = pos + int(branch_off)
            if opcode in (0x26, 0x2B, 0x2C):
                payload_fixups.append((opcode, idx, pos, target))
            else:
                branch_fixups.append((idx, target))
        elif fmt == "31c":
            a = (word0 >> 8) & 0xFF
            lo = _u16le(insns, byte_off + 2)
            hi = _u16le(insns, byte_off + 4)
            idx_val = lo | (hi << 16)
            ref_idx = _intern_dex_ref(dex, opcode, idx_val, pool)
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, imm=ref_idx))
        elif fmt == "35c":
            a_count = (word0 >> 12) & 0x0F
            method_idx = _u16le(insns, byte_off + 2)
            regs_word = _u16le(insns, byte_off + 4)
            ref_idx = _intern_dex_ref(dex, opcode, method_idx, pool)
            # Encode: main insn carries ref + arg count; INVOKE_ARGS carries regs.
            c_reg = regs_word & 0x0F
            d_reg = (regs_word >> 4) & 0x0F
            e_reg = (regs_word >> 8) & 0x0F
            f_reg = (regs_word >> 12) & 0x0F
            g_reg = (word0 >> 8) & 0x0F
            result.append(VmpInsn(real_op=vmp_op_val, dst=a_count, imm=ref_idx))
            # Pack up to 5 arg registers in a follow-up pseudo-instruction.
            result.append(VmpInsn(
                real_op=int(VmpOp.INVOKE_ARGS),
                dst=c_reg, src1=d_reg, src2=e_reg,
                imm=(f_reg | (g_reg << 8)),
            ))
        elif fmt == "3rc":
            a_count = (word0 >> 8) & 0xFF
            method_idx = _u16le(insns, byte_off + 2)
            start_reg = _u16le(insns, byte_off + 4)
            ref_idx = _intern_dex_ref(dex, opcode, method_idx, pool)
            result.append(VmpInsn(real_op=vmp_op_val, dst=a_count, imm=ref_idx))
            result.append(VmpInsn(
                real_op=int(VmpOp.INVOKE_ARGS),
                dst=start_reg & 0xFF, src1=(start_reg >> 8) & 0xFF,
                imm=1,  # flag: range mode
            ))
        elif fmt == "51l":
            a = (word0 >> 8) & 0xFF
            val = 0
            for i in range(4):
                val |= _u16le(insns, byte_off + 2 + i * 2) << (i * 16)
            # Store as two VMP insns: low 32 + high 32
            lo32 = val & 0xFFFFFFFF
            hi32 = (val >> 32) & 0xFFFFFFFF
            result.append(VmpInsn(real_op=vmp_op_val, dst=a, imm=int(lo32) if lo32 < 0x80000000 else int(lo32) - 0x100000000))
            result.append(VmpInsn(real_op=int(VmpOp.CONST_WIDE_HI32), imm=int(hi32) if hi32 < 0x80000000 else int(hi32) - 0x100000000))
        elif fmt == "45cc":
            # invoke-polymorphic {vC..vG}, meth@BBBB, proto@HHHH
            a_count = (word0 >> 12) & 0x0F
            method_idx = _u16le(insns, byte_off + 2)
            regs_word = _u16le(insns, byte_off + 4)
            proto_idx = _u16le(insns, byte_off + 6)
            ref_idx = _intern_dex_ref(dex, opcode, method_idx, pool)
            c_reg = regs_word & 0x0F
            d_reg = (regs_word >> 4) & 0x0F
            e_reg = (regs_word >> 8) & 0x0F
            f_reg = (regs_word >> 12) & 0x0F
            g_reg = (word0 >> 8) & 0x0F
            result.append(VmpInsn(real_op=vmp_op_val, dst=a_count, imm=ref_idx))
            result.append(VmpInsn(
                real_op=int(VmpOp.INVOKE_ARGS),
                dst=c_reg, src1=d_reg, src2=e_reg,
                imm=(f_reg | (g_reg << 8)),
            ))
        elif fmt == "4rcc":
            # invoke-polymorphic/range {vCCCC..vNNNN}, meth@BBBB, proto@HHHH
            a_count = (word0 >> 8) & 0xFF
            method_idx = _u16le(insns, byte_off + 2)
            start_reg = _u16le(insns, byte_off + 4)
            # proto_idx at byte_off+6, not needed at VMP level
            ref_idx = _intern_dex_ref(dex, opcode, method_idx, pool)
            result.append(VmpInsn(real_op=vmp_op_val, dst=a_count, imm=ref_idx))
            result.append(VmpInsn(
                real_op=int(VmpOp.INVOKE_ARGS),
                dst=start_reg & 0xFF, src1=(start_reg >> 8) & 0xFF,
                imm=1,
            ))
        else:
            result.append(VmpInsn(real_op=int(VmpOp.NOP)))

        pos += width

    # Tag every instruction with its original VMP index (before transformations)
    # so branch targets can be rebuilt after split/obfuscate passes.
    for i, insn in enumerate(result):
        insn._orig_idx = i
        insn._target_vmp_idx = -1

    # Fixup branches: convert dalvik code-unit offsets to VMP insn indices.
    for vmp_idx, dalvik_target in branch_fixups:
        target_vmp_idx = off_to_idx.get(dalvik_target, vmp_idx + 1)
        result[vmp_idx].imm = target_vmp_idx - vmp_idx  # relative offset
        result[vmp_idx]._target_vmp_idx = target_vmp_idx  # absolute target for post-transform fixup
    # Resolve switch/fill payloads to pool strings and store string index in imm.
    for payload_opcode, vmp_idx, insn_pos_cu, payload_pos_cu in payload_fixups:
        spec = _build_payload_spec(
            payload_opcode,
            insns,
            insn_pos_cu,
            payload_pos_cu,
            off_to_idx,
            vmp_idx,
        )
        result[vmp_idx].imm = pool.intern(spec)

    return result, off_to_idx


def _intern_dex_ref(dex: DexFile, opcode: int, idx: int, pool: RefPool) -> int:
    """Intern a DEX constant pool reference into the VMP string pool."""
    # String references
    if opcode in (0x1A, 0x1B):
        return pool.intern(dex.strings[idx] if idx < len(dex.strings) else "")
    # Type references (const-class, check-cast, instance-of, new-instance, new-array)
    if opcode in (0x1C, 0x1F, 0x20, 0x22, 0x23, 0x24, 0x25):
        return pool.intern(dex.type_name(idx))
    # Field references
    if 0x52 <= opcode <= 0x6D:
        fid = dex.field_ids[idx]
        cls = dex.type_name(fid.class_idx)
        name = dex.strings[fid.name_idx]
        typ = dex.type_name(fid.type_idx)
        return pool.intern(f"{cls}->{name}:{typ}")
    # Method references (regular invokes)
    if 0x6E <= opcode <= 0x78:
        cls = dex.method_class_name(idx)
        name = dex.method_name(idx)
        sig = dex.method_signature(idx)
        return pool.intern(f"{cls}->{name}{sig}")
    # invoke-polymorphic: idx is a method_idx (MethodHandle.invoke / invokeExact)
    if opcode in (0xFA, 0xFB):
        cls = dex.method_class_name(idx)
        name = dex.method_name(idx)
        sig = dex.method_signature(idx)
        return pool.intern(f"{cls}->{name}{sig}")
    # invoke-custom: idx is a call_site_idx — resolve to rich call-site descriptor
    if opcode in (0xFC, 0xFD):
        return pool.intern(_build_call_site_ref(dex, idx))
    return pool.intern(str(idx))


_MH_KIND_NAMES = {
    0: "static_put", 1: "static_get", 2: "instance_put", 3: "instance_get",
    4: "invoke_static", 5: "invoke_instance", 6: "invoke_constructor",
    7: "invoke_direct", 8: "invoke_interface",
}


def _build_call_site_ref(dex: DexFile, cs_idx: int) -> str:
    """Build a call-site descriptor string for the VMP string pool.

    Format: @cs:<kind>|<target_ref>|<iface_method_name>
      - kind: method_handle kind number (4=static, 5=virtual, ...)
      - target_ref: Lclass;->name(sig)ret of the implementation method
      - iface_method_name: interface method name from call site (e.g. "run")

    Falls back to @cs:<cs_idx> if parsing fails.
    """
    if cs_idx < 0 or cs_idx >= len(dex.call_sites):
        return f"@cs:{cs_idx}"
    cs = dex.call_sites[cs_idx]
    # Get the target implementation method handle (item [4] if present)
    mh_idx = cs.extra_method_handle_idx
    if mh_idx < 0:
        mh_idx = cs.bootstrap_handle_idx
    if mh_idx < 0 or mh_idx >= len(dex.method_handles):
        return f"@cs:{cs_idx}"
    mh = dex.method_handles[mh_idx]
    kind = mh.method_handle_type
    target_ref = dex.method_handle_ref(mh_idx)
    if not target_ref:
        return f"@cs:{cs_idx}"
    iface_name = cs.method_name or "invoke"
    return f"@cs:{kind}|{target_ref}|{iface_name}"


# ── Opcode shuffle table ─────────────────────────────────────────────────

def generate_opcode_shuffle(seed: bytes | None = None) -> tuple[list[int], list[int]]:
    """Generate a random opcode permutation.

    Returns (shuffle, unshuffle) where:
      shuffle[real_op]    → shuffled_opcode  (used by compiler)
      unshuffle[shuffled] → real_op          (stored in blob for interpreter)
    """
    rng = random.Random(seed or os.urandom(32))
    perm = list(range(256))
    rng.shuffle(perm)
    # shuffle: real_op → shuffled
    shuffle = [0] * 256
    unshuffle = [0] * 256
    for shuffled, real_op in enumerate(perm):
        shuffle[real_op] = shuffled
        unshuffle[shuffled] = real_op
    return shuffle, unshuffle


# ── VMP try-catch structures ─────────────────────────────────────────────

@dataclass
class VmpCatchHandler:
    type_str_idx: int = -1  # string pool index of exception type descriptor, -1 = catch-all slot
    handler_pc: int = 0     # VMP instruction index to jump to

@dataclass
class VmpTryBlock:
    start_pc: int = 0       # VMP instruction index (inclusive)
    end_pc: int = 0         # VMP instruction index (exclusive)
    handlers: list[VmpCatchHandler] = field(default_factory=list)
    catch_all_pc: int = -1  # VMP instruction index, -1 if no catch-all


def _translate_try_catch(
    dex: DexFile,
    code: CodeItem,
    off_to_idx: dict[int, int],
    vmp_insn_count: int,
    pool: RefPool,
) -> list[VmpTryBlock]:
    """Translate Dalvik try-catch structures to VMP-addressed try blocks."""
    handler_map: dict[int, EncodedCatchHandler] = {}
    for ech in code.catch_handlers:
        handler_map[ech._list_offset] = ech

    blocks: list[VmpTryBlock] = []
    for ti in code.tries:
        catch_entry = handler_map.get(ti.handler_off)
        if catch_entry is None:
            continue

        start_vmp = off_to_idx.get(ti.start_addr, 0)
        end_dalvik = ti.start_addr + ti.insn_count
        end_vmp = off_to_idx.get(end_dalvik, vmp_insn_count)

        handlers: list[VmpCatchHandler] = []
        for ch in catch_entry.handlers:
            type_idx = -1
            if ch.type_idx != NO_INDEX:
                type_idx = pool.intern(dex.type_name(ch.type_idx))
            h_pc = off_to_idx.get(ch.addr, 0)
            handlers.append(VmpCatchHandler(type_str_idx=type_idx, handler_pc=h_pc))

        catch_all = -1
        if catch_entry.catch_all_addr >= 0:
            catch_all = off_to_idx.get(catch_entry.catch_all_addr, 0)

        blocks.append(VmpTryBlock(
            start_pc=start_vmp,
            end_pc=end_vmp,
            handlers=handlers,
            catch_all_pc=catch_all,
        ))

    return blocks


# ── VMP instruction splitting pass ──────────────────────────────────────

def _lfsr32(state: int) -> int:
    """One step of a 32-bit Galois LFSR (taps 32,31,29,1)."""
    lsb = state & 1
    state >>= 1
    if lsb:
        state ^= 0xD0000001
    return state & 0xFFFFFFFF


def _to_i32(v: int) -> int:
    """Convert a Python int to a proper signed int32 (fits in struct '<i')."""
    v = v & 0xFFFFFFFF
    if v >= 0x80000000:
        v -= 0x100000000
    return v


def _op_is_branch(real_op: int) -> bool:
    """Return True if the opcode is a branch/switch/goto."""
    return real_op in (
        int(VmpOp.GOTO),
        int(VmpOp.IF_EQ), int(VmpOp.IF_NE), int(VmpOp.IF_LT),
        int(VmpOp.IF_GE), int(VmpOp.IF_GT), int(VmpOp.IF_LE),
        int(VmpOp.IF_EQZ), int(VmpOp.IF_NEZ), int(VmpOp.IF_LTZ),
        int(VmpOp.IF_GEZ), int(VmpOp.IF_GTZ), int(VmpOp.IF_LEZ),
        int(VmpOp.PACKED_SWITCH), int(VmpOp.SPARSE_SWITCH),
    )


def _op_is_special(real_op: int) -> bool:
    """Return True for pseudo/special opcodes that must not be split."""
    return real_op in (
        int(VmpOp.INVOKE_ARGS), int(VmpOp.CONST_WIDE_HI32),
    )


_BINOP_REAL_OPS = {
    int(VmpOp.ADD_INT), int(VmpOp.SUB_INT), int(VmpOp.MUL_INT),
    int(VmpOp.DIV_INT), int(VmpOp.REM_INT), int(VmpOp.AND_INT),
    int(VmpOp.OR_INT), int(VmpOp.XOR_INT), int(VmpOp.SHL_INT),
    int(VmpOp.SHR_INT), int(VmpOp.USHR_INT),
    int(VmpOp.ADD_LONG), int(VmpOp.SUB_LONG), int(VmpOp.MUL_LONG),
    int(VmpOp.DIV_LONG), int(VmpOp.REM_LONG), int(VmpOp.AND_LONG),
    int(VmpOp.OR_LONG), int(VmpOp.XOR_LONG), int(VmpOp.SHL_LONG),
    int(VmpOp.SHR_LONG), int(VmpOp.USHR_LONG),
    int(VmpOp.ADD_FLOAT), int(VmpOp.SUB_FLOAT), int(VmpOp.MUL_FLOAT),
    int(VmpOp.DIV_FLOAT), int(VmpOp.REM_FLOAT),
    int(VmpOp.ADD_DOUBLE), int(VmpOp.SUB_DOUBLE), int(VmpOp.MUL_DOUBLE),
    int(VmpOp.DIV_DOUBLE), int(VmpOp.REM_DOUBLE),
}


def _insn_uses_2addr_operands(insn: VmpInsn) -> bool:
    """True when dst is also the hidden left operand."""
    return insn.real_op in _BINOP_REAL_OPS and insn.src2 == 0 and insn.imm == 0


def _pick_temp_register(rng: random.Random, registers_size: int) -> int | None:
    """Return a byte-encodable scratch register outside the method frame."""
    base = max(registers_size, 64)
    if base >= 256:
        return None
    return base + rng.randrange(256 - base)


def _fixup_branch_targets(insns: list[VmpInsn]) -> dict[int, int]:
    """Rebuild all branch target offsets after instruction insertion/deletion.

    Uses the _orig_idx and _target_vmp_idx tags set during decode_dalvik_method
    to recompute correct relative offsets.

    Returns the old→new index map for use by try-block fixup.
    """
    # Build old-to-new index map from surviving _orig_idx tags.
    old_to_new: dict[int, int] = {}
    for new_idx, insn in enumerate(insns):
        oi = getattr(insn, '_orig_idx', -1)
        if oi >= 0:
            old_to_new[oi] = new_idx

    # Fix up branch opcodes.
    for new_idx, insn in enumerate(insns):
        if not _op_is_branch(insn.real_op):
            continue
        target = getattr(insn, '_target_vmp_idx', -1)
        if target < 0:
            continue
        new_target = old_to_new.get(target, new_idx + 1)
        insn.imm = new_target - new_idx

    return old_to_new


def _fixup_try_blocks(
    blocks: list[VmpTryBlock],
    old_to_new: dict[int, int],
    insn_count: int,
) -> None:
    """Fix up try-block PCs after instruction insertion/deletion."""
    for tb in blocks:
        tb.start_pc = old_to_new.get(tb.start_pc, 0)
        tb.end_pc = old_to_new.get(tb.end_pc, insn_count)
        if tb.catch_all_pc >= 0:
            tb.catch_all_pc = old_to_new.get(tb.catch_all_pc, 0)
        for h in tb.handlers:
            h.handler_pc = old_to_new.get(h.handler_pc, 0)


def split_vmp_instructions(
    insns: list[VmpInsn],
    registers_size: int,
    rng: random.Random,
    split_prob: float = 0.35,
) -> list[VmpInsn]:
    """Probabilistically split single VMP instructions into semantically
    equivalent multi-instruction sequences, breaking the 1:1 mapping.

    Each eligible instruction has *split_prob* chance of being expanded.
    Split sequences use temporary registers above the method's register
    range to avoid corrupting live state.
    """
    result: list[VmpInsn] = []

    # LFSR state for generating varied immediates
    lfsr = rng.randint(1, 0xFFFFFFFF)

    def _tag_recent(count: int) -> None:
        for split_insn in result[-count:]:
            split_insn._split_group = orig_idx

    for insn in insns:
        op = insn.real_op
        orig_idx = getattr(insn, '_orig_idx', -1)
        if _op_is_special(op) or _op_is_branch(op):
            result.append(insn)
            continue

        if _insn_uses_2addr_operands(insn):
            result.append(insn)
            continue

        if rng.random() >= split_prob:
            result.append(insn)
            continue

        lfsr = _lfsr32(lfsr)
        tmp = _pick_temp_register(rng, registers_size)
        if tmp is None:
            result.append(insn)
            continue
        lfsr = _lfsr32(lfsr)
        noise = (lfsr & 0xFF) + 1  # 1..256 non-zero

        split_type = rng.randint(0, 5)

        if split_type == 0 and op in (int(VmpOp.ADD_INT), int(VmpOp.SUB_INT)):
            # x = a + b  →  tmp = a + b; x = tmp - noise; x = x + noise
            first = VmpInsn(real_op=op, dst=tmp, src1=insn.src1, src2=insn.src2, imm=insn.imm)
            first._orig_idx = orig_idx; first._target_vmp_idx = -1
            result.append(first)
            result.append(VmpInsn(real_op=int(VmpOp.SUB_INT), dst=insn.dst, src1=tmp, src2=0, imm=noise))
            result.append(VmpInsn(real_op=int(VmpOp.ADD_INT), dst=insn.dst, src1=insn.dst, src2=0, imm=noise))
            _tag_recent(3)

        elif split_type == 1 and op in (int(VmpOp.CONST),):
            # x = const  →  tmp = const ^ noise; x = tmp ^ noise
            scrambled = insn.imm ^ noise ^ 0x7377
            first = VmpInsn(real_op=int(VmpOp.CONST), dst=tmp, imm=scrambled)
            first._orig_idx = orig_idx; first._target_vmp_idx = -1
            result.append(first)
            result.append(VmpInsn(real_op=int(VmpOp.XOR_INT), dst=insn.dst, src1=tmp, src2=0, imm=noise ^ 0x7377))
            _tag_recent(2)

        elif split_type == 2 and op in (int(VmpOp.MOVE),):
            # x = y  →  tmp = y | y; x = tmp (identity via OR)
            first = VmpInsn(real_op=int(VmpOp.OR_INT), dst=tmp, src1=insn.src1, src2=insn.src1)
            first._orig_idx = orig_idx; first._target_vmp_idx = -1
            result.append(first)
            result.append(VmpInsn(real_op=int(VmpOp.MOVE), dst=insn.dst, src1=tmp))
            _tag_recent(2)

        elif split_type == 3 and op in (
            int(VmpOp.ADD_INT), int(VmpOp.SUB_INT), int(VmpOp.MUL_INT),
            int(VmpOp.AND_INT), int(VmpOp.OR_INT), int(VmpOp.XOR_INT),
            int(VmpOp.SHL_INT), int(VmpOp.SHR_INT), int(VmpOp.USHR_INT),
        ):
            # x = a op b  →  tmp = a op b; x = tmp ^ noise; x = x ^ noise
            first = VmpInsn(real_op=op, dst=tmp, src1=insn.src1, src2=insn.src2, imm=insn.imm)
            first._orig_idx = orig_idx; first._target_vmp_idx = -1
            result.append(first)
            result.append(VmpInsn(real_op=int(VmpOp.XOR_INT), dst=insn.dst, src1=tmp, src2=0, imm=noise))
            result.append(VmpInsn(real_op=int(VmpOp.XOR_INT), dst=insn.dst, src1=insn.dst, src2=0, imm=noise))
            _tag_recent(3)

        elif split_type == 4 and op in (int(VmpOp.NEG_INT), int(VmpOp.NOT_INT)):
            if op == int(VmpOp.NEG_INT):
                # x = -a  ->  tmp = 0; x = tmp - a
                first = VmpInsn(real_op=int(VmpOp.CONST), dst=tmp, imm=0)
                first._orig_idx = orig_idx; first._target_vmp_idx = -1
                result.append(first)
                src2, mode_imm = _encode_normal_src2(insn.src1)
                result.append(VmpInsn(real_op=int(VmpOp.SUB_INT), dst=insn.dst, src1=tmp, src2=src2, imm=mode_imm))
                _tag_recent(2)
            else:
                # x = ~a  ->  tmp = -1; x = a ^ tmp
                first = VmpInsn(real_op=int(VmpOp.CONST), dst=tmp, imm=-1)
                first._orig_idx = orig_idx; first._target_vmp_idx = -1
                result.append(first)
                result.append(VmpInsn(real_op=int(VmpOp.XOR_INT), dst=insn.dst, src1=insn.src1, src2=tmp))
                _tag_recent(2)

        elif split_type == 5 and op == int(VmpOp.MOVE):
            # x = y  →  tmp = y + 0; x = tmp
            first = VmpInsn(real_op=int(VmpOp.ADD_INT), dst=tmp, src1=insn.src1, src2=0, imm=VMP_BINOP_LIT_ZERO_SENTINEL)
            first._orig_idx = orig_idx; first._target_vmp_idx = -1
            result.append(first)
            result.append(VmpInsn(real_op=int(VmpOp.MOVE), dst=insn.dst, src1=tmp))
            _tag_recent(2)

        else:
            result.append(insn)

    return result


# ── Operand scrambling (LFSR-based) ─────────────────────────────────────

def scramble_operands(
    insns: list[VmpInsn], seed: int
) -> tuple[list[VmpInsn], int]:
    """XOR-scramble dst/src1/src2/imm with per-instruction LFSR output."""
    lfsr = seed | 1  # ensure non-zero
    for insn in insns:
        lfsr = _lfsr32(lfsr)
        mask = lfsr
        lfsr = _lfsr32(lfsr)
        insn.dst  ^= (mask & 0xFF)
        insn.src1 ^= ((mask >> 8) & 0xFF)
        insn.src2 ^= ((mask >> 16) & 0xFF)
        insn.imm   = _to_i32((insn.imm & 0xFFFFFFFF) ^ (mask & 0xFFFFFFFF))
    return insns, seed


# ── Enhanced VMP bytecode obfuscation ────────────────────────────────────

def obfuscate_vmp_bytecode(
    insns: list[VmpInsn],
    registers_size: int = 16,
    seed: int | None = None,
    junk_ratio: float = 0.10,
    inline_junk_ratio: float = 0.12,
) -> list[VmpInsn]:
    """Insert dead code blocks interleaved inside the method body (not just
    appended at the end).  Uses opaque predicates to create fake branches
    that never execute at runtime.

    Two strategies:
    1. Between basic blocks, insert GOTO-guarded junk blocks.
    2. Inline opaque predicates: CONST tmp=0xFFFFFFFF; IF_EQZ tmp, dead_label
       (always taken because tmp != 0).  The junk block remains in the
       bytecode but is skipped on the real path.
    """
    rng = random.Random(seed)

    if len(insns) < 4:
        return list(insns)

    # Step 1: find safe insertion points (after branch targets, before returns)
    result: list[VmpInsn] = []
    num_junk = max(1, int(len(insns) * junk_ratio)) if junk_ratio > 0 else 0
    num_inline = max(1, int(len(insns) * inline_junk_ratio)) if inline_junk_ratio > 0 else 0
    junk_remaining = num_junk
    inline_remaining = num_inline

    for i, insn in enumerate(insns):
        result.append(insn)

        # Insert inline opaque-predicate junk after every ~7th real instruction
        split_group = getattr(insn, "_split_group", None)
        next_same_split_group = (
            split_group is not None
            and i + 1 < len(insns)
            and getattr(insns[i + 1], "_split_group", None) == split_group
        )
        if (
            inline_remaining > 0
            and i % 7 == 3
            and not next_same_split_group
            and not _op_is_branch(insn.real_op)
            and not _op_is_special(insn.real_op)
        ):
            # Check next insn isn't INVOKE_ARGS or CONST_WIDE_HI32
            next_is_special = (i + 1 < len(insns) and _op_is_special(insns[i + 1].real_op))
            if not next_is_special:
                tmp = _pick_temp_register(rng, registers_size)
                if tmp is None:
                    continue
                inline_remaining -= 1
                # Opaque predicate: tmp is non-zero, so IF_NEZ skips the junk block.
                jtype = rng.randint(0, 3)
                junk: list[VmpInsn] = []
                if jtype == 0:
                    junk.append(VmpInsn(real_op=int(VmpOp.NOP), dst=rng.randint(0, 255), src1=rng.randint(0, 255)))
                elif jtype == 1:
                    junk.append(VmpInsn(real_op=int(VmpOp.CONST), dst=tmp, imm=rng.randint(-0x80000000, 0x7FFFFFFF)))
                elif jtype == 2:
                    junk.append(VmpInsn(real_op=int(VmpOp.OR_INT), dst=tmp, src1=tmp, src2=tmp))
                else:
                    junk.append(VmpInsn(real_op=int(VmpOp.ADD_INT), dst=tmp, src1=tmp, src2=0, imm=VMP_BINOP_LIT_ZERO_SENTINEL))
                result.append(VmpInsn(real_op=int(VmpOp.CONST), dst=tmp, imm=-1))
                result.append(VmpInsn(real_op=int(VmpOp.IF_NEZ), dst=tmp, imm=len(junk) + 1))
                result.extend(junk)

        # Insert GOTO-guarded junk block at basic-block boundaries
        if junk_remaining > 0 and _op_is_branch(insn.real_op) and i + 1 < len(insns):
            # Branch instruction — natural basic block boundary
            if rng.random() < 0.35:
                junk_remaining -= 1
                tmp = _pick_temp_register(rng, registers_size)
                if tmp is None:
                    tmp = rng.randint(0, 255)
                # Junk block (1-3 insns)
                junk_start = len(result)
                result.append(VmpInsn(real_op=int(VmpOp.GOTO), imm=0))  # placeholder, patched below
                for _ in range(rng.randint(1, 3)):
                    jtype = rng.randint(0, 4)
                    if jtype == 0:
                        result.append(VmpInsn(real_op=int(VmpOp.NOP), dst=rng.randint(0, 255), src1=rng.randint(0, 255), src2=rng.randint(0, 255)))
                    elif jtype == 1:
                        result.append(VmpInsn(real_op=int(VmpOp.MOVE), dst=tmp, src1=tmp))
                    elif jtype == 2:
                        result.append(VmpInsn(real_op=int(VmpOp.CONST), dst=tmp, imm=_to_i32(rng.getrandbits(32))))
                    elif jtype == 3:
                        result.append(VmpInsn(real_op=int(VmpOp.OR_INT), dst=tmp, src1=tmp, src2=tmp))
                    else:
                        result.append(VmpInsn(real_op=int(VmpOp.ADD_INT), dst=tmp, src1=tmp, src2=0, imm=VMP_BINOP_LIT_ZERO_SENTINEL))
                result.append(VmpInsn(real_op=int(VmpOp.GOTO), imm=1))  # skip past self to next real insn
                # Patch the skip-offset: GOTO must jump over all junk + the exit GOTO
                result[junk_start].imm = _to_i32(len(result) - junk_start)  # skip past junk block to next real insn

    # Append additional junk at the end as fallback (after return)
    for _ in range(junk_remaining):
        jtype = rng.randint(0, 4)
        tmp = _pick_temp_register(rng, registers_size)
        if tmp is None:
            tmp = rng.randint(0, 255)
        imm = rng.randint(-0x80000000, 0x7FFFFFFF)
        if jtype == 0:
            result.append(VmpInsn(real_op=int(VmpOp.NOP), dst=rng.randint(0, 255), src1=rng.randint(0, 255), src2=rng.randint(0, 255), imm=imm))
        elif jtype == 1:
            result.append(VmpInsn(real_op=int(VmpOp.MOVE), dst=tmp, src1=tmp))
        elif jtype == 2:
            result.append(VmpInsn(real_op=int(VmpOp.CONST), dst=tmp, imm=imm))
        elif jtype == 3:
            result.append(VmpInsn(real_op=int(VmpOp.OR_INT), dst=tmp, src1=tmp, src2=tmp))
        else:
            result.append(VmpInsn(real_op=int(VmpOp.ADD_INT), dst=tmp, src1=tmp, src2=0, imm=VMP_BINOP_LIT_ZERO_SENTINEL))

    return result


@dataclass
class VmpMethodEntry:
    method_id: int
    class_name_idx: int
    method_name_idx: int
    method_sig_idx: int
    registers_size: int
    ins_size: int
    outs_size: int
    tries_count: int
    op_obfs_seed: int = 0       # LFSR seed for operand de-scrambling
    bytecode: list[VmpInsn] = field(default_factory=list)
    try_blocks: list[VmpTryBlock] = field(default_factory=list)


# ── Blob serialiser ──────────────────────────────────────────────────────

def serialize_vmp_blob(
    methods: list[VmpMethodEntry],
    pool: RefPool,
    unshuffle: list[int],
    shuffle: list[int],
) -> bytes:
    """Serialize VMP data into the blob format the native interpreter reads."""
    parts: list[bytes] = []

    # Magic + version
    parts.append(VMP_BLOB_MAGIC)
    parts.append(struct.pack("<I", VMP_BLOB_VERSION))

    # Opcode table (unshuffle: shuffled → real_op; interpreter needs this)
    parts.append(bytes(unshuffle))

    # String pool
    strings = pool.strings
    string_salt = _derive_string_pool_salt(strings, unshuffle)
    parts.append(struct.pack("<I", string_salt))
    parts.append(struct.pack("<I", len(strings)))
    for i, s in enumerate(strings):
        encoded = s.encode("utf-8")
        encoded = _crypt_vmp_string(encoded, string_salt, i)
        parts.append(struct.pack("<H", len(encoded)))
        parts.append(encoded)

    # Bytecode section (concatenated, compute offsets)
    bytecode_blobs: list[bytes] = []
    for m in methods:
        bc = b""
        for insn in m.bytecode:
            bc += insn.pack_raw(shuffle)
        bytecode_blobs.append(bc)

    # Method table
    parts.append(struct.pack("<I", len(methods)))
    bc_offset = 0
    for i, m in enumerate(methods):
        bc_data = bytecode_blobs[i]
        parts.append(struct.pack(
            "<IIIIHHHHiii",
            m.method_id,
            m.class_name_idx,
            m.method_name_idx,
            m.method_sig_idx,
            m.registers_size,
            m.ins_size,
            m.outs_size,
            m.tries_count,
            m.op_obfs_seed,  # 32-bit seed for operand de-scrambling
            bc_offset,
            len(bc_data),
        ))
        bc_offset += len(bc_data)

    # Bytecode section
    parts.append(struct.pack("<I", bc_offset))  # total bytecode size
    for bc in bytecode_blobs:
        parts.append(bc)

    # Try-catch section (VMP-addressed try blocks)
    for m in methods:
        parts.append(struct.pack("<H", len(m.try_blocks)))
        for tb in m.try_blocks:
            parts.append(struct.pack("<HHH", tb.start_pc, tb.end_pc, len(tb.handlers)))
            for h in tb.handlers:
                parts.append(struct.pack("<ii", h.type_str_idx, h.handler_pc))
            parts.append(struct.pack("<i", tb.catch_all_pc))

    return b"".join(parts)


def _derive_string_pool_salt(strings: list[str], unshuffle: list[int]) -> int:
    h = hashlib.sha256()
    h.update(bytes(unshuffle))
    for s in strings:
        b = s.encode("utf-8")
        h.update(struct.pack("<I", len(b)))
        h.update(b)
    salt = struct.unpack("<I", h.digest()[:4])[0]
    return salt or 0xA7C35D19


def _crypt_vmp_string(data: bytes, salt: int, string_idx: int) -> bytes:
    seed = (salt ^ ((string_idx + 1) * 0x9E3779B1)) & 0xFFFFFFFF
    out = bytearray(data)
    for i in range(len(out)):
        seed = _lfsr32(seed or 0xD00DF00D)
        out[i] ^= (seed >> ((i & 3) * 8)) & 0xFF
        out[i] ^= ((string_idx * 131 + i * 17 + 0x5D) & 0xFF)
    return bytes(out)


# ── High-level compile API ───────────────────────────────────────────────

def compile_methods(
    dex: DexFile,
    target_methods: list[tuple[str, str, str | None]],
    seed: bytes | None = None,
    *,
    split_prob: float = 0.0,
    junk_ratio: float = 0.0,
    inline_junk_ratio: float = 0.0,
) -> tuple[bytes, list[int]]:
    """Compile target methods from a DEX file into a VMP blob.

    target_methods: list of (class_descriptor, method_name, signature_or_None).

    Semantics:
      - method_name == "*" extracts all methods defined on the class
      - signature == None matches all overloads with the given method name
      - otherwise matches one exact method

    Returns (vmp_blob_bytes, list_of_method_indices_that_were_compiled).
    """
    pool = RefPool()
    shuffle, unshuffle = generate_opcode_shuffle(seed)
    rng = random.Random(seed)
    d2v = generate_d2v_map(rng)
    entries: list[VmpMethodEntry] = []
    compiled_indices: list[int] = []
    compiled_set: set[int] = set()

    for class_desc, mname, msig in target_methods:
        candidates: list[EncodedMethod] = []

        if mname == "*":
            ems = _iter_class_methods(dex, class_desc)
            if not ems:
                print(f"[!] VMP: class not found or empty: {class_desc}")
                continue
            candidates = ems
        elif msig is None:
            ems = _iter_class_methods(dex, class_desc)
            if not ems:
                print(f"[!] VMP: method not found: {class_desc}->{mname}")
                continue
            candidates = [em for em in ems if dex.method_name(em.method_idx) == mname]
            if not candidates:
                print(f"[!] VMP: method not found: {class_desc}->{mname}")
                continue
        else:
            midx = dex.find_method(class_desc, mname, msig)
            if midx is None:
                print(f"[!] VMP: method not found: {class_desc}->{mname}{msig}")
                continue
            em = _find_encoded_method(dex, midx)
            if em is None:
                print(f"[!] VMP: no code for method: {class_desc}->{mname}{msig}")
                continue
            candidates = [em]

        for em in sorted(candidates, key=lambda x: x.method_idx):
            midx = em.method_idx
            if midx in compiled_set:
                continue

            if em.code is None:
                print(f"[!] VMP: no code for method: {class_desc}->{dex.method_name(midx)}")
                continue

            code = em.code
            if code.insns_size == 0:
                continue

            method_label = f"{class_desc}->{dex.method_name(midx)}{dex.method_signature(midx)}"
            try:
                vmp_insns, off_to_idx = decode_dalvik_method(dex, code, pool, d2v)
            except (ValueError, struct.error) as exc:
                print(f"[!] VMP: skip unsupported method {method_label}: {exc}")
                continue

            orig_insn_count = len(vmp_insns)

            # Pass 1: Split instructions (breaks 1:1 Dalvik→VMP mapping)
            vmp_insns = split_vmp_instructions(
                vmp_insns,
                registers_size=code.registers_size,
                rng=rng,
                split_prob=split_prob,
            )

            # Pass 2: Inline junk code (opaque predicates + interleaved blocks)
            vmp_insns = obfuscate_vmp_bytecode(
                vmp_insns,
                registers_size=code.registers_size,
                seed=int.from_bytes((seed or b"\x00" * 4)[:4], "little"),
                junk_ratio=junk_ratio,
                inline_junk_ratio=inline_junk_ratio,
            )

            # Fixup branch targets after all instruction insertions
            old_to_new = _fixup_branch_targets(vmp_insns)

            # Pass 3: Operand scrambling (LFSR-based)
            obfs_seed = rng.randint(1, 0x7FFFFFFF)
            vmp_insns, _ = scramble_operands(vmp_insns, obfs_seed)

            try_blocks = _translate_try_catch(dex, code, off_to_idx, len(vmp_insns), pool)
            _fixup_try_blocks(try_blocks, old_to_new, len(vmp_insns))

            entry = VmpMethodEntry(
                method_id=len(entries),
                class_name_idx=pool.intern(class_desc),
                method_name_idx=pool.intern(dex.method_name(midx)),
                method_sig_idx=pool.intern(dex.method_signature(midx)),
                registers_size=code.registers_size,
                ins_size=code.ins_size,
                outs_size=code.outs_size,
                tries_count=len(try_blocks),
                op_obfs_seed=obfs_seed,
                bytecode=vmp_insns,
                try_blocks=try_blocks,
            )
            entries.append(entry)
            compiled_indices.append(midx)
            compiled_set.add(midx)

    blob = serialize_vmp_blob(entries, pool, unshuffle, shuffle)
    return blob, compiled_indices


def compile_methods_multi_dex(
    dex_files: list[DexFile],
    target_methods: list[tuple[str, str, str | None]],
    seed: bytes | None = None,
    *,
    split_prob: float = 0.0,
    junk_ratio: float = 0.0,
    inline_junk_ratio: float = 0.0,
) -> tuple[bytes, dict[int, list[int]], list[dict[str, Any]]]:
    """Compile targets across all DEX files into a single VMP blob.

    Returns ``(blob_bytes, {dex_idx: [method_idx, ...]}, method_info_list)``
    where *method_info_list* contains per-method metadata for stub generation.
    """
    pool = RefPool()
    shuffle, unshuffle = generate_opcode_shuffle(seed)
    rng = random.Random(seed)
    d2v = generate_d2v_map(rng)
    entries: list[VmpMethodEntry] = []
    compiled_per_dex: dict[int, list[int]] = {}   # dex_idx → [method_idx]
    compiled_set: set[tuple[int, int]] = set()     # (dex_idx, method_idx)
    method_info: list[dict[str, Any]] = []          # for stub generation

    for class_desc, mname, msig in target_methods:
        matched = False
        for dex_idx, dex in enumerate(dex_files):
            candidates: list[EncodedMethod] = []

            if mname == "*":
                ems = _iter_class_methods(dex, class_desc)
                if not ems:
                    continue
                candidates = ems
                matched = True
            elif msig is None:
                ems = _iter_class_methods(dex, class_desc)
                if not ems:
                    continue
                candidates = [em for em in ems if dex.method_name(em.method_idx) == mname]
                if not candidates:
                    continue
                matched = True
            else:
                midx = dex.find_method(class_desc, mname, msig)
                if midx is None:
                    continue
                matched = True
                em = _find_encoded_method(dex, midx)
                if em is None:
                    continue
                candidates = [em]

            for em in sorted(candidates, key=lambda x: x.method_idx):
                midx = em.method_idx
                if (dex_idx, midx) in compiled_set:
                    continue
                if em.code is None or em.code.insns_size == 0:
                    continue

                code = em.code
                method_label = f"{class_desc}->{dex.method_name(midx)}{dex.method_signature(midx)}"
                try:
                    vmp_insns, off_to_idx = decode_dalvik_method(dex, code, pool, d2v)
                except (ValueError, struct.error) as exc:
                    print(f"[!] VMP: skip unsupported method {method_label}: {exc}")
                    continue
                is_static = bool(em.access_flags & 0x0008)
                sig = dex.method_signature(midx)

                # Pass 1: Split instructions
                vmp_insns = split_vmp_instructions(
                    vmp_insns,
                    registers_size=code.registers_size,
                    rng=rng,
                    split_prob=split_prob,
                )
                # Pass 2: Inline junk code
                vmp_insns = obfuscate_vmp_bytecode(
                    vmp_insns,
                    registers_size=code.registers_size,
                    seed=int.from_bytes((seed or b"\x00" * 4)[:4], "little"),
                    junk_ratio=junk_ratio,
                    inline_junk_ratio=inline_junk_ratio,
                )

                # Fixup branch targets after all instruction insertions
                old_to_new = _fixup_branch_targets(vmp_insns)

                # Pass 3: Operand scrambling
                obfs_seed = rng.randint(1, 0x7FFFFFFF)
                vmp_insns, _ = scramble_operands(vmp_insns, obfs_seed)

                try_blocks = _translate_try_catch(dex, code, off_to_idx, len(vmp_insns), pool)
                _fixup_try_blocks(try_blocks, old_to_new, len(vmp_insns))

                # The production computed-goto interpreter does not perform
                # in-method try/catch handler dispatch (that logic lives only in
                # the portable switch fallback). A VMP-protected method that
                # relies on its own try/catch to keep business semantics will
                # therefore let exceptions escape instead of catching them.
                # auto_protect_map downgrades such methods away from VMP, but a
                # hand-written protection map can still target them, so flag it
                # for the caller to warn or fail-close on.
                has_try_blocks = len(try_blocks) > 0
                if has_try_blocks:
                    print(
                        "[!] VMP: method has try/catch blocks not honored by the "
                        f"fast-path interpreter: {method_label}"
                    )

                entry = VmpMethodEntry(
                    method_id=len(entries),
                    class_name_idx=pool.intern(class_desc),
                    method_name_idx=pool.intern(dex.method_name(midx)),
                    method_sig_idx=pool.intern(sig),
                    registers_size=code.registers_size,
                    ins_size=code.ins_size,
                    outs_size=code.outs_size,
                    tries_count=len(try_blocks),
                    op_obfs_seed=obfs_seed,
                    bytecode=vmp_insns,
                    try_blocks=try_blocks,
                )
                entries.append(entry)
                compiled_per_dex.setdefault(dex_idx, []).append(midx)
                compiled_set.add((dex_idx, midx))
                method_info.append({
                    "method_id": entry.method_id,
                    "class_desc": class_desc,
                    "method_name": dex.method_name(midx),
                    "signature": sig,
                    "is_static": is_static,
                    "has_try_catch": has_try_blocks,
                })

            break  # first dex that has it

        if not matched:
            print(f"[!] VMP multi-dex: method not found: {class_desc}->{mname}" + (msig or ""))

    blob = serialize_vmp_blob(entries, pool, unshuffle, shuffle)
    return blob, compiled_per_dex, method_info


def _iter_class_methods(dex: DexFile, class_desc: str) -> list[EncodedMethod]:
    """Return all methods defined on a class (direct + virtual)."""
    return dex.iter_class_methods(class_desc)


def _find_encoded_method(dex: DexFile, method_idx: int) -> EncodedMethod | None:
    return dex.find_encoded_method(method_idx)
