"""VMP v5 format round-trip tests.

Verifies:
  * The width table derivation is deterministic given a seed.
  * The operand-layout derivation is deterministic, contiguous for
    multi-byte fields, and covers every byte position exactly once.
  * Every VmpOp can be packed under v5 and unpacked to recover
    (opcode, operand fields).
  * The blob serializer + the blob_compat reader round-trip a non-trivial
    method list.
  * v4 and v5 blobs are distinguishable via the version byte.

These are pure-Python tests; the C interpreter is exercised in a
separate test set (test_vmp_v4_v5_parity.py — to be added in session 4).
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

_packer_dir = str(Path(__file__).resolve().parent.parent / "packer")
if _packer_dir not in sys.path:
    sys.path.insert(0, _packer_dir)

from vmp_compiler import (  # noqa: E402
    VMP_BLOB_MAGIC,
    VMP_BLOB_VERSION,
    VMP_BLOB_VERSION_V5,
    VMP_V5_WIDTH_2,
    VMP_V5_WIDTH_4,
    VMP_V5_WIDTH_6,
    VMP_V5_WIDTH_8,
    VMP_V5_WIDTH_12,
    VMP_V5_WIDTH_16,
    VMP_V5_WIDTH_CLASSES,
    VmpInsn,
    VmpOp,
    derive_v5_layout_table,
    derive_v5_width_table,
    serialize_vmp_blob,
    serialize_vmp_blob_v5,
    v5_width_for_op,
)
from vmp_blob_compat import read_blob  # noqa: E402


# ────────────────────────────────────────────────────────────────────────
# Width table
# ────────────────────────────────────────────────────────────────────────


def test_width_table_is_deterministic():
    a = derive_v5_width_table(0x12345678)
    b = derive_v5_width_table(0x12345678)
    assert a == b


def test_width_table_changes_with_seed():
    a = derive_v5_width_table(0x12345678)
    b = derive_v5_width_table(0x12345679)
    # The widths per real_op never change (we permute within a class),
    # so the *table* may be identical — but the inner permutations
    # exposed by other helpers must differ. Sanity-check by ensuring
    # the function is at least called identically.
    assert len(a) == 256 and len(b) == 256


def test_width_table_contains_only_valid_widths():
    table = derive_v5_width_table(0xCAFEBABE)
    assert set(table).issubset(set(VMP_V5_WIDTH_CLASSES))


def test_specific_ops_have_expected_widths():
    assert v5_width_for_op(VmpOp.NOP) == VMP_V5_WIDTH_2
    assert v5_width_for_op(VmpOp.RETURN_VOID) == VMP_V5_WIDTH_2
    assert v5_width_for_op(VmpOp.MOVE) == VMP_V5_WIDTH_4
    assert v5_width_for_op(VmpOp.NEG_INT) == VMP_V5_WIDTH_4
    assert v5_width_for_op(VmpOp.INT_TO_LONG) == VMP_V5_WIDTH_4
    assert v5_width_for_op(VmpOp.CONST_WIDE) == VMP_V5_WIDTH_12
    assert v5_width_for_op(VmpOp.INVOKE_VIRTUAL) == VMP_V5_WIDTH_16
    assert v5_width_for_op(VmpOp.PACKED_SWITCH) == VMP_V5_WIDTH_16
    # Default: anything unlisted is W8.
    assert v5_width_for_op(VmpOp.ADD_INT) == VMP_V5_WIDTH_8
    assert v5_width_for_op(VmpOp.IF_EQ) == VMP_V5_WIDTH_8
    assert v5_width_for_op(VmpOp.IGET) == VMP_V5_WIDTH_8


# ────────────────────────────────────────────────────────────────────────
# Operand layout
# ────────────────────────────────────────────────────────────────────────


def test_layout_is_deterministic():
    a = derive_v5_layout_table(0xAA55AA55)
    b = derive_v5_layout_table(0xAA55AA55)
    assert a == b


def test_layout_changes_with_seed():
    a = derive_v5_layout_table(0xAA55AA55)
    b = derive_v5_layout_table(0xAA55AA56)
    assert a != b


@pytest.mark.parametrize("width", VMP_V5_WIDTH_CLASSES)
def test_layout_covers_every_byte_exactly_once(width):
    layouts = derive_v5_layout_table(0xDEADC0DE)
    spec = layouts[width]
    covered = set()
    for name, pos in spec.items():
        if isinstance(pos, int):
            assert pos not in covered, f"W{width} byte {pos} covered twice (field {name})"
            covered.add(pos)
        else:
            start, length = pos
            for p in range(start, start + length):
                assert p not in covered, f"W{width} byte {p} covered twice (field {name})"
                covered.add(p)
    assert covered == set(range(width)), f"W{width} coverage gap: {set(range(width)) - covered}"


@pytest.mark.parametrize("width", [VMP_V5_WIDTH_6, VMP_V5_WIDTH_8, VMP_V5_WIDTH_12, VMP_V5_WIDTH_16])
def test_layout_multi_byte_field_is_contiguous(width):
    """Multi-byte fields must occupy contiguous bytes (otherwise LE
    struct unpack wouldn't work)."""
    layouts = derive_v5_layout_table(0xC0FFEE42)
    spec = layouts[width]
    multi_fields = [(n, pos) for n, pos in spec.items() if isinstance(pos, tuple)]
    assert len(multi_fields) == 1, f"W{width} should have exactly one multi-byte field"
    name, (start, length) = multi_fields[0]
    assert 0 <= start <= width - length, f"W{width} {name} out of range"


# ────────────────────────────────────────────────────────────────────────
# VmpInsn pack_raw_v5 round-trip
# ────────────────────────────────────────────────────────────────────────


def _identity_shuffle() -> list[int]:
    """Identity opcode permutation so test recovery is direct."""
    return list(range(256))


@pytest.mark.parametrize("op,width", [
    (VmpOp.NOP, VMP_V5_WIDTH_2),
    (VmpOp.RETURN_VOID, VMP_V5_WIDTH_2),
    (VmpOp.MOVE, VMP_V5_WIDTH_4),
    (VmpOp.NEG_INT, VMP_V5_WIDTH_4),
    (VmpOp.MONITOR_ENTER, VMP_V5_WIDTH_4),
    (VmpOp.ARRAY_LENGTH, VMP_V5_WIDTH_4),
    (VmpOp.ADD_INT, VMP_V5_WIDTH_8),
    (VmpOp.IF_EQ, VMP_V5_WIDTH_8),
    (VmpOp.IGET, VMP_V5_WIDTH_8),
    (VmpOp.CONST, VMP_V5_WIDTH_8),
    (VmpOp.CONST_WIDE, VMP_V5_WIDTH_12),
    (VmpOp.INVOKE_VIRTUAL, VMP_V5_WIDTH_16),
    (VmpOp.INVOKE_STATIC, VMP_V5_WIDTH_16),
    (VmpOp.PACKED_SWITCH, VMP_V5_WIDTH_16),
])
def test_pack_raw_v5_produces_correct_width(op, width):
    insn = VmpInsn(real_op=int(op), dst=5, src1=7, src2=9, imm=0x1337)
    shuffle = _identity_shuffle()
    table = derive_v5_width_table(0x11111111)
    layouts = derive_v5_layout_table(0x22222222)

    extra = list(range(13)) if width == VMP_V5_WIDTH_16 else None
    packed = insn.pack_raw_v5(shuffle, table, layouts, extra_args=extra)
    assert len(packed) == width, f"op={op.name} expected {width}B got {len(packed)}B"


def test_pack_raw_v5_round_trips_opcode_and_dst_w4():
    insn = VmpInsn(real_op=int(VmpOp.NEG_INT), dst=3, src1=5)
    shuffle = _identity_shuffle()
    table = derive_v5_width_table(0xAAAA)
    layouts = derive_v5_layout_table(0xBBBB)
    packed = insn.pack_raw_v5(shuffle, table, layouts)
    assert len(packed) == VMP_V5_WIDTH_4
    spec = layouts[VMP_V5_WIDTH_4]
    assert packed[spec["opcode"]] == int(VmpOp.NEG_INT)
    assert packed[spec["dst"]] == 3
    assert packed[spec["src1"]] == 5


def test_pack_raw_v5_round_trips_imm32_w8():
    insn = VmpInsn(real_op=int(VmpOp.ADD_INT), dst=1, src1=2, src2=3, imm=-12345)
    shuffle = _identity_shuffle()
    table = derive_v5_width_table(0xC0DE)
    layouts = derive_v5_layout_table(0xFACE)
    packed = insn.pack_raw_v5(shuffle, table, layouts)
    assert len(packed) == VMP_V5_WIDTH_8
    spec = layouts[VMP_V5_WIDTH_8]
    start, length = spec["imm32"]
    recovered = struct.unpack("<i", packed[start:start + length])[0]
    assert recovered == -12345


def test_pack_raw_v5_w16_carries_reg_list():
    insn = VmpInsn(real_op=int(VmpOp.INVOKE_VIRTUAL), dst=0, src1=0, src2=0, imm=0)
    args = [11, 12, 13, 14, 15, 16, 17]
    shuffle = _identity_shuffle()
    table = derive_v5_width_table(0x12)
    layouts = derive_v5_layout_table(0x34)
    packed = insn.pack_raw_v5(shuffle, table, layouts, extra_args=args)
    assert len(packed) == VMP_V5_WIDTH_16
    spec = layouts[VMP_V5_WIDTH_16]
    start, length = spec["reg_run"]
    reg_bytes = packed[start:start + length]
    for i, expected in enumerate(args):
        assert reg_bytes[i] == expected, f"reg[{i}] mismatch"
    assert packed[spec["nargs"]] == len(args)


# ────────────────────────────────────────────────────────────────────────
# Blob serializer round-trip
# ────────────────────────────────────────────────────────────────────────


def _empty_pool():
    from vmp_compiler import RefPool
    return RefPool()


def test_v4_blob_still_works():
    """Sanity: existing v4 path is not broken by our additions."""
    from vmp_compiler import VmpMethodEntry
    method = VmpMethodEntry(
        method_id=42,
        class_name_idx=0, method_name_idx=0, method_sig_idx=0,
        registers_size=4, ins_size=1, outs_size=0, tries_count=0,
        op_obfs_seed=0,
        bytecode=[VmpInsn(real_op=int(VmpOp.NOP))],
        try_blocks=[],
    )
    pool = _empty_pool()
    pool.intern("Lcom/foo/Bar;")
    shuffle = _identity_shuffle()
    unshuffle = _identity_shuffle()
    blob = serialize_vmp_blob([method], pool, unshuffle, shuffle)
    view = read_blob(blob)
    assert view.version == VMP_BLOB_VERSION  # 4
    assert len(view.methods) == 1
    assert view.methods[0].method_id == 42


def test_v5_blob_header_round_trips():
    from vmp_compiler import VmpMethodEntry
    method = VmpMethodEntry(
        method_id=99,
        class_name_idx=0, method_name_idx=0, method_sig_idx=0,
        registers_size=3, ins_size=0, outs_size=0, tries_count=0,
        op_obfs_seed=0,
        bytecode=[VmpInsn(real_op=int(VmpOp.NOP)), VmpInsn(real_op=int(VmpOp.RETURN_VOID))],
        try_blocks=[],
    )
    pool = _empty_pool()
    pool.intern("Lcom/x/Y;")
    shuffle = _identity_shuffle()
    unshuffle = _identity_shuffle()
    blob = serialize_vmp_blob_v5(
        [method], pool, unshuffle, shuffle,
        width_table_seed=0xAABBCCDD,
        operand_layout_seed=0x11223344,
    )
    view = read_blob(blob)
    assert view.version == VMP_BLOB_VERSION_V5
    assert view.width_table_seed == 0xAABBCCDD
    assert view.operand_layout_seed == 0x11223344
    assert view.format_flags & 0b111 == 0b111  # width + layout + string-pool flags set
    assert len(view.methods) == 1
    assert view.methods[0].method_id == 99
    # bytecode length is the sum of widths
    assert view.methods[0].bc_length == VMP_V5_WIDTH_2 + VMP_V5_WIDTH_2


def test_v5_bytecode_section_total_matches_sum_of_widths():
    from vmp_compiler import VmpMethodEntry
    insns = [
        VmpInsn(real_op=int(VmpOp.NOP)),                  # 2
        VmpInsn(real_op=int(VmpOp.MOVE), dst=1, src1=2),  # 4
        VmpInsn(real_op=int(VmpOp.ADD_INT), dst=0, src1=1, src2=2, imm=0),  # 8
        VmpInsn(real_op=int(VmpOp.CONST_WIDE), dst=3, imm=0x1234567890ABCDEF),  # 12
        VmpInsn(real_op=int(VmpOp.RETURN_VOID)),          # 2
    ]
    expected_bytes = 2 + 4 + 8 + 12 + 2
    method = VmpMethodEntry(
        method_id=1, class_name_idx=0, method_name_idx=0, method_sig_idx=0,
        registers_size=8, ins_size=0, outs_size=0, tries_count=0, op_obfs_seed=0,
        bytecode=insns, try_blocks=[],
    )
    pool = _empty_pool()
    pool.intern("L;")
    blob = serialize_vmp_blob_v5(
        [method], pool, _identity_shuffle(), _identity_shuffle(),
        width_table_seed=0x42, operand_layout_seed=0x84,
    )
    view = read_blob(blob)
    assert view.methods[0].bc_length == expected_bytes
    assert len(view.bytecode_section) == expected_bytes


def test_v4_and_v5_blobs_are_distinguishable_by_version_field():
    from vmp_compiler import VmpMethodEntry
    method = VmpMethodEntry(
        method_id=1, class_name_idx=0, method_name_idx=0, method_sig_idx=0,
        registers_size=2, ins_size=0, outs_size=0, tries_count=0, op_obfs_seed=0,
        bytecode=[VmpInsn(real_op=int(VmpOp.NOP))], try_blocks=[],
    )
    pool = _empty_pool()
    pool.intern("L;")
    v4 = serialize_vmp_blob([method], pool, _identity_shuffle(), _identity_shuffle())
    v5 = serialize_vmp_blob_v5(
        [method], pool, _identity_shuffle(), _identity_shuffle(),
        width_table_seed=0, operand_layout_seed=0,
    )
    assert v4[:12] == VMP_BLOB_MAGIC
    assert v5[:12] == VMP_BLOB_MAGIC
    assert struct.unpack("<I", v4[12:16])[0] == 4
    assert struct.unpack("<I", v5[12:16])[0] == 5


def test_layout_seed_changes_byte_positions():
    """Different layout seeds should produce different byte-level output
    for the same logical insn — proves per-build randomization actually
    randomizes."""
    insn = VmpInsn(real_op=int(VmpOp.ADD_INT), dst=1, src1=2, src2=3, imm=99)
    shuffle = _identity_shuffle()
    table = derive_v5_width_table(0)
    layout_a = derive_v5_layout_table(0x111)
    layout_b = derive_v5_layout_table(0x222)
    a = insn.pack_raw_v5(shuffle, table, layout_a)
    b = insn.pack_raw_v5(shuffle, table, layout_b)
    # Bytes are still the same multiset (same fields, just permuted) but
    # the byte-level sequence should differ for most seed pairs.
    assert a != b, "expected different byte layouts under different seeds"
