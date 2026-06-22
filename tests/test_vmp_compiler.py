"""Tests for VMP compiler: opcodes, format table, serialization."""

import random

import pytest

import sys
from pathlib import Path

_packer = Path(__file__).resolve().parent.parent / "packer"
if str(_packer) not in sys.path:
    sys.path.insert(0, str(_packer))

from vmp_compiler import (
    RefPool,
    VmpInsn,
    VmpOp,
    VMP_BINOP_LIT_ZERO_SENTINEL,
    VMP_BINOP_REG0_SENTINEL,
    VMP_BLOB_MAGIC,
    VMP_BLOB_VERSION,
    _FMT,
    decode_dalvik_method,
    generate_d2v_map,
    obfuscate_vmp_bytecode,
    serialize_vmp_blob,
    split_vmp_instructions,
    _translate_try_catch,
)
from dex_parser import CatchHandler, CodeItem, DexFile, EncodedCatchHandler, TryItem

OP_COUNT = VmpOp.OP_COUNT
ADD_INT_SAFE_OPS = {int(VmpOp.ADD_INT), *range(150, 160), *range(165, 173)}
SUB_INT_SAFE_OPS = {int(VmpOp.SUB_INT), 160, 161, 162}
AND_INT_SAFE_OPS = {int(VmpOp.AND_INT), 163, 164}
OR_INT_SAFE_OPS = {int(VmpOp.OR_INT), 173, 174}
XOR_INT_SAFE_OPS = {int(VmpOp.XOR_INT), 175, 176}


def _code_item(*units: int, registers_size: int = 4) -> CodeItem:
    raw = b"".join(int(u & 0xFFFF).to_bytes(2, "little") for u in units)
    return CodeItem(registers_size=registers_size, insns_size=len(units), insns=raw)


class TestVmpOp:
    def test_op_count_is_200(self):
        assert OP_COUNT == 200

    def test_op_count_matches_actual(self):
        # The highest op value (excluding OP_COUNT) should be OP_COUNT - 1
        real_ops = [int(op) for op in VmpOp if op.name != "OP_COUNT"]
        max_op = max(real_ops)
        assert max_op == 199

    def test_all_op_values_covered(self):
        values = {int(op) for op in VmpOp if op.name != "OP_COUNT"}
        # Values should be 0 through 199, no gaps
        assert values == set(range(200))

    def test_op_names_are_valid_identifiers(self):
        for op in VmpOp:
            assert op.name.isidentifier(), f"{op.name} is not a valid identifier"

    def test_no_duplicate_op_values(self):
        values = [int(op) for op in VmpOp]
        assert len(values) == len(set(values)), "duplicate VmpOp values"

    def test_nop_is_zero(self):
        assert VmpOp.NOP == 0

    def test_move_is_one(self):
        assert VmpOp.MOVE == 1

    def test_invoke_custom_exists(self):
        assert VmpOp.INVOKE_CUSTOM == 148

    def test_invoke_polymorphic_exists(self):
        assert VmpOp.INVOKE_POLYMORPHIC == 149

    def test_invoke_family_coverage(self):
        invoke_ops = {
            VmpOp.INVOKE_VIRTUAL,
            VmpOp.INVOKE_SUPER,
            VmpOp.INVOKE_DIRECT,
            VmpOp.INVOKE_STATIC,
            VmpOp.INVOKE_INTERFACE,
            VmpOp.INVOKE_CUSTOM,
            VmpOp.INVOKE_POLYMORPHIC,
        }
        assert len(invoke_ops) == 7

    def test_arithmetic_family(self):
        arithmetic = {
            VmpOp.ADD_INT, VmpOp.SUB_INT, VmpOp.MUL_INT, VmpOp.DIV_INT, VmpOp.REM_INT,
            VmpOp.ADD_LONG, VmpOp.SUB_LONG, VmpOp.MUL_LONG, VmpOp.DIV_LONG, VmpOp.REM_LONG,
            VmpOp.ADD_FLOAT, VmpOp.SUB_FLOAT, VmpOp.MUL_FLOAT, VmpOp.DIV_FLOAT, VmpOp.REM_FLOAT,
            VmpOp.ADD_DOUBLE, VmpOp.SUB_DOUBLE, VmpOp.MUL_DOUBLE, VmpOp.DIV_DOUBLE, VmpOp.REM_DOUBLE,
        }
        assert len(arithmetic) == 20

    def test_low_risk_int_ops_use_safe_semantic_alias_pools(self):
        maps = [generate_d2v_map(random.Random(seed)) for seed in range(40)]
        binop_alias_values = set(range(150, 160))
        lit_alias_values = set(range(165, 173))

        assert any(int(d2v[0x90]) in binop_alias_values for d2v in maps)
        assert any(int(d2v[0xB0]) in binop_alias_values for d2v in maps)
        assert any(int(d2v[0xD0]) in lit_alias_values for d2v in maps)
        assert any(int(d2v[0xD8]) in lit_alias_values for d2v in maps)
        assert any(int(d2v[0x91]) in SUB_INT_SAFE_OPS - {int(VmpOp.SUB_INT)} for d2v in maps)
        assert any(int(d2v[0x95]) in AND_INT_SAFE_OPS - {int(VmpOp.AND_INT)} for d2v in maps)
        assert any(int(d2v[0x96]) in OR_INT_SAFE_OPS - {int(VmpOp.OR_INT)} for d2v in maps)
        assert any(int(d2v[0x97]) in XOR_INT_SAFE_OPS - {int(VmpOp.XOR_INT)} for d2v in maps)
        assert any(int(d2v[0xD9]) in SUB_INT_SAFE_OPS - {int(VmpOp.SUB_INT)} for d2v in maps)
        assert any(int(d2v[0xDD]) in AND_INT_SAFE_OPS - {int(VmpOp.AND_INT)} for d2v in maps)
        assert any(int(d2v[0xDE]) in OR_INT_SAFE_OPS - {int(VmpOp.OR_INT)} for d2v in maps)
        assert any(int(d2v[0xDF]) in XOR_INT_SAFE_OPS - {int(VmpOp.XOR_INT)} for d2v in maps)

        for d2v in maps:
            assert int(d2v[0x91]) in SUB_INT_SAFE_OPS
            assert int(d2v[0xD1]) in SUB_INT_SAFE_OPS
            assert int(d2v[0x95]) in AND_INT_SAFE_OPS
            assert int(d2v[0xD5]) in AND_INT_SAFE_OPS
            assert int(d2v[0x96]) in OR_INT_SAFE_OPS
            assert int(d2v[0xD6]) in OR_INT_SAFE_OPS
            assert int(d2v[0x97]) in XOR_INT_SAFE_OPS
            assert int(d2v[0xD7]) in XOR_INT_SAFE_OPS
            assert d2v[0x92] == VmpOp.MUL_INT
            assert d2v[0x93] == VmpOp.DIV_INT
            assert d2v[0x94] == VmpOp.REM_INT


class TestDalvikFormatTable:
    def test_format_table_exists_with_entries(self):
        assert len(_FMT) > 0, "Dalvik format table is empty"

    def test_nop_format(self):
        fmt, width = _FMT[0x00]
        assert fmt == "10x"
        assert width == 1

    def test_move_format(self):
        fmt, width = _FMT[0x01]
        assert fmt == "12x"
        assert width == 1

    def test_const_4_format(self):
        fmt, width = _FMT[0x12]
        assert fmt == "11n"
        assert width == 1

    def test_const_16_format(self):
        fmt, width = _FMT[0x13]
        assert fmt == "21s"
        assert width == 2

    def test_const_format(self):
        fmt, width = _FMT[0x14]
        assert fmt == "31i"
        assert width == 3

    def test_invoke_virtual_format(self):
        fmt, width = _FMT[0x6E]
        assert fmt == "35c"
        assert width == 3

    def test_invoke_static_format(self):
        fmt, width = _FMT[0x71]
        assert fmt == "35c"
        assert width == 3

    def test_invoke_interface_format(self):
        fmt, width = _FMT[0x72]
        assert fmt == "35c"
        assert width == 3

    def test_return_void_format(self):
        fmt, width = _FMT[0x0E]
        assert fmt == "10x"
        assert width == 1

    def test_all_format_widths_positive(self):
        for opcode, (fmt, width) in _FMT.items():
            assert width >= 1, f"opcode 0x{opcode:02X} has invalid width {width}"
            assert isinstance(fmt, str) and len(fmt) in (3, 4), f"opcode 0x{opcode:02X} bad format {fmt!r}"


class TestDalvikDecodeOperandModes:
    def _decode_units(self, *units: int):
        code = _code_item(*units)
        insns, _ = decode_dalvik_method(DexFile(), code, RefPool())
        return insns

    def test_normal_23x_source_register_zero_is_not_2addr(self):
        # add-int v1, v2, v0
        insns = self._decode_units(0x0190, 0x0002)

        assert int(insns[0].real_op) in ADD_INT_SAFE_OPS
        assert insns[0].dst == 1
        assert insns[0].src1 == 2
        assert insns[0].src2 == 0
        assert insns[0].imm == VMP_BINOP_REG0_SENTINEL

    def test_literal_zero_is_not_2addr(self):
        # add-int/lit8 v1, v2, #0
        insns = self._decode_units(0x01D8, 0x0002)

        assert int(insns[0].real_op) in ADD_INT_SAFE_OPS
        assert insns[0].dst == 1
        assert insns[0].src1 == 2
        assert insns[0].src2 == 0
        assert insns[0].imm == VMP_BINOP_LIT_ZERO_SENTINEL

    def test_2addr_keeps_legacy_zero_mode(self):
        # add-int/2addr v1, v2
        insns = self._decode_units(0x21B0)

        assert int(insns[0].real_op) in ADD_INT_SAFE_OPS
        assert insns[0].dst == 1
        assert insns[0].src1 == 2
        assert insns[0].src2 == 0
        assert insns[0].imm == 0


class TestVmpHighRiskSemantics:
    def test_monitor_enter_exit_keep_object_register(self):
        # monitor-enter v1; monitor-exit v1; return-void
        code = _code_item(0x011D, 0x011E, 0x000E)

        insns, _ = decode_dalvik_method(DexFile(), code, RefPool())

        assert [insn.real_op for insn in insns] == [
            VmpOp.MONITOR_ENTER,
            VmpOp.MONITOR_EXIT,
            VmpOp.RETURN_VOID,
        ]
        assert insns[0].dst == 1
        assert insns[1].dst == 1

    def test_packed_switch_payload_is_interned_with_vmp_relative_targets(self):
        # const/4 v0,#1; packed-switch v0,+4; return v0; payload(size=2, first_key=1)
        code = _code_item(
            0x1012,
            0x002B, 0x0004, 0x0000,
            0x000F,
            0x0100, 0x0002,
            0x0001, 0x0000,
            0x0003, 0x0000,
            0x0003, 0x0000,
        )
        pool = RefPool()

        insns, _ = decode_dalvik_method(DexFile(), code, pool)

        switch = next(insn for insn in insns if insn.real_op == VmpOp.PACKED_SWITCH)
        assert switch.dst == 0
        assert pool.strings[switch.imm] == "PS|1|1,1"

    def test_sparse_switch_payload_is_interned_with_keys_and_vmp_relative_targets(self):
        # sparse-switch v2,+4; return-void; payload keys 10/42 both target return-void.
        code = _code_item(
            0x022C, 0x0004, 0x0000,
            0x000E,
            0x0200, 0x0002,
            0x000A, 0x0000,
            0x002A, 0x0000,
            0x0003, 0x0000,
            0x0003, 0x0000,
        )
        pool = RefPool()

        insns, _ = decode_dalvik_method(DexFile(), code, pool)

        switch = next(insn for insn in insns if insn.real_op == VmpOp.SPARSE_SWITCH)
        assert switch.dst == 2
        assert pool.strings[switch.imm] == "SS|10:1,42:1"

    def test_fill_array_payload_is_skipped_and_interned_as_payload_spec(self):
        # fill-array-data v0,+4; return-void; payload byte[3] = {1,2,3}
        code = _code_item(
            0x0026, 0x0004, 0x0000,
            0x000E,
            0x0300, 0x0001,
            0x0003, 0x0000,
            0x0201, 0x0003,
        )
        pool = RefPool()

        insns, _ = decode_dalvik_method(DexFile(), code, pool)

        assert [insn.real_op for insn in insns] == [
            VmpOp.FILL_ARRAY_DATA,
            VmpOp.RETURN_VOID,
        ]
        assert pool.strings[insns[0].imm] == "FA|1|3|010203"

    def test_try_catch_translation_uses_vmp_addresses_and_exception_type_pool(self):
        # const/4 v0,#0; throw v0; move-exception v1; return v1
        code = _code_item(0x0012, 0x0027, 0x010D, 0x010F)
        code.tries_size = 1
        code.tries = [TryItem(start_addr=0, insn_count=2, handler_off=0)]
        code.catch_handlers = [
            EncodedCatchHandler(
                handlers=[CatchHandler(type_idx=0, addr=2)],
                catch_all_addr=3,
                _list_offset=0,
            )
        ]
        dex = DexFile(strings=["Ljava/lang/IllegalStateException;"], type_ids=[0])
        pool = RefPool()

        insns, off_to_idx = decode_dalvik_method(dex, code, pool)
        try_blocks = _translate_try_catch(dex, code, off_to_idx, len(insns), pool)

        assert [insn.real_op for insn in insns[:4]] == [
            VmpOp.CONST,
            VmpOp.THROW,
            VmpOp.MOVE_EXCEPTION,
            VmpOp.RETURN,
        ]
        assert len(try_blocks) == 1
        block = try_blocks[0]
        assert block.start_pc == 0
        assert block.end_pc == 2
        assert block.handlers[0].handler_pc == 2
        assert pool.strings[block.handlers[0].type_str_idx] == "Ljava/lang/IllegalStateException;"
        assert block.catch_all_pc == 3


class TestVmpSplitObfuscation:
    def test_2addr_binop_is_not_split(self):
        insn = VmpInsn(real_op=int(VmpOp.XOR_INT), dst=4, src1=5, src2=0, imm=0)

        out = split_vmp_instructions([insn], registers_size=8, rng=random.Random(0), split_prob=1.0)

        assert out == [insn]

    def test_move_object_is_not_split_through_integer_add(self):
        insn = VmpInsn(real_op=int(VmpOp.MOVE_OBJECT), dst=1, src1=2)

        out = split_vmp_instructions([insn], registers_size=4, rng=random.Random(4), split_prob=1.0)

        assert out == [insn]

    def test_split_is_disabled_when_no_scratch_register_is_available(self):
        insn = VmpInsn(real_op=int(VmpOp.ADD_INT), dst=1, src1=2, src2=3)

        out = split_vmp_instructions([insn], registers_size=256, rng=random.Random(1), split_prob=1.0)

        assert out == [insn]

    def test_inline_junk_does_not_split_split_group(self):
        grouped_first = VmpInsn(real_op=int(VmpOp.CONST), dst=64, imm=123)
        grouped_second = VmpInsn(real_op=int(VmpOp.XOR_INT), dst=1, src1=64, imm=55)
        grouped_first._split_group = 7
        grouped_second._split_group = 7
        insns = [
            VmpInsn(real_op=int(VmpOp.CONST), dst=0, imm=1),
            VmpInsn(real_op=int(VmpOp.CONST), dst=1, imm=2),
            VmpInsn(real_op=int(VmpOp.CONST), dst=2, imm=3),
            grouped_first,
            grouped_second,
            VmpInsn(real_op=int(VmpOp.RETURN), dst=1),
        ]

        out = obfuscate_vmp_bytecode(insns, registers_size=4, seed=0, junk_ratio=0.0, inline_junk_ratio=1.0)

        assert out[3] is grouped_first
        assert out[4] is grouped_second

    def test_zero_junk_ratios_leave_bytecode_unchanged(self):
        insns = [
            VmpInsn(real_op=int(VmpOp.CONST), dst=0, imm=4),
            VmpInsn(real_op=int(VmpOp.CONST), dst=1, imm=8),
            VmpInsn(real_op=int(VmpOp.ADD_INT), dst=2, src1=0, imm=1),
            VmpInsn(real_op=int(VmpOp.RETURN), dst=2),
        ]

        out = obfuscate_vmp_bytecode(
            insns,
            registers_size=4,
            seed=0,
            junk_ratio=0.0,
            inline_junk_ratio=0.0,
        )

        assert out == insns

    def test_inline_opaque_predicate_checks_temp_register(self):
        insns = [
            VmpInsn(real_op=int(VmpOp.CONST), dst=i, imm=i)
            for i in range(5)
        ]

        out = obfuscate_vmp_bytecode(
            insns,
            registers_size=4,
            seed=0,
            junk_ratio=0.0,
            inline_junk_ratio=1.0,
        )

        guard_const = out[4]
        guard_if = out[5]

        assert guard_const.real_op == VmpOp.CONST
        assert guard_if.real_op == VmpOp.IF_NEZ
        assert guard_if.dst == guard_const.dst
        assert out[5 + guard_if.imm] is insns[4]

    def test_junk_obfuscation_keeps_register_operands_byte_encodable(self):
        insns = [
            VmpInsn(real_op=int(VmpOp.IF_EQZ), dst=0, imm=1),
            VmpInsn(real_op=int(VmpOp.CONST), dst=1, imm=1),
            VmpInsn(real_op=int(VmpOp.CONST), dst=2, imm=2),
            VmpInsn(real_op=int(VmpOp.RETURN), dst=2),
        ]

        out = obfuscate_vmp_bytecode(
            insns,
            registers_size=256,
            seed=1,
            junk_ratio=1.0,
            inline_junk_ratio=1.0,
        )

        for insn in out:
            insn.pack_raw(list(range(256)))

    def test_goto_guarded_junk_skips_to_next_real_instruction(self):
        branch = VmpInsn(real_op=int(VmpOp.IF_EQZ), dst=0, imm=1)
        after_branch = VmpInsn(real_op=int(VmpOp.CONST), dst=1, imm=1)
        insns = [
            branch,
            after_branch,
            VmpInsn(real_op=int(VmpOp.CONST), dst=2, imm=2),
            VmpInsn(real_op=int(VmpOp.CONST), dst=3, imm=3),
        ]

        out = obfuscate_vmp_bytecode(
            insns,
            registers_size=4,
            seed=1,
            junk_ratio=1.0,
            inline_junk_ratio=0.0,
        )

        skip = out[1]

        assert skip.real_op == VmpOp.GOTO
        assert out[1 + skip.imm] is after_branch


class TestBlobHeader:
    def test_blob_magic_length(self):
        assert len(VMP_BLOB_MAGIC) >= 4

    def test_blob_version_positive(self):
        assert VMP_BLOB_VERSION >= 1

    def test_blob_version_is_encrypted_string_pool_format(self):
        assert VMP_BLOB_VERSION == 4

    def test_blob_magic_not_empty(self):
        assert VMP_BLOB_MAGIC
        assert VMP_BLOB_MAGIC.strip() != b""

    def test_string_pool_is_not_serialized_as_plaintext(self):
        pool = RefPool()
        secret = "Lcom/example/Secret;->check(Ljava/lang/String;)Z"
        pool.intern(secret)

        blob = serialize_vmp_blob(
            methods=[],
            pool=pool,
            unshuffle=list(range(256)),
            shuffle=list(range(256)),
        )

        assert secret.encode("utf-8") not in blob

        pos = len(VMP_BLOB_MAGIC) + 4 + 256
        string_salt = int.from_bytes(blob[pos:pos + 4], "little")
        string_count = int.from_bytes(blob[pos + 4:pos + 8], "little")

        assert string_salt != 0
        assert string_count == 1
