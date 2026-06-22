"""Tests for DEX parser: data structures, readers, checksums."""

import struct
import zlib

import pytest

# Import packer module (sibling to tests/)
import sys
from pathlib import Path

_packer = Path(__file__).resolve().parent.parent / "packer"
if str(_packer) not in sys.path:
    sys.path.insert(0, str(_packer))

from dex_parser import (
    DEX_MAGIC,
    ENDIAN_CONSTANT,
    NO_INDEX,
    ACC_PUBLIC,
    ACC_PRIVATE,
    ACC_PROTECTED,
    ACC_STATIC,
    ACC_FINAL,
    ACC_NATIVE,
    ACC_ABSTRACT,
    DexHeader,
    DexFile,
    _u8,
    _u16,
    _u32,
    _s32,
    _read_uleb128,
    _read_sleb128,
    compute_dex_checksum,
    compute_dex_signature,
)


class TestDexConstants:
    def test_magic(self):
        assert DEX_MAGIC == b"dex\n"
        assert len(DEX_MAGIC) == 4

    def test_endian_constant(self):
        assert ENDIAN_CONSTANT == 0x12345678

    def test_no_index(self):
        assert NO_INDEX == 0xFFFFFFFF

    def test_access_flags_are_unique(self):
        flags = [ACC_PUBLIC, ACC_PRIVATE, ACC_STATIC, ACC_NATIVE]
        assert len(flags) == len(set(flags))


class TestUleb128:
    def test_read_uleb128_single_byte(self):
        data = bytes([42])
        val, pos = _read_uleb128(data, 0)
        assert val == 42
        assert pos == 1  # consumed 1 byte

    def test_read_uleb128_multi_byte(self):
        # Encode 300 (0b 1 0010_1100 = 0xAC 0x02)
        data = bytes([0xAC, 0x02])
        val, pos = _read_uleb128(data, 0)
        assert val == 300
        assert pos == 2

    def test_read_uleb128_zero(self):
        data = bytes([0x00])
        val, pos = _read_uleb128(data, 0)
        assert val == 0
        assert pos == 1

    def test_read_uleb128_max_single(self):
        # Max value in a single byte: 0x7F = 127
        data = bytes([0x7F])
        val, pos = _read_uleb128(data, 0)
        assert val == 127

    def test_read_sleb128_positive(self):
        data = bytes([42])
        val, pos = _read_sleb128(data, 0)
        assert val == 42

    def test_read_sleb128_negative(self):
        # -1 in SLEB128 single byte = 0x7F (actually 0x71? No.)
        # SLEB128: -1 is encoded as 0x7F in one byte (sign bit set, value 0)
        # Wait: -1 = 0x7F? No. Let me compute:
        # For signed: 7 bits of data, 1 bit continuation
        # -1 in 7 bits = 0x7F (all 1s), continuation bit 0 → 0x7F with no continuation
        data = bytes([0x7F])
        val, pos = _read_sleb128(data, 0)
        assert val == -1

    def test_read_sleb128_negative_multi_byte(self):
        # -128 in SLEB128: 0x80 0x7F
        # 0x80 → low 7 bits = 0, continuation=1
        # 0x7F → low 7 bits = 0x7F=127, continuation=0, sign bit = 1
        # Result: 0 | (127 << 7) = 16256, sign extend with -(1<<14) = -16384
        # That gives -128. Actually wait: -128 = 0x180 in unsigned? Let me recalculate.
        # -128: in 14 bits, -128 = 0x3F80? Actually:
        # 128 = 0b1000_0000
        # in SLEB128: 128 = 0x80 0x01 (bit pattern: 1_0000000, 0_0000001)
        # -128 = ~128 + 1 = 0xFF80 in 16-bit, but in SLEB128 it's 0x80 0x7F
        # Let me not over-think: 0x80 0x7F → val = 0x80&0x7F | ((0x7F&0x7F) << 7) = 0 | (127<<7) = 16256
        # sign bit of 0x7F is set (bit 6), so result |= -(1<<14) → 16256 - 16384 = -128
        data = bytes([0x80, 0x7F])
        val, pos = _read_sleb128(data, 0)
        assert val == -128


class TestDexHeader:
    def test_default_header(self):
        h = DexHeader()
        assert h.magic == b""
        assert h.checksum == 0
        assert h.string_ids_size == 0
        assert h.header_size == 0

    def test_header_field_assignment(self):
        h = DexHeader(magic=DEX_MAGIC, checksum=42, file_size=100)
        assert h.magic == DEX_MAGIC
        assert h.checksum == 42
        assert h.file_size == 100


class TestDexFile:
    def test_empty_dex_file(self):
        dex = DexFile()
        assert dex.strings == []
        assert dex.type_ids == []
        assert dex.method_ids == []
        assert dex.class_defs == []

    def test_type_name_no_index(self):
        dex = DexFile()
        assert dex.type_name(NO_INDEX) == ""

    def test_type_name_out_of_bounds(self):
        dex = DexFile(type_ids=[])
        assert dex.type_name(0) == ""
        assert dex.type_name(100) == ""

    def test_type_name_valid(self):
        dex = DexFile(strings=["Ljava/lang/Object;", "I"], type_ids=[0, 1])
        assert dex.type_name(0) == "Ljava/lang/Object;"
        assert dex.type_name(1) == "I"


class TestComputations:
    def test_compute_checksum_empty_minimal(self):
        # Adler-32 of empty after byte 12
        data = b"\x00" * 32
        expected = zlib.adler32(data[12:]) & 0xFFFFFFFF
        assert compute_dex_checksum(data) == expected

    def test_compute_checksum_deterministic(self):
        data = b"\x00" * 12 + b"hello world test data"
        assert compute_dex_checksum(data) == compute_dex_checksum(data)

    def test_compute_signature_empty(self):
        import hashlib
        data = b"\x00" * 32 + b"payload"
        expected = hashlib.sha1(data[32:]).digest()
        assert compute_dex_signature(data) == expected

    def test_compute_checksum_known(self):
        # Empty payload — Adler-32 of empty bytes
        data = bytearray(12)  # first 12 bytes ignored
        cs = compute_dex_checksum(data)
        # Adler-32 of empty is 1
        assert cs == 1


class TestByteReaders:
    def test_u8(self):
        data = bytes([0xAB, 0xCD])
        assert _u8(data, 0) == 0xAB
        assert _u8(data, 1) == 0xCD

    def test_u16(self):
        data = struct.pack("<H", 0x1234)
        assert _u16(data, 0) == 0x1234

    def test_u32(self):
        data = struct.pack("<I", 0xDEADBEEF)
        assert _u32(data, 0) == 0xDEADBEEF

    def test_s32_negative(self):
        data = struct.pack("<i", -42)
        assert _s32(data, 0) == -42
