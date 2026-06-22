"""Tests for method extraction: stub generation, serialization, constants."""

import struct

import pytest

import sys
from pathlib import Path

_packer = Path(__file__).resolve().parent.parent / "packer"
if str(_packer) not in sys.path:
    sys.path.insert(0, str(_packer))

from method_extractor import (
    EXTRACT_MAGIC,
    ExtractedMethod,
    ExtractionResult,
    _stub_fill,
    serialize_extraction_blob,
)


class TestStubFill:
    def test_zero_insns(self):
        assert _stub_fill(0) == b""

    def test_negative_insns_returns_empty(self):
        assert _stub_fill(-1) == b""

    def test_single_unit_self_loop(self):
        # insns_size == 1: goto +0 (infinite self-loop)
        result = _stub_fill(1)
        assert result == b"\x28\x00"
        assert len(result) == 2

    def test_two_units_const4_throw(self):
        # insns_size >= 2: const/4 v0,0 + throw v0
        result = _stub_fill(2)
        assert result == b"\x12\x00\x27\x00"
        assert len(result) == 4

    def test_three_units_adds_one_nop(self):
        result = _stub_fill(3)
        assert result[:4] == b"\x12\x00\x27\x00"  # const/4 + throw
        assert result[4:] == b"\x00\x00"            # 1 nop
        assert len(result) == 6

    def test_five_units_pads_with_nops(self):
        result = _stub_fill(5)
        assert len(result) == 10  # 5 units * 2 bytes
        assert result[:4] == b"\x12\x00\x27\x00"  # first two units
        assert result[4:] == b"\x00\x00" * 3       # three nops

    def test_stub_always_even_bytes(self):
        for size in range(1, 10):
            result = _stub_fill(size)
            assert len(result) == size * 2


class TestExtractionResult:
    def test_default_empty(self):
        r = ExtractionResult()
        assert r.methods == []
        assert r.patched_dex_data == {}

    def test_add_extracted_method(self):
        em = ExtractedMethod(
            dex_index=0,
            insns_file_offset=100,
            insns_bytes=b"\x12\x34\x56\x78",
        )
        r = ExtractionResult(methods=[em])
        assert len(r.methods) == 1
        assert r.methods[0].dex_index == 0
        assert r.methods[0].insns_bytes == b"\x12\x34\x56\x78"


class TestSerializeExtractionBlob:
    def test_empty_methods(self):
        blob = serialize_extraction_blob([])
        # u32 count = 0
        assert blob == struct.pack("<I", 0)

    def test_single_method(self):
        methods = [
            ExtractedMethod(
                dex_index=0,
                insns_file_offset=256,
                insns_bytes=b"\x01\x02\x03\x04",
            )
        ]
        blob = serialize_extraction_blob(methods)
        # Parse back
        count = struct.unpack_from("<I", blob, 0)[0]
        assert count == 1
        dex_idx = struct.unpack_from("<H", blob, 4)[0]
        assert dex_idx == 0
        offset = struct.unpack_from("<I", blob, 6)[0]
        assert offset == 256
        insns_len = struct.unpack_from("<I", blob, 10)[0]
        assert insns_len == 4
        insns = blob[14:18]
        assert insns == b"\x01\x02\x03\x04"

    def test_multiple_methods(self):
        methods = [
            ExtractedMethod(dex_index=0, insns_file_offset=0, insns_bytes=b"\xAA" * 10),
            ExtractedMethod(dex_index=1, insns_file_offset=500, insns_bytes=b"\xBB" * 5),
            ExtractedMethod(dex_index=0, insns_file_offset=200, insns_bytes=b""),
        ]
        blob = serialize_extraction_blob(methods)
        count = struct.unpack_from("<I", blob, 0)[0]
        assert count == 3

        pos = 4
        for i, m in enumerate(methods):
            d = struct.unpack_from("<H", blob, pos)[0]
            o = struct.unpack_from("<I", blob, pos + 2)[0]
            l = struct.unpack_from("<I", blob, pos + 6)[0]
            b = blob[pos + 10 : pos + 10 + l]
            assert d == m.dex_index, f"method {i}: dex_index mismatch"
            assert o == m.insns_file_offset, f"method {i}: offset mismatch"
            assert l == len(m.insns_bytes), f"method {i}: len mismatch"
            assert b == m.insns_bytes, f"method {i}: bytes mismatch"
            pos += 10 + l

    def test_roundtrip_empty(self):
        # Serialize and verify count is zero
        blob = serialize_extraction_blob([])
        assert len(blob) == 4  # just the count


class TestExtractMagic:
    def test_magic_length(self):
        assert len(EXTRACT_MAGIC) == 15

    def test_magic_not_empty(self):
        assert EXTRACT_MAGIC
        assert EXTRACT_MAGIC != b"\x00" * 15
