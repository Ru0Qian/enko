"""Version-agnostic VMP blob reader.

This is the single entry point both Python tools (inspectors,
diagnostics, the test suite) and any future Python-side analyzer
should use. It hides the version dispatch so callers don't have to
branch on the magic header.

The native interpreter has its own dispatch (vmp_dispatch_v4 vs v5
in enko_vmp.c); this module is for the Python build / test side.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any


VMP_BLOB_MAGIC = b"M2vK7pQ9dL4\x00"


@dataclass
class MethodEntry:
    method_id: int
    class_name_idx: int
    method_name_idx: int
    method_sig_idx: int
    registers_size: int
    ins_size: int
    outs_size: int
    tries_count: int
    op_obfs_seed: int
    bc_offset: int
    bc_length: int


@dataclass
class BlobView:
    """Uniform view over any version of the VMP blob.

    Fields populated for both v4 and v5:
      version, format_flags, unshuffle_table, strings_encrypted,
      string_pool_salt, methods, bytecode_section, try_catch_offset

    v5-only fields (None on v4):
      width_table_seed, operand_layout_seed
    """
    version: int
    format_flags: int
    unshuffle_table: bytes
    string_pool_salt: int
    strings_encrypted: list[bytes]
    methods: list[MethodEntry]
    bytecode_section: bytes
    try_catch_blob: bytes
    width_table_seed: int | None = None
    operand_layout_seed: int | None = None
    extra_header: bytes = b""


def read_blob(data: bytes) -> BlobView:
    """Parse a VMP blob (v4 or v5) into a BlobView."""
    if len(data) < 16:
        raise ValueError("blob too short for common header")
    if data[:12] != VMP_BLOB_MAGIC:
        raise ValueError("VMP magic mismatch")
    version = struct.unpack_from("<I", data, 12)[0]
    if version == 4:
        return _read_v4(data)
    if version == 5:
        return _read_v5(data)
    raise ValueError(f"unsupported VMP blob version: {version}")


def _read_v4(data: bytes) -> BlobView:
    pos = 16
    unshuffle = data[pos:pos + 256]
    pos += 256
    salt = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    n_strings = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    encrypted = []
    for _ in range(n_strings):
        ln = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        encrypted.append(data[pos:pos + ln])
        pos += ln
    n_methods = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    methods = []
    method_entry_size = struct.calcsize("<IIIIHHHHiii")
    for _ in range(n_methods):
        unpacked = struct.unpack_from("<IIIIHHHHiii", data, pos)
        pos += method_entry_size
        methods.append(MethodEntry(*unpacked))
    bc_total = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    bytecode = data[pos:pos + bc_total]
    pos += bc_total
    try_catch_blob = data[pos:]
    return BlobView(
        version=4,
        format_flags=0,
        unshuffle_table=bytes(unshuffle),
        string_pool_salt=salt,
        strings_encrypted=encrypted,
        methods=methods,
        bytecode_section=bytecode,
        try_catch_blob=try_catch_blob,
    )


def _read_v5(data: bytes) -> BlobView:
    pos = 16
    extra_size = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    flags = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    width_seed = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    layout_seed = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    salt = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    pos += 4  # reserved

    # Any further bytes inside the declared extra-header area belong to
    # forward-compat extensions; we capture them raw.
    consumed_extra = 24  # bytes we read past the magic+version
    if extra_size > consumed_extra:
        extra_payload = data[pos:pos + (extra_size - consumed_extra)]
        pos += extra_size - consumed_extra
    else:
        extra_payload = b""

    unshuffle = data[pos:pos + 256]
    pos += 256
    n_strings = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    encrypted = []
    for _ in range(n_strings):
        ln = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        encrypted.append(data[pos:pos + ln])
        pos += ln
    n_methods = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    methods = []
    method_entry_size = struct.calcsize("<IIIIHHHHiii")
    for _ in range(n_methods):
        unpacked = struct.unpack_from("<IIIIHHHHiii", data, pos)
        pos += method_entry_size
        methods.append(MethodEntry(*unpacked))
    bc_total = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    bytecode = data[pos:pos + bc_total]
    pos += bc_total
    try_catch_blob = data[pos:]
    return BlobView(
        version=5,
        format_flags=flags,
        unshuffle_table=bytes(unshuffle),
        string_pool_salt=salt,
        strings_encrypted=encrypted,
        methods=methods,
        bytecode_section=bytecode,
        try_catch_blob=try_catch_blob,
        width_table_seed=width_seed,
        operand_layout_seed=layout_seed,
        extra_header=extra_payload,
    )
