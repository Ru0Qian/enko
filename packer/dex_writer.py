"""DEX binary patcher for VMP.

Patches target methods to be `native` (sets ACC_NATIVE, clears code_off)
so that at runtime JNI RegisterNatives can route them to the VMP interpreter.
Also updates the DEX checksum and SHA-1 signature.
"""
from __future__ import annotations

import struct

from dex_parser import (
    DexFile, ClassDef, ClassData, EncodedMethod,
    ACC_NATIVE, ACC_ABSTRACT,
    compute_dex_checksum, compute_dex_signature,
    _read_uleb128, _read_sleb128,
)


def _write_uleb128(val: int) -> bytes:
    """Encode an unsigned value as ULEB128."""
    out = bytearray()
    while True:
        byte = val & 0x7F
        val >>= 7
        if val != 0:
            byte |= 0x80
        out.append(byte)
        if val == 0:
            break
    return bytes(out)


def patch_methods_to_native(
    dex: DexFile,
    method_indices: list[int],
    wipe_insns: bool = False,
) -> bytearray:
    """Return a new DEX bytearray with the given methods patched to native.

    Strategy:
      1. For each target method, find its encoded_method in the class_data_item.
      2. Rewrite the class_data_item in-place:
         - Set access_flags |= ACC_NATIVE
         - Set code_off = 0
      3. (Optional) wipe the original code_item insns bytes for those methods.
      4. Update DEX signature (SHA-1) and checksum (Adler-32).

    This avoids touching any constant-pool sections, so all offsets remain valid.

    wipe_insns is only safe when the methods are actually treated as native at
    runtime (i.e. code_off=0 is honored).  It removes the original Dalvik
    bytecode from the DEX data section to hinder static recovery.
    """
    data = bytearray(dex.raw)
    target_set = set(method_indices)

    for cd in dex.class_defs:
        if cd.class_data is None or cd.class_data_off == 0:
            continue
        _patch_class_data(data, cd, target_set)

    if wipe_insns:
        _wipe_code_insns(data, dex, target_set)

    # Update signature and checksum.
    sig = compute_dex_signature(data)
    data[12:32] = sig
    cksum = compute_dex_checksum(data)
    struct.pack_into("<I", data, 8, cksum)

    return data


def _wipe_code_insns(data: bytearray, dex: DexFile, targets: set[int]) -> None:
    """Zero-fill the original Dalvik insns bytes for target methods.

    The methods must be patched to `native` (code_off=0) before doing this,
    otherwise ART may still try to execute the bytecode.

    We only wipe the `insns` array region (code_item header and try/catch data
    are left intact), since the goal is to remove recoverable bytecode.
    """
    for cd in dex.class_defs:
        if cd.class_data is None:
            continue
        methods = cd.class_data.direct_methods + cd.class_data.virtual_methods
        for em in methods:
            if em.method_idx not in targets:
                continue
            if em.code is None:
                continue
            ci = em.code
            insns_off = ci._file_offset + 16
            insns_len = ci.insns_size * 2
            if insns_len <= 0:
                continue
            if insns_off < 0 or insns_off + insns_len > len(data):
                continue
            data[insns_off: insns_off + insns_len] = b"\x00" * insns_len


def _patch_class_data(
    data: bytearray,
    cd: ClassDef,
    targets: set[int],
) -> None:
    """Rewrite a class_data_item in-place, patching target methods."""
    pos = cd.class_data_off

    # Read sizes.
    sf_size, pos = _read_uleb128(data, pos)
    if_size, pos = _read_uleb128(data, pos)
    dm_size, pos = _read_uleb128(data, pos)
    vm_size, pos = _read_uleb128(data, pos)

    # Skip static fields.
    for _ in range(sf_size):
        _, pos = _read_uleb128(data, pos)  # field_idx diff
        _, pos = _read_uleb128(data, pos)  # access_flags

    # Skip instance fields.
    for _ in range(if_size):
        _, pos = _read_uleb128(data, pos)
        _, pos = _read_uleb128(data, pos)

    # Patch direct methods.
    prev_idx = 0
    for _ in range(dm_size):
        diff, pos_after_diff = _read_uleb128(data, pos)
        prev_idx += diff
        pos = pos_after_diff
        af, pos_after_af = _read_uleb128(data, pos)
        pos = pos_after_af
        co, pos_after_co = _read_uleb128(data, pos)
        pos = pos_after_co

        if prev_idx in targets:
            _rewrite_method_entry(data, pos_after_diff, af, co)

    # Patch virtual methods.
    prev_idx = 0
    for _ in range(vm_size):
        diff, pos_after_diff = _read_uleb128(data, pos)
        prev_idx += diff
        pos = pos_after_diff
        af, pos_after_af = _read_uleb128(data, pos)
        pos = pos_after_af
        co, pos_after_co = _read_uleb128(data, pos)
        pos = pos_after_co

        if prev_idx in targets:
            _rewrite_method_entry(data, pos_after_diff, af, co)


def _rewrite_method_entry(
    data: bytearray,
    af_start: int,
    old_af: int,
    old_co: int,
) -> None:
    """Rewrite access_flags and code_off ULEB128 fields in-place.

    ULEB128 encoding is variable-length, so we need to be careful:
    - The new access_flags may need more bytes (ACC_NATIVE added).
    - The new code_off is 0 (1 byte in ULEB128).

    We overwrite in-place.  If the new encoding is shorter, we pad with
    high-continuation bytes that still decode correctly (ULEB128 allows
    leading zero continuations).
    """
    # Compute new values.
    new_af = old_af | ACC_NATIVE
    new_co = 0  # no code for native methods

    # Measure old ULEB128 byte lengths.
    old_af_bytes = _uleb128_len(old_af)
    old_co_bytes = _uleb128_len(old_co)
    total_old = old_af_bytes + old_co_bytes

    new_af_enc = _write_uleb128(new_af)
    new_co_enc = _write_uleb128(new_co)
    total_new = len(new_af_enc) + len(new_co_enc)

    if total_new <= total_old:
        # Pad access_flags ULEB128 with leading-zero continuation bytes
        # so that af + co fills exactly the original byte span.
        padded_af = _pad_uleb128(new_af, total_old - len(new_co_enc))
        data[af_start: af_start + total_old] = padded_af + new_co_enc
    else:
        # New encoding is longer — this is rare (only if ACC_NATIVE pushes
        # access_flags past a ULEB128 boundary AND code_off was already
        # very small).  In practice code_off is > 128 for all real DEX
        # files so the shorter code_off=0 always reclaims enough space.
        # Guard: pad code_off=0 to steal back the extra byte.
        needed_af = len(new_af_enc)
        avail_co = total_old - needed_af
        if avail_co >= 1:
            padded_co = _pad_uleb128(new_co, avail_co)
            data[af_start: af_start + total_old] = new_af_enc + padded_co
        else:
            raise ValueError(
                f"Cannot patch method to native in-place: ULEB128 space "
                f"insufficient (need {total_new} bytes, have {total_old}, "
                f"af=0x{old_af:x}->0x{new_af:x}, code_off={old_co}). "
                f"The method may already be native or class_data is corrupt."
            )


def _pad_uleb128(val: int, target_len: int) -> bytes:
    """Encode val as ULEB128 padded to exactly target_len bytes."""
    out = bytearray()
    remaining = val
    for i in range(target_len):
        byte = remaining & 0x7F
        remaining >>= 7
        if i < target_len - 1:
            byte |= 0x80
        out.append(byte)
    return bytes(out)


def _uleb128_len(val: int) -> int:
    """Number of bytes needed to encode val as ULEB128."""
    if val == 0:
        return 1
    n = 0
    v = val
    while v > 0:
        v >>= 7
        n += 1
    return n
