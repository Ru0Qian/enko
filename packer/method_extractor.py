"""Method Body Extraction for DEX hardening (Phase 4.1).

Extracts the ``insns`` (instruction body) of target methods from DEX files,
replaces them with a ``throw`` stub + NOP fill, and produces an encrypted
blob that the native runtime can use to restore the instructions at load time.

The extraction blob is AES-GCM encrypted with the same per-APK payload key.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ModuleNotFoundError:
    AES = None  # type: ignore[assignment]
    get_random_bytes = None  # type: ignore[assignment]

from dex_parser import (
    DexFile,
    EncodedMethod,
    parse_dex,
    compute_dex_checksum,
    compute_dex_signature,
)

# Magic prefix for the extraction blob (before AES-GCM encryption layer).
EXTRACT_MAGIC = b"T9qE1vN6pM3uC7x"  # 15 bytes, same length as PAYLOAD_MAGIC

# Dalvik NOP = 0x0000.
# We use a stub that is valid for any return type:
#   - For insns_size >= 2: const/4 v0, 0; throw v0; [nop...]
#     (always throws null => NPE, verifies cleanly as long as registers_size >= 1)
#   - For insns_size == 1: goto +0 (infinite loop, no registers required)
#     (verifies cleanly for any signature, and fits in a single code unit)
_CONST4_V0_0 = b"\x12\x00"  # const/4 v0, #int 0
_THROW_V0 = b"\x27\x00"     # throw v0
_GOTO_0 = b"\x28\x00"       # goto +0 (jump to self)
_NOP_UNIT = b"\x00\x00"     # nop (1 code unit)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ExtractedMethod:
    """Metadata for one extracted method."""
    dex_index: int          # index into the dex_files list
    insns_file_offset: int  # byte offset of insns within the DEX file
    insns_bytes: bytes      # original insns raw bytes


@dataclass
class ExtractionResult:
    """Result of running method extraction on a set of DEX files."""
    methods: list[ExtractedMethod] = field(default_factory=list)
    patched_dex_data: dict[int, bytearray] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Core extraction logic
# ---------------------------------------------------------------------------

def _find_encoded_method(dex: DexFile, method_idx: int) -> EncodedMethod | None:
    return dex.find_encoded_method(method_idx)


def _iter_class_methods(dex: DexFile, class_desc: str) -> list[EncodedMethod]:
    """Return all methods defined on a class (direct + virtual).

    Note: this returns only methods present in class_data_item, i.e. methods
    actually defined in this DEX (not external references).
    """
    return dex.iter_class_methods(class_desc)


def _stub_fill(insns_code_units: int) -> bytes:
    """Generate a verifiable stub followed by NOP padding.

    - insns_size == 1: emit a self-loop (goto +0)
    - insns_size >= 2: emit const/4 + throw (always throws) then NOP fill

    This avoids needing to know the method return type.
    """
    if insns_code_units <= 0:
        return b""
    if insns_code_units == 1:
        return _GOTO_0

    parts = [_CONST4_V0_0, _THROW_V0]
    for _ in range(insns_code_units - 2):
        parts.append(_NOP_UNIT)
    return b"".join(parts)


def extract_methods(
    dex_files: list[Path],
    targets: list[tuple[str, str, str | None]],
    fail_open: bool = False,
) -> ExtractionResult:
    """Extract method insns from the given DEX files.

    *targets*: list of ``(class_descriptor, method_name, signature_or_None)``.
    The format matches :func:`harden_apk.parse_vmp_dex_spec`.

    Returns an :class:`ExtractionResult` with extracted method data and the
    patched (stub-filled) DEX bytearrays that should be written back.
    """
    result = ExtractionResult()

    parsed: list[DexFile] = []
    raw_data: list[bytearray] = []
    for dex_path in dex_files:
        raw = dex_path.read_bytes()
        dex = parse_dex(raw)
        parsed.append(dex)
        raw_data.append(bytearray(raw))

    extracted: set[tuple[int, int]] = set()  # (dex_idx, method_idx)

    for class_desc, method_name, sig in targets:
        found = False

        for dex_idx, dex in enumerate(parsed):
            # Resolve this target spec to one-or-more method indices in THIS dex.
            if method_name == "*":
                ems = _iter_class_methods(dex, class_desc)
                if not ems:
                    continue
                candidate_indices = [em.method_idx for em in ems]
            elif sig is None:
                # No signature provided => match all overloads with this name.
                ems = _iter_class_methods(dex, class_desc)
                if not ems:
                    continue
                candidate_indices = [
                    em.method_idx
                    for em in ems
                    if dex.method_name(em.method_idx) == method_name
                ]
                if not candidate_indices:
                    continue
            else:
                midx = dex.find_method(class_desc, method_name, sig)
                if midx is None:
                    continue
                candidate_indices = [midx]

            found = True
            data = raw_data[dex_idx]

            for midx in sorted(set(candidate_indices)):
                if (dex_idx, midx) in extracted:
                    continue

                em = _find_encoded_method(dex, midx)
                if em is None or em.code is None:
                    msg = f"extract: no code for {class_desc}->{dex.method_name(midx)}"
                    # For wildcards/overloads it's expected to see abstract/native methods.
                    if method_name == "*" or sig is None:
                        print(f"[!] {msg}; skip")
                        continue
                    if fail_open:
                        print(f"[!] {msg}")
                        continue
                    raise RuntimeError(msg)

                ci = em.code
                if ci.insns_size == 0:
                    continue

                insns_off = ci._file_offset + 16  # 16-byte code_item header
                insns_len = ci.insns_size * 2      # in bytes

                # Bounds check.
                if insns_off + insns_len > len(data):
                    msg = (
                        f"extract: insns out of bounds for "
                        f"{class_desc}->{dex.method_name(midx)} "
                        f"(off={insns_off}, len={insns_len}, dex_size={len(data)})"
                    )
                    if fail_open:
                        print(f"[!] {msg}")
                        continue
                    raise RuntimeError(msg)

                # Replace with verifiable stub + NOP fill.
                stub = _stub_fill(ci.insns_size)

                # Ensure the throw-stub can reference v0 even for methods with no registers.
                if ci.insns_size >= 2 and ci.registers_size < 1:
                    struct.pack_into("<H", data, ci._file_offset, 1)

                # Save original insns + patch.
                original_insns = bytes(data[insns_off: insns_off + insns_len])
                result.methods.append(ExtractedMethod(
                    dex_index=dex_idx,
                    insns_file_offset=insns_off,
                    insns_bytes=original_insns,
                ))
                extracted.add((dex_idx, midx))

                data[insns_off: insns_off + insns_len] = stub

            break  # only extract from the first DEX that has this class/method

        if not found:
            msg = f"extract: method not found: {class_desc}->{method_name}" + (sig or "")
            if fail_open:
                print(f"[!] {msg}")
            else:
                raise RuntimeError(msg)

    # Do NOT recalculate checksums/signatures: at runtime the original
    # method insns are bulk-restored into the DirectByteBuffer BEFORE ART
    # creates its InMemoryDexClassLoader.  ART therefore sees the original
    # bytecode and the original (unchanged) checksum/signature — which match.
    # Recalculating here would produce a checksum for the stub-filled version,
    # causing ART to reject the DEX after restore.
    modified_dex_indices = {m.dex_index for m in result.methods}
    for dex_idx in modified_dex_indices:
        result.patched_dex_data[dex_idx] = raw_data[dex_idx]

    return result


# ---------------------------------------------------------------------------
# Blob serialisation
# ---------------------------------------------------------------------------

def serialize_extraction_blob(methods: list[ExtractedMethod]) -> bytes:
    """Serialize extracted method data into the blob plaintext format.

    Format::

        method_count : u32
        for each method:
            dex_index        : u16
            insns_file_offset: u32
            insns_byte_len   : u32
            insns_data       : bytes[insns_byte_len]
    """
    parts: list[bytes] = []
    parts.append(struct.pack("<I", len(methods)))
    for m in methods:
        parts.append(struct.pack("<H", m.dex_index))
        parts.append(struct.pack("<I", m.insns_file_offset))
        parts.append(struct.pack("<I", len(m.insns_bytes)))
        parts.append(m.insns_bytes)
    return b"".join(parts)


def encrypt_extraction_blob(plaintext: bytes, key: bytes) -> bytes:
    """AES-GCM encrypt the extraction blob.

    Output: ``EXTRACT_MAGIC(15) + nonce(12) + ciphertext + tag(16)``
    """
    if AES is None or get_random_bytes is None:
        raise RuntimeError("pycryptodome is required for extraction encryption")
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return EXTRACT_MAGIC + nonce + ciphertext + tag


# ---------------------------------------------------------------------------
# High-level API for harden_apk.py
# ---------------------------------------------------------------------------

def run_method_extraction(
    dex_files: list[Path],
    targets: list[tuple[str, str, str | None]],
    payload_key: bytes,
    fail_open: bool = False,
) -> tuple[bytes | None, int]:
    """Extract target methods, patch DEX files, produce encrypted blob.

    Returns ``(encrypted_blob_or_None, extracted_count)``.
    """
    result = extract_methods(dex_files, targets, fail_open=fail_open)
    if not result.methods:
        return None, 0

    # Write patched DEX data back to disk.
    for dex_idx, patched_data in result.patched_dex_data.items():
        dex_files[dex_idx].write_bytes(patched_data)
        print(
            f"[*] extract: patched {dex_files[dex_idx].name} "
            f"({sum(1 for m in result.methods if m.dex_index == dex_idx)} method(s))"
        )

    plaintext = serialize_extraction_blob(result.methods)
    blob = encrypt_extraction_blob(plaintext, payload_key)

    total_insns = sum(len(m.insns_bytes) for m in result.methods)
    print(
        f"[*] extract: {len(result.methods)} method(s), "
        f"{total_insns} insns bytes, blob {len(blob)} bytes"
    )
    return blob, len(result.methods)
