#!/usr/bin/env python3
"""VMP blob inspector — developer diagnostic.

Reads any VMP blob (v4 or v5) and dumps:
  - header fields
  - opcode unshuffle table
  - (v5) derived width table + operand layout table
  - method list
  - per-method bytecode walked with width info

NOT shipped in releases. Used by the test suite for v4/v5 parity
verification.

Usage:
    python tools/vmp_blob_inspect.py <blob-file> [--strings] [--bytecode METHOD_IDX]
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

# Ensure packer modules importable.
_packer_dir = str(Path(__file__).resolve().parent.parent / "packer")
if _packer_dir not in sys.path:
    sys.path.insert(0, _packer_dir)

from vmp_blob_compat import BlobView, read_blob  # noqa: E402
from vmp_compiler import (  # noqa: E402
    derive_v5_layout_table,
    derive_v5_width_table,
    _crypt_vmp_string,
)


def dump_header(view: BlobView) -> None:
    print(f"version           = {view.version}")
    print(f"format_flags      = 0x{view.format_flags:08x}")
    print(f"string_pool_salt  = 0x{view.string_pool_salt:08x}")
    print(f"n_strings         = {len(view.strings_encrypted)}")
    print(f"n_methods         = {len(view.methods)}")
    print(f"bytecode_bytes    = {len(view.bytecode_section)}")
    if view.version == 5:
        print(f"width_table_seed  = 0x{view.width_table_seed:08x}")
        print(f"operand_layout_seed = 0x{view.operand_layout_seed:08x}")
        print(f"extra_header_size = {len(view.extra_header) + 24} (incl. mandatory fields)")


def dump_strings(view: BlobView) -> None:
    for i, encrypted in enumerate(view.strings_encrypted):
        # Decrypt for display only.
        decrypted = _crypt_vmp_string(encrypted, view.string_pool_salt, i)
        try:
            text = decrypted.decode("utf-8")
        except UnicodeDecodeError:
            text = decrypted.hex()
        print(f"  [{i:4d}] {text!r}")


def dump_v5_width_table(view: BlobView) -> None:
    assert view.version == 5 and view.width_table_seed is not None
    table = derive_v5_width_table(view.width_table_seed)
    by_class: dict[int, list[int]] = {}
    for op, w in enumerate(table):
        by_class.setdefault(w, []).append(op)
    for w in sorted(by_class):
        ops = by_class[w]
        print(f"  W{w}: {len(ops)} ops -> first 8: {ops[:8]}")


def dump_v5_layouts(view: BlobView) -> None:
    assert view.version == 5 and view.operand_layout_seed is not None
    layouts = derive_v5_layout_table(view.operand_layout_seed)
    for w, layout in sorted(layouts.items()):
        line_parts = []
        for field_name, pos in layout.items():
            if isinstance(pos, tuple):
                line_parts.append(f"{field_name}@[{pos[0]}:{pos[0]+pos[1]}]")
            else:
                line_parts.append(f"{field_name}@{pos}")
        print(f"  W{w}: {' '.join(line_parts)}")


def dump_bytecode_v5(view: BlobView, method_idx: int) -> None:
    if not (0 <= method_idx < len(view.methods)):
        print(f"method_idx {method_idx} out of range")
        return
    m = view.methods[method_idx]
    bc = view.bytecode_section[m.bc_offset:m.bc_offset + m.bc_length]
    width_table = derive_v5_width_table(view.width_table_seed)
    layouts = derive_v5_layout_table(view.operand_layout_seed)
    unshuffle = list(view.unshuffle_table)

    print(f"method {method_idx}: class_idx={m.class_name_idx} name_idx={m.method_name_idx} "
          f"sig_idx={m.method_sig_idx} regs={m.registers_size} bytes={m.bc_length}")
    pc = 0
    insn_count = 0
    while pc < len(bc):
        # Opcode is pinned to byte 0 of every insn — that's the one
        # fixed anchor every v5 build keeps consistent. Read it,
        # un-shuffle, derive the width.
        if pc + 1 > len(bc):
            print(f"  pc={pc}: <truncated>")
            break
        byte = bc[pc + 0]
        real_op = unshuffle[byte]
        w = width_table[real_op]
        if pc + w > len(bc):
            print(f"  pc={pc}: <width {w} overruns remaining {len(bc) - pc} bytes>")
            break
        slice_bytes = bc[pc:pc + w]
        print(f"  pc={pc:4d} w={w}  real_op={real_op:3d}  bytes={slice_bytes.hex()}")
        pc += w
        insn_count += 1
    print(f"  ({insn_count} insns / {pc} bytes)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect a VMP blob")
    parser.add_argument("blob", help="path to blob file (e.g. extracted libvtvm.so payload)")
    parser.add_argument("--strings", action="store_true", help="dump decrypted string pool")
    parser.add_argument("--width-table", action="store_true",
                        help="(v5) dump derived width table summary")
    parser.add_argument("--layout", action="store_true",
                        help="(v5) dump operand-field positions per width class")
    parser.add_argument("--bytecode", type=int, default=-1,
                        help="(v5) walk bytecode of method INDEX")
    args = parser.parse_args()

    data = Path(args.blob).read_bytes()
    view = read_blob(data)
    print(f"=== {args.blob} ===")
    dump_header(view)
    if args.strings:
        print("--- string pool ---")
        dump_strings(view)
    if args.width_table and view.version == 5:
        print("--- v5 width table ---")
        dump_v5_width_table(view)
    if args.layout and view.version == 5:
        print("--- v5 operand layouts ---")
        dump_v5_layouts(view)
    if args.bytecode >= 0 and view.version == 5:
        print(f"--- v5 bytecode method[{args.bytecode}] ---")
        dump_bytecode_v5(view, args.bytecode)
    return 0


if __name__ == "__main__":
    sys.exit(main())
