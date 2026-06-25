# VMP Blob Format

This document is the byte-level specification of Enko's VMP blob format.
It is the source of truth — the Python compiler (`packer/vmp_compiler.py`)
and the native interpreter (`shell-app/.../enko_vmp.c`) both implement
what is written here.

The blob is the encoded bytecode of all VMP-protected methods, packaged
into a single `libvtvm.so` payload that the shell loads at runtime.

## Versioning policy

| Version | Status | Notes |
|---------|--------|-------|
| v1–v3 | EOL | Used pre-2026 builds; no longer emitted or interpreted. |
| v4 | **current default** | Fixed-width 8-byte insns, opcode shuffle, LFSR operand scrambling, encrypted string pool. |
| v5 | **active development** | Variable-length insns (2/4/6/8/12/16 bytes), per-build randomized width table and operand layouts. Auto-enabled for `--vmp-vm-tier strong` / `extreme` once stable. |

**Backwards-compat window**: v5 ships in 2026-Q3 alongside v4. Six months
later (2027-Q1) the v4 *encoder* is deprecated with a warning; both
encoders stay buildable. Twelve months later (2027-Q3) the v4 encoder is
removed but the interpreter still reads v4 blobs so previously shipped
APKs keep working. Eighteen months later (2028-Q1) the v4 interpreter
path is removed.

The interpreter dispatches on `header.version`. Two completely
independent dispatch paths exist (`vmp_dispatch_v4` and
`vmp_dispatch_v5`) — reverse-engineering one does not leak the other.

## Common header (all versions)

```
offset  size  field
0       12    MAGIC = "M2vK7pQ9dL4\0"
12      4     VERSION (u32 LE; currently 4 or 5)
```

Anything past byte 16 is version-specific. The interpreter MUST read the
version, then jump to the per-version reader.

## v4 layout (current default)

After the common header at offset 16:

```
16      256   unshuffle_table[256]  — shuffled_opcode → real_op
272     4     string_pool_salt (u32 LE)
276     4     n_strings (u32 LE)
280..   var.  n_strings × (u16 len, encrypted bytes)
            (encryption: LFSR seeded by (salt ^ ((idx+1)*0x9E3779B1)))
…       4     n_methods (u32 LE)
…       N×38  method table: each entry packed "<IIIIHHHHiii":
            method_id, class_name_idx, method_name_idx, method_sig_idx,
            registers_size, ins_size, outs_size, tries_count,
            op_obfs_seed, bc_offset, bc_length
…       4     bc_total_size (u32 LE)
…       var.  concatenated bytecode (each insn = 8 bytes fixed)
…       var.  per-method try-catch tables
```

Each v4 insn is `<BBBBi>` — `(shuffled_opcode, dst, src1, src2, imm32)`.
Per-method `op_obfs_seed` drives an LFSR that XORs into each operand
field; the interpreter de-scrambles before reading.

## v5 layout (active development)

After the common header at offset 16:

```
16      4     header_extension_size (u32 LE)
            Size in bytes of the v5-specific extended header that follows
            (currently 24). Reserved for forward-compat: future fields
            append here without breaking the rest of the blob.
20      4     format_flags (u32 LE)
            bit 0  width_table_randomized        (always 1 in v5)
            bit 1  operand_layout_randomized     (always 1 in v5)
            bit 2  string_pool_encrypted          (always 1 in v5)
            bit 3  reserved
            bit 4..31 reserved (must be 0)
24      4     width_table_seed (u32 LE)
            Per-build random seed. Driven into LFSR to derive the
            per-opcode width table. Interpreter regenerates the table
            from this seed; the table itself is never serialized.
28      4     operand_layout_seed (u32 LE)
            Per-build random seed for operand-field position permutations
            within each width class.
32      4     string_pool_salt (u32 LE)
            Same role as v4's salt.
36      4     reserved (must be 0)
40      256   opcode_unshuffle_table[256]   — shuffled_opcode → real_op
            Identical role to v4.
296     4     n_strings (u32 LE)
300..   var.  n_strings × (u16 len, encrypted bytes)
…       4     n_methods (u32 LE)
…       N×38  method table — same packing as v4
            (bc_offset and bc_length are now BYTE offsets/sizes, not insn
            counts; the v5 reader must treat them as bytes.)
…       4     bc_total_size (u32 LE)
…       var.  concatenated bytecode (variable-length insns)
…       var.  per-method try-catch tables
            (start_pc, end_pc, handler_pc fields are now BYTE PCs.)
```

### v5 width classes

Each opcode (after un-shuffling) maps to exactly one of these widths:

| Class | Bytes | Used by |
|-------|-------|---------|
| W2  | 2  | `NOP`, `RETURN_VOID` |
| W4  | 4  | `MOVE*`, `MOVE_RESULT*`, `MOVE_EXCEPTION`, `RETURN*` (typed), `MONITOR_ENTER/EXIT`, `ARRAY_LENGTH`, `THROW`, all unops, all numeric conversions, alias unops |
| W6  | 6  | `CONST_S16` (new in v5: signed-16-bit const, optimisation for small literals) |
| W8  | 8  | All binops, all if-tests, `GOTO`, `IGET*/IPUT*/SGET*/SPUT*`, `AGET*/APUT*`, `CONST`, `CONST_CLASS`, `CONST_STRING`, `NEW_INSTANCE`, `NEW_ARRAY`, `CHECK_CAST`, `INSTANCE_OF`, all binop/lit aliases, all if-aliases |
| W12 | 12 | `CONST_WIDE` (64-bit immediate), `CONST_WIDE_HI32` (pseudo, paired with `CONST` in chains) |
| W16 | 16 | All invokes (`INVOKE_VIRTUAL/SUPER/DIRECT/STATIC/INTERFACE/CUSTOM/POLYMORPHIC`), `PACKED_SWITCH`, `SPARSE_SWITCH`, `FILL_ARRAY_DATA`, `FILLED_NEW_ARRAY` |

All invokes consume W16 even with zero arguments. This is intentional —
attackers cannot fingerprint short vs long invokes by byte count.

The mapping above is derived from `_OP_WIDTH_BASE` in
`packer/vmp_compiler.py`. Per-build `width_table_seed` rotates which
specific `real_op` ID lives in each class (within the same width — a
W4 op never becomes W8). The interpreter regenerates the mapping from
the seed.

### v5 operand layouts

For each width class, the **logical fields** are fixed by the opcode
family. The **physical byte positions** of those fields within the insn
are permuted per build, seeded by `operand_layout_seed`.

Logical fields per width class:

| Width | Fields |
|-------|--------|
| W2  | `opcode (1B)`, `arg0 (1B)` |
| W4  | `opcode (1B)`, `dst (1B)`, `src1 (1B)`, `pad (1B)` |
| W6  | `opcode (1B)`, `dst (1B)`, `imm_s16 (2B)`, `pad (2B)` |
| W8  | `opcode (1B)`, `dst (1B)`, `src1 (1B)`, `src2 (1B)`, `imm (4B)` |
| W12 | `opcode (1B)`, `dst (1B)`, `pad (2B)`, `imm64 (8B)` |
| W16 | `opcode (1B)`, `dst (1B)`, `nargs (1B)`, `r0…r4 (5B)`, `r5…r14 (10B + 1B pad)` — packed as `1B + 1B + 1B + 5B + 8B` after layout shuffle |

The per-build operand-layout permutation reshuffles the **field-position
table** for each width class — e.g. on build A the `opcode` byte may
live at byte 3 of W8 and `imm` at bytes 4-7; on build B `opcode` is at
byte 7 and `imm` at bytes 0-3. The interpreter reconstructs the field-
position map from `operand_layout_seed`.

This means **two consecutive builds of the same APK produce VMP blobs
where the same Java code emits different byte streams** — width
table, operand layout, opcode shuffle, and LFSR seed all change.

## Bytecode stream walking (v5)

To advance from one insn to the next, the v5 interpreter:

1. Read the byte at field-position `opcode_pos[width_class]` of the
   current insn — but it doesn't know the width yet, so it reads byte 0,
   un-shuffles, reads byte 0 instead and uses a heuristic? **No**: the
   opcode byte position is the **same for all width classes for a given
   build**, locked in by `operand_layout_seed`. So byte
   `opcode_pos_global` is the opcode regardless of width.
2. Un-shuffle to get `real_op`.
3. Look up `width = WIDTH_TABLE[real_op]`.
4. Decode remaining operand bytes per the class's layout.
5. Advance PC by `width` bytes.

The interpreter maintains a single 256-entry width array and a single
6-entry layout array per width class, both regenerated from blob seeds.

## try-catch table (v5)

Same wire format as v4 but `start_pc`, `end_pc`, `handler_pc`,
`catch_all_pc` are now **byte offsets** into the bytecode stream, not
insn counts. A v5-aware interpreter walks the bytecode stream with the
width table to locate the insn containing a given byte PC.

## Reading the blob from Python

Use `packer.vmp_blob_compat.read_blob(bytes)`. It returns a uniform
`BlobView` regardless of version, so callers don't have to branch.

```python
view = read_blob(open("libvtvm.so", "rb").read())
print(view.version)         # 4 or 5
print(view.method_count)    # int
print(view.format_flags)    # 0 for v4, bitmask for v5
```

## Diagnostic tooling

`tools/vmp_blob_inspect.py` is a developer-only utility that dumps any
blob's header + opcode table + width table + LFSR-decrypted strings +
insn stream. Not shipped in releases; used by the test suite to
generate v4-vs-v5 diff reports for behavioural parity verification.

## Test obligations

For every shipped opcode, the test suite verifies:

1. **Round-trip Python**: encode → decode → compare to original VmpInsn.
2. **Cross-version behavioural parity (v5 only)**: compile the same DEX
   method to both v4 and v5, run both interpreters on the same DEX run
   sequence, assert observable output (return value, JNI side effects,
   exceptions) is bit-identical.
3. **Random-permutation fuzz**: generate random DEX method shapes,
   encode to v4 and v5, run both, compare.

The CI matrix runs all three for every opcode at every supported width
class. See `tests/test_vmp_v5_roundtrip.py` and
`tests/test_vmp_v4_v5_parity.py`.

## Security properties (claimed)

v5 raises the static-analysis bar relative to v4 in three ways:

1. **Variable instruction width** defeats the simplest "every 8 bytes
   is one insn" disassemblers.
2. **Per-build randomized width table** means an attacker who reverse-
   engineers one build's width assignment cannot reuse that knowledge
   on another build of the same APK.
3. **Per-build randomized operand-field positions** mean the byte that
   holds the opcode in build A is unrelated to the byte that holds the
   opcode in build B — even after rederiving the width table.

v5 is **not** claimed to be unbreakable. A determined attacker who
recovers all four per-build secrets (opcode shuffle, width seed, layout
seed, LFSR scrambling seed) can disassemble the blob. The goal is to
add per-build noise so that **a one-off reverse on one build does not
help reverse the next build** — i.e. AI-assisted automated tooling
cannot accumulate cross-build knowledge.
