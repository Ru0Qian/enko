"""Minimal DEX binary parser for VMP compilation.

Supports reading all constant pools, class definitions, and method code items
from a standard DEX file (version 035+).  Also supports call-site and
method-handle items for DEX 038+ (invoke-custom / invoke-polymorphic).
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import BinaryIO

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEX_MAGIC = b"dex\n"
ENDIAN_CONSTANT = 0x12345678
NO_INDEX = 0xFFFFFFFF

# access flags
ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_NATIVE = 0x0100
ACC_ABSTRACT = 0x0400

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DexHeader:
    magic: bytes = b""
    checksum: int = 0
    signature: bytes = b""
    file_size: int = 0
    header_size: int = 0
    endian_tag: int = 0
    link_size: int = 0
    link_off: int = 0
    map_off: int = 0
    string_ids_size: int = 0
    string_ids_off: int = 0
    type_ids_size: int = 0
    type_ids_off: int = 0
    proto_ids_size: int = 0
    proto_ids_off: int = 0
    field_ids_size: int = 0
    field_ids_off: int = 0
    method_ids_size: int = 0
    method_ids_off: int = 0
    class_defs_size: int = 0
    class_defs_off: int = 0
    data_size: int = 0
    data_off: int = 0


@dataclass
class ProtoId:
    shorty_idx: int = 0
    return_type_idx: int = 0
    parameters_off: int = 0
    parameter_types: list[int] = field(default_factory=list)


@dataclass
class FieldId:
    class_idx: int = 0
    type_idx: int = 0
    name_idx: int = 0


@dataclass
class MethodId:
    class_idx: int = 0
    proto_idx: int = 0
    name_idx: int = 0


@dataclass
class MethodHandleItem:
    """DEX method_handle_item (DEX 038+)."""
    method_handle_type: int = 0   # 0-8: STATIC_PUT..INVOKE_INTERFACE
    field_or_method_id: int = 0   # index into field_ids or method_ids


@dataclass
class CallSiteItem:
    """Parsed call-site data from encoded_array_item (DEX 038+).

    For LambdaMetafactory, the encoded array is:
      [0] method_handle  — bootstrap method
      [1] string         — interface method name (e.g. "run")
      [2] method_type    — erased method type (proto_idx)
      [3] method_type    — additional
      [4] method_handle  — target implementation
      [5] method_type    — instantiated
    """
    bootstrap_handle_idx: int = -1
    method_name: str = ""
    extra_method_handle_idx: int = -1  # target handle, if present
    raw_values: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class TryItem:
    start_addr: int = 0
    insn_count: int = 0
    handler_off: int = 0


@dataclass
class CatchHandler:
    type_idx: int = NO_INDEX  # NO_INDEX means catch-all
    addr: int = 0


@dataclass
class EncodedCatchHandler:
    handlers: list[CatchHandler] = field(default_factory=list)
    catch_all_addr: int = -1
    _list_offset: int = 0  # byte offset relative to encoded_catch_handler_list start


@dataclass
class CodeItem:
    registers_size: int = 0
    ins_size: int = 0
    outs_size: int = 0
    tries_size: int = 0
    debug_info_off: int = 0
    insns_size: int = 0  # in 16-bit code units
    insns: bytes = b""  # raw bytecode (insns_size * 2 bytes)
    tries: list[TryItem] = field(default_factory=list)
    catch_handlers: list[EncodedCatchHandler] = field(default_factory=list)
    # file offset where this code_item starts (for patching)
    _file_offset: int = 0


@dataclass
class EncodedMethod:
    method_idx: int = 0  # absolute (decoded from diff encoding)
    access_flags: int = 0
    code_off: int = 0
    code: CodeItem | None = None


@dataclass
class EncodedField:
    field_idx: int = 0
    access_flags: int = 0


@dataclass
class ClassData:
    static_fields: list[EncodedField] = field(default_factory=list)
    instance_fields: list[EncodedField] = field(default_factory=list)
    direct_methods: list[EncodedMethod] = field(default_factory=list)
    virtual_methods: list[EncodedMethod] = field(default_factory=list)


@dataclass
class ClassDef:
    class_idx: int = 0
    access_flags: int = 0
    superclass_idx: int = 0
    interfaces_off: int = 0
    source_file_idx: int = 0
    annotations_off: int = 0
    class_data_off: int = 0
    static_values_off: int = 0
    class_data: ClassData | None = None


# ---------------------------------------------------------------------------
# DEX File representation
# ---------------------------------------------------------------------------

@dataclass
class DexFile:
    raw: bytearray = field(default_factory=bytearray)
    header: DexHeader = field(default_factory=DexHeader)
    strings: list[str] = field(default_factory=list)
    type_ids: list[int] = field(default_factory=list)  # each is string_idx
    proto_ids: list[ProtoId] = field(default_factory=list)
    field_ids: list[FieldId] = field(default_factory=list)
    method_ids: list[MethodId] = field(default_factory=list)
    class_defs: list[ClassDef] = field(default_factory=list)
    method_handles: list[MethodHandleItem] = field(default_factory=list)
    call_sites: list[CallSiteItem] = field(default_factory=list)

    # pre-built indexes (populated by build_indexes())
    _class_desc_to_defs: dict[str, list[ClassDef]] = field(default_factory=dict, repr=False)
    _method_idx_to_encoded: dict[int, EncodedMethod] = field(default_factory=dict, repr=False)

    def build_indexes(self) -> None:
        """Pre-build class→defs and method_idx→EncodedMethod indexes for O(1) lookup."""
        self._class_desc_to_defs.clear()
        self._method_idx_to_encoded.clear()
        for cd in self.class_defs:
            desc = self.type_name(cd.class_idx)
            self._class_desc_to_defs.setdefault(desc, []).append(cd)
            if cd.class_data is None:
                continue
            for em in cd.class_data.direct_methods:
                self._method_idx_to_encoded[em.method_idx] = em
            for em in cd.class_data.virtual_methods:
                self._method_idx_to_encoded[em.method_idx] = em

    def find_encoded_method(self, method_idx: int) -> EncodedMethod | None:
        """O(1) lookup by method_idx using pre-built index."""
        if self._method_idx_to_encoded:
            return self._method_idx_to_encoded.get(method_idx)
        # fallback: linear scan if indexes not built
        for cd in self.class_defs:
            if cd.class_data is None:
                continue
            for em in cd.class_data.direct_methods + cd.class_data.virtual_methods:
                if em.method_idx == method_idx:
                    return em
        return None

    def iter_class_methods(self, class_desc: str) -> list[EncodedMethod]:
        """Return all methods defined on a class (direct + virtual). O(1) with index."""
        out: list[EncodedMethod] = []
        defs = self._class_desc_to_defs.get(class_desc) if self._class_desc_to_defs else None
        if defs is not None:
            for cd in defs:
                if cd.class_data is None:
                    continue
                out.extend(cd.class_data.direct_methods)
                out.extend(cd.class_data.virtual_methods)
            return out
        # fallback: linear scan
        for cd in self.class_defs:
            if self.type_name(cd.class_idx) != class_desc:
                continue
            if cd.class_data is None:
                continue
            out.extend(cd.class_data.direct_methods)
            out.extend(cd.class_data.virtual_methods)
        return out

    # helpers
    def type_name(self, type_idx: int) -> str:
        if type_idx == NO_INDEX or type_idx >= len(self.type_ids):
            return ""
        return self.strings[self.type_ids[type_idx]]

    def method_class_name(self, method_idx: int) -> str:
        return self.type_name(self.method_ids[method_idx].class_idx)

    def method_name(self, method_idx: int) -> str:
        return self.strings[self.method_ids[method_idx].name_idx]

    def method_proto_shorty(self, method_idx: int) -> str:
        mid = self.method_ids[method_idx]
        return self.strings[self.proto_ids[mid.proto_idx].shorty_idx]

    def method_signature(self, method_idx: int) -> str:
        mid = self.method_ids[method_idx]
        proto = self.proto_ids[mid.proto_idx]
        params = "".join(self.type_name(t) for t in proto.parameter_types)
        ret = self.type_name(proto.return_type_idx)
        return f"({params}){ret}"

    def find_method(self, class_desc: str, method_name: str, signature: str | None = None) -> int | None:
        """Find method_idx by class descriptor + name + optional signature."""
        for idx, mid in enumerate(self.method_ids):
            if self.type_name(mid.class_idx) != class_desc:
                continue
            if self.strings[mid.name_idx] != method_name:
                continue
            if signature is not None and self.method_signature(idx) != signature:
                continue
            return idx
        return None

    def method_handle_ref(self, mh_idx: int) -> str:
        """Resolve a method_handle index to a 'class->name(sig)ret' string."""
        if mh_idx < 0 or mh_idx >= len(self.method_handles):
            return ""
        mh = self.method_handles[mh_idx]
        kind = mh.method_handle_type
        idx = mh.field_or_method_id
        if kind >= 4:  # INVOKE_STATIC .. INVOKE_INTERFACE
            if idx < len(self.method_ids):
                cls = self.method_class_name(idx)
                name = self.method_name(idx)
                sig = self.method_signature(idx)
                return f"{cls}->{name}{sig}"
        elif kind <= 3:  # field accessors
            if idx < len(self.field_ids):
                fid = self.field_ids[idx]
                cls = self.type_name(fid.class_idx)
                name = self.strings[fid.name_idx]
                typ = self.type_name(fid.type_idx)
                return f"{cls}->{name}:{typ}"
        return ""

    def call_site_target_ref(self, cs_idx: int) -> str | None:
        """For a call_site (lambda), resolve to the target implementation method ref."""
        if cs_idx < 0 or cs_idx >= len(self.call_sites):
            return None
        cs = self.call_sites[cs_idx]
        # Try the extra (target) method handle first
        if cs.extra_method_handle_idx >= 0:
            ref = self.method_handle_ref(cs.extra_method_handle_idx)
            if ref:
                return ref
        # Fall back to bootstrap handle
        if cs.bootstrap_handle_idx >= 0:
            ref = self.method_handle_ref(cs.bootstrap_handle_idx)
            if ref:
                return ref
        return None


# ---------------------------------------------------------------------------
# Reader helpers
# ---------------------------------------------------------------------------

def _u8(data: bytes | bytearray, off: int) -> int:
    return data[off]


def _u16(data: bytes | bytearray, off: int) -> int:
    val: int = struct.unpack_from("<H", data, off)[0]
    return val


def _u32(data: bytes | bytearray, off: int) -> int:
    val: int = struct.unpack_from("<I", data, off)[0]
    return val


def _s32(data: bytes | bytearray, off: int) -> int:
    val: int = struct.unpack_from("<i", data, off)[0]
    return val


def _read_uleb128(data: bytes | bytearray, off: int) -> tuple[int, int]:
    """Returns (value, new_offset)."""
    result = 0
    shift = 0
    pos = off
    while True:
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, pos


def _read_sleb128(data: bytes | bytearray, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    pos = off
    while True:
        b = data[pos]
        result |= (b & 0x7F) << shift
        shift += 7
        pos += 1
        if (b & 0x80) == 0:
            break
    if shift < 32 and (b & 0x40):
        result |= -(1 << shift)
    return result, pos


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _read_string_data(data: bytes | bytearray, off: int) -> str:
    """Read MUTF-8 string data at offset (after size ULEB128)."""
    _size, pos = _read_uleb128(data, off)
    end = data.index(0, pos)
    raw = data[pos:end]
    # Simplified MUTF-8: works for ASCII and most common cases.
    return raw.decode("utf-8", errors="replace")


def parse_dex(raw: bytes | bytearray) -> DexFile:
    data = bytearray(raw)
    dex = DexFile(raw=data)
    h = dex.header

    # ---- header ----
    h.magic = bytes(data[0:8])
    if not h.magic.startswith(DEX_MAGIC):
        raise ValueError(f"bad DEX magic: {h.magic!r}")
    h.checksum = _u32(data, 8)
    h.signature = bytes(data[12:32])
    h.file_size = _u32(data, 32)
    h.header_size = _u32(data, 36)
    h.endian_tag = _u32(data, 40)
    h.link_size = _u32(data, 44)
    h.link_off = _u32(data, 48)
    h.map_off = _u32(data, 52)
    h.string_ids_size = _u32(data, 56)
    h.string_ids_off = _u32(data, 60)
    h.type_ids_size = _u32(data, 64)
    h.type_ids_off = _u32(data, 68)
    h.proto_ids_size = _u32(data, 72)
    h.proto_ids_off = _u32(data, 76)
    h.field_ids_size = _u32(data, 80)
    h.field_ids_off = _u32(data, 84)
    h.method_ids_size = _u32(data, 88)
    h.method_ids_off = _u32(data, 92)
    h.class_defs_size = _u32(data, 96)
    h.class_defs_off = _u32(data, 100)
    h.data_size = _u32(data, 104)
    h.data_off = _u32(data, 108)

    # ---- string_ids → strings ----
    for i in range(h.string_ids_size):
        str_data_off = _u32(data, h.string_ids_off + i * 4)
        dex.strings.append(_read_string_data(data, str_data_off))

    # ---- type_ids ----
    for i in range(h.type_ids_size):
        dex.type_ids.append(_u32(data, h.type_ids_off + i * 4))

    # ---- proto_ids ----
    for i in range(h.proto_ids_size):
        base = h.proto_ids_off + i * 12
        p = ProtoId(
            shorty_idx=_u32(data, base),
            return_type_idx=_u32(data, base + 4),
            parameters_off=_u32(data, base + 8),
        )
        if p.parameters_off != 0:
            pcount = _u32(data, p.parameters_off)
            for j in range(pcount):
                p.parameter_types.append(_u16(data, p.parameters_off + 4 + j * 2))
        dex.proto_ids.append(p)

    # ---- field_ids ----
    for i in range(h.field_ids_size):
        base = h.field_ids_off + i * 8
        dex.field_ids.append(FieldId(
            class_idx=_u16(data, base),
            type_idx=_u16(data, base + 2),
            name_idx=_u32(data, base + 4),
        ))

    # ---- method_ids ----
    for i in range(h.method_ids_size):
        base = h.method_ids_off + i * 8
        dex.method_ids.append(MethodId(
            class_idx=_u16(data, base),
            proto_idx=_u16(data, base + 2),
            name_idx=_u32(data, base + 4),
        ))

    # ---- class_defs ----
    for i in range(h.class_defs_size):
        base = h.class_defs_off + i * 32
        cd = ClassDef(
            class_idx=_u32(data, base),
            access_flags=_u32(data, base + 4),
            superclass_idx=_u32(data, base + 8),
            interfaces_off=_u32(data, base + 12),
            source_file_idx=_u32(data, base + 16),
            annotations_off=_u32(data, base + 20),
            class_data_off=_u32(data, base + 24),
            static_values_off=_u32(data, base + 28),
        )
        if cd.class_data_off != 0:
            cd.class_data = _parse_class_data(data, cd.class_data_off)
        dex.class_defs.append(cd)

    # ---- method_handle_items & call_site_ids (DEX 038+) ----
    # These aren't in the standard header; find them via map_list.
    if h.map_off != 0:
        _parse_map_extras(data, h.map_off, dex)

    dex.build_indexes()
    return dex


def _parse_class_data(data: bytearray, off: int) -> ClassData:
    cd = ClassData()
    pos = off
    sf_size, pos = _read_uleb128(data, pos)
    if_size, pos = _read_uleb128(data, pos)
    dm_size, pos = _read_uleb128(data, pos)
    vm_size, pos = _read_uleb128(data, pos)

    prev_idx = 0
    for _ in range(sf_size):
        diff, pos = _read_uleb128(data, pos)
        af, pos = _read_uleb128(data, pos)
        prev_idx += diff
        cd.static_fields.append(EncodedField(field_idx=prev_idx, access_flags=af))

    prev_idx = 0
    for _ in range(if_size):
        diff, pos = _read_uleb128(data, pos)
        af, pos = _read_uleb128(data, pos)
        prev_idx += diff
        cd.instance_fields.append(EncodedField(field_idx=prev_idx, access_flags=af))

    prev_idx = 0
    for _ in range(dm_size):
        diff, pos = _read_uleb128(data, pos)
        af, pos = _read_uleb128(data, pos)
        co, pos = _read_uleb128(data, pos)
        prev_idx += diff
        em = EncodedMethod(method_idx=prev_idx, access_flags=af, code_off=co)
        if co != 0:
            em.code = _parse_code_item(data, co)
        cd.direct_methods.append(em)

    prev_idx = 0
    for _ in range(vm_size):
        diff, pos = _read_uleb128(data, pos)
        af, pos = _read_uleb128(data, pos)
        co, pos = _read_uleb128(data, pos)
        prev_idx += diff
        em = EncodedMethod(method_idx=prev_idx, access_flags=af, code_off=co)
        if co != 0:
            em.code = _parse_code_item(data, co)
        cd.virtual_methods.append(em)

    return cd


def _parse_code_item(data: bytearray, off: int) -> CodeItem:
    ci = CodeItem()
    ci._file_offset = off
    ci.registers_size = _u16(data, off)
    ci.ins_size = _u16(data, off + 2)
    ci.outs_size = _u16(data, off + 4)
    ci.tries_size = _u16(data, off + 6)
    ci.debug_info_off = _u32(data, off + 8)
    ci.insns_size = _u32(data, off + 12)
    insns_bytes = ci.insns_size * 2
    ci.insns = bytes(data[off + 16: off + 16 + insns_bytes])

    if ci.tries_size > 0:
        tries_off = off + 16 + insns_bytes
        # padding to 4-byte alignment
        if ci.insns_size % 2 != 0:
            tries_off += 2
        for i in range(ci.tries_size):
            t_base = tries_off + i * 8
            ci.tries.append(TryItem(
                start_addr=_u32(data, t_base),
                insn_count=_u16(data, t_base + 4),
                handler_off=_u16(data, t_base + 6),
            ))
        # catch handlers follow tries
        handlers_off = tries_off + ci.tries_size * 8
        _handlers_size, pos = _read_uleb128(data, handlers_off)
        for _ in range(_handlers_size):
            ech = EncodedCatchHandler()
            ech._list_offset = pos - handlers_off
            hcount, pos = _read_sleb128(data, pos)
            catch_all = hcount <= 0
            abs_count = abs(hcount)
            for _ in range(abs_count):
                tidx, pos = _read_uleb128(data, pos)
                addr, pos = _read_uleb128(data, pos)
                ech.handlers.append(CatchHandler(type_idx=tidx, addr=addr))
            if catch_all:
                ca_addr, pos = _read_uleb128(data, pos)
                ech.catch_all_addr = ca_addr
            ci.catch_handlers.append(ech)

    return ci


# ---------------------------------------------------------------------------
# Checksum / signature helpers
# ---------------------------------------------------------------------------

def compute_dex_signature(data: bytes | bytearray) -> bytes:
    """SHA-1 of everything after the signature field (offset 32 to end)."""
    return hashlib.sha1(data[32:]).digest()


def compute_dex_checksum(data: bytes | bytearray) -> int:
    """Adler-32 of everything after the checksum field (offset 12 to end)."""
    import zlib
    return zlib.adler32(data[12:]) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# DEX 038+ map_list parsing (method_handle_items, call_site_ids)
# ---------------------------------------------------------------------------

# map_list type codes
_TYPE_METHOD_HANDLE_ITEM = 0x0008
_TYPE_CALL_SITE_ID_ITEM  = 0x0007


def _parse_map_extras(data: bytearray, map_off: int, dex: DexFile) -> None:
    """Scan map_list for method_handle and call_site sections."""
    map_size = _u32(data, map_off)
    mh_off = mh_count = 0
    cs_off = cs_count = 0
    for i in range(map_size):
        base = map_off + 4 + i * 12
        item_type = _u16(data, base)
        item_size = _u32(data, base + 4)
        item_off  = _u32(data, base + 8)
        if item_type == _TYPE_METHOD_HANDLE_ITEM:
            mh_off, mh_count = item_off, item_size
        elif item_type == _TYPE_CALL_SITE_ID_ITEM:
            cs_off, cs_count = item_off, item_size

    # Parse method_handle_items (8 bytes each)
    for i in range(mh_count):
        base = mh_off + i * 8
        dex.method_handles.append(MethodHandleItem(
            method_handle_type=_u16(data, base),
            field_or_method_id=_u16(data, base + 4),
        ))

    # Parse call_site_ids → encoded_array_items
    for i in range(cs_count):
        cs_id_off = cs_off + i * 4
        ea_off = _u32(data, cs_id_off)
        cs = _parse_call_site_item(data, ea_off, dex)
        dex.call_sites.append(cs)


def _parse_call_site_item(data: bytearray, off: int, dex: DexFile) -> CallSiteItem:
    """Parse the encoded_array at *off* into a CallSiteItem."""
    cs = CallSiteItem()
    size, pos = _read_uleb128(data, off)

    for idx in range(size):
        vtype, value, pos = _parse_encoded_value(data, pos)
        cs.raw_values.append((vtype, value))
        if idx == 0 and vtype == 0x16:   # METHOD_HANDLE — bootstrap
            cs.bootstrap_handle_idx = value
        elif idx == 1 and vtype == 0x17:  # STRING — method name
            if value < len(dex.strings):
                cs.method_name = dex.strings[value]
        elif idx == 4 and vtype == 0x16:  # METHOD_HANDLE — target impl
            cs.extra_method_handle_idx = value

    return cs


def _parse_encoded_value(data: bytearray, pos: int) -> tuple[int, int, int]:
    """Parse one encoded_value, return (value_type, int_value, new_pos)."""
    header = data[pos]
    pos += 1
    value_type = header & 0x1F
    value_arg = (header >> 5) & 0x07

    if value_type == 0x1E:  # NULL
        return (value_type, 0, pos)
    if value_type == 0x1F:  # BOOLEAN
        return (value_type, value_arg, pos)

    # For most types, read (value_arg + 1) bytes as a little-endian integer.
    byte_count = value_arg + 1
    val = 0
    for i in range(byte_count):
        val |= data[pos + i] << (8 * i)
    pos += byte_count

    # Sign-extend for signed types (BYTE, SHORT, INT, LONG, FLOAT, DOUBLE).
    if value_type in (0x00, 0x02, 0x04, 0x06):
        if val & (1 << (8 * byte_count - 1)):
            val -= 1 << (8 * byte_count)

    return (value_type, val, pos)
