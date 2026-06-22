#!/usr/bin/env python3
"""Generate XOR-encrypted C byte arrays for enko_obfstr.h.

Usage:
    python tools/gen_obfstr.py "enko_payload_key_v1"
    python tools/gen_obfstr.py --name payload_key_seed "enko_payload_key_v1"
    python tools/gen_obfstr.py --key 0xC7 "ENKO_PAYLOAD_V1"
    python tools/gen_obfstr.py --batch strings.txt   # one string per line
"""
import argparse
import sys


def xor_encrypt(plaintext: str, key: int) -> list[int]:
    return [b ^ key for b in plaintext.encode("utf-8")]


def to_c_name(s: str) -> str:
    out = []
    for ch in s:
        if ch.isalnum() or ch == "_":
            out.append(ch.lower())
        else:
            out.append("_")
    return "".join(out).strip("_")


def format_decl(name: str, plaintext: str, key: int) -> str:
    enc = xor_encrypt(plaintext, key)
    hex_bytes = ",".join(f"0x{b:02X}" for b in enc)
    return (
        f"/* \"{plaintext}\" (len={len(plaintext)}) */\n"
        f"OBFSTR_DECL({name}, {hex_bytes});\n"
        f"/* OBFSTR_USE(var, {name}, {len(plaintext)}); */\n"
    )


def main() -> int:
    p = argparse.ArgumentParser(description="Generate OBFSTR_DECL for enko_obfstr.h")
    p.add_argument("plaintext", nargs="?", default="", help="plaintext string to encrypt")
    p.add_argument("--name", default="", help="C identifier name (auto-derived if omitted)")
    p.add_argument("--key", default="0xC7", help="XOR key (hex, default 0xC7)")
    p.add_argument("--batch", default="", help="file with one string per line")
    args = p.parse_args()

    key = int(args.key, 0)

    if args.batch:
        with open(args.batch, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|", 1)
                if len(parts) == 2:
                    name, plaintext = parts[0].strip(), parts[1].strip()
                else:
                    name, plaintext = to_c_name(line), line
                print(format_decl(name, plaintext, key))
        return 0

    if not args.plaintext:
        p.print_help()
        return 1

    name = args.name or to_c_name(args.plaintext)
    print(format_decl(name, args.plaintext, key))
    return 0


if __name__ == "__main__":
    sys.exit(main())
