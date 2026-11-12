#!/usr/bin/env python3
"""Read-only PE32+ inspection, with bounds checks for malformed files."""

import argparse
import json
from pathlib import Path
import struct


class PEFormatError(ValueError):
    pass


def _field(data: bytes, fmt: str, offset: int):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise PEFormatError(f"truncated field at offset 0x{offset:x}")
    values = struct.unpack_from(fmt, data, offset)
    return values[0] if len(values) == 1 else values


def inspect(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEFormatError("missing or truncated DOS header")
    pe = _field(data, "<I", 0x3C)
    if pe + 24 > len(data) or data[pe:pe + 4] != bytes((80, 69, 0, 0)):
        raise PEFormatError("missing or truncated PE signature")
    coff = pe + 4
    machine, count, _, _, _, opt_size, flags = _field(data, "<HHIIIHH", coff)
    opt = coff + 20
    end = opt + opt_size
    if end > len(data) or opt_size < 112:
        raise PEFormatError("optional header missing or too short")
    if _field(data, "<H", opt) != 0x20B:
        raise PEFormatError("expected PE32+ (64-bit)")
    if machine != 0x8664:
        raise PEFormatError("expected AMD64 executable")
    if flags & 0x2000:
        raise PEFormatError("DLL is not supported")
    entry = _field(data, "<I", opt + 16)
    image_base = _field(data, "<Q", opt + 24)
    size_image = _field(data, "<I", opt + 56)
    size_hdr = _field(data, "<I", opt + 60)
    dll_flags = _field(data, "<H", opt + 70)
    directories = _field(data, "<I", opt + 108)
    if not size_image or not entry or entry >= size_image:
        raise PEFormatError("invalid image size or entry point")
    if not size_hdr or size_hdr > len(data) or size_hdr > size_image:
        raise PEFormatError("invalid header size")
    section_base = end
    if section_base + count * 40 > len(data) or not count:
        raise PEFormatError("section table truncated or empty")
    for i in range(count):
        pos = section_base + 40 * i
        virtual_size, virtual_address, raw_size, raw_offset = _field(data, "<IIII", pos + 8)
        if virtual_address + virtual_size > size_image:
            raise PEFormatError(f"section {i} exceeds image size")
        if raw_size and (raw_offset + raw_size > len(data)):
            raise PEFormatError(f"section {i} exceeds file size")
    reloc_size = 0
    if directories > 5:
        if opt_size < 112 + 6 * 8:
            raise PEFormatError("relocation directory not covered by optional header")
        reloc_rva, reloc_size = _field(data, "<II", opt + 112 + 5 * 8)
        if reloc_size and (not reloc_rva or reloc_rva + reloc_size > size_image):
            raise PEFormatError("invalid relocation directory")
    return {
        "machine": hex(machine), "sections": count, "image_base": hex(image_base),
        "entry_rva": hex(entry), "size_of_image": size_image,
        "size_of_headers": size_hdr, "aslr": bool(dll_flags & 0x40),
        "relocs": reloc_size > 0,
    }


def info(path: str) -> dict:
    result = inspect(Path(path).read_bytes())
    return {"file": path, **result}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    errors = 0
    for path in args.paths:
        try:
            result = info(path)
            if args.json:
                print(json.dumps(result, sort_keys=True))
            else:
                print(f"{path}: SizeOfImage={result['size_of_image']} "
                      f"entry={result['entry_rva']} sections={result['sections']} "
                      f"ASLR={result['aslr']} relocs={result['relocs']}")
        except (OSError, PEFormatError) as exc:
            errors += 1
            print(json.dumps({"file": path, "error": str(exc)}) if args.json
                  else f"{path}: {exc}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
