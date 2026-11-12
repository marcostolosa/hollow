#!/usr/bin/env python3
"""peinfo.py — mostra os campos que importam para o overwrite (sem dependencia)."""

import struct
import sys


def info(path: str) -> dict:
    with open(path, "rb") as fh:
        data = fh.read(0x400)
    if data[:2] != b"MZ":
        raise SystemExit(f"{path}: sem MZ")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise SystemExit(f"{path}: sem PE")
    coff = e_lfanew + 4
    machine, nsec = struct.unpack_from("<HH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        raise SystemExit(f"{path}: nao e PE32+")
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    size_image = struct.unpack_from("<I", data, opt + 56)[0]
    size_hdr = struct.unpack_from("<I", data, opt + 60)[0]
    dllchar = struct.unpack_from("<H", data, opt + 70)[0]
    # reloc directory (index 5)
    reloc_rva, reloc_size = struct.unpack_from("<II", data, opt + 112 + 5 * 8)
    return {
        "file": path,
        "machine": hex(machine),
        "sections": nsec,
        "image_base": hex(image_base),
        "entry_rva": hex(entry),
        "size_of_image": size_image,
        "size_of_headers": size_hdr,
        "aslr": bool(dllchar & 0x40),
        "relocs": reloc_size > 0,
    }


if __name__ == "__main__":
    for p in sys.argv[1:]:
        d = info(p)
        print(f"{d['file']}:")
        print(
            f"  SizeOfImage = {d['size_of_image']} bytes ({d['size_of_image'] / 1024:.0f} KB)"
        )
        print(
            f"  ImageBase   = {d['image_base']}   entry={d['entry_rva']}   secoes={d['sections']}"
        )
        print(f"  ASLR={d['aslr']}  relocs={d['relocs']}  (relocs=0 -> nao relocavel)")
