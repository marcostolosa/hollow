#!/usr/bin/env python3
"""mkfloppy.py — monta uma imagem FAT12 de 1.44MB com o autounattend.xml.

Windows Setup procura o arquivo pelo nome literal `autounattend.xml`, entao um
FAT sem VFAT (nome curto AUTOUNAT.XML) NAO serve como fallback. Este gerador
emite entradas de long file name (LFN) antes da entrada 8.3.

Sem mtools, sem root.
"""

import struct
import sys

SECTOR = 512
SPC = 1
RESERVED = 1
NFATS = 2
ROOT_ENTRIES = 224
TOTAL_SECTORS = 2880
MEDIA = 0xF0
SPF = 9
ROOT_SECTORS = (ROOT_ENTRIES * 32 + SECTOR - 1) // SECTOR
DATA_START = RESERVED + NFATS * SPF + ROOT_SECTORS
ATTR_LFN = 0x0F
ATTR_ARCHIVE = 0x20


def fat12_set(fat: bytearray, cluster: int, value: int) -> None:
    off = cluster + cluster // 2
    cur = struct.unpack_from("<H", fat, off)[0]
    if cluster & 1:
        cur = (cur & 0x000F) | ((value & 0x0FFF) << 4)
    else:
        cur = (cur & 0xF000) | (value & 0x0FFF)
    struct.pack_into("<H", fat, off, cur)


def lfn_checksum(short11: bytes) -> int:
    s = 0
    for b in short11:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


def short_name(long_name: str, used: set[str]) -> bytes:
    """8.3 ASCII, com ~N se necessario."""
    base, _, ext = long_name.upper().rpartition(".")
    if not base:
        base, ext = ext, ""
    clean = "".join(c for c in base if c.isalnum() or c in "_-")[:8]
    ext = "".join(c for c in ext if c.isalnum())[:3]

    if len(base) <= 8 and len(clean) == len(base):
        cand = clean.ljust(8) + ext.ljust(3)
        if cand not in used:
            used.add(cand)
            return cand.encode()

    for n in range(1, 100):
        suffix = f"~{n}"
        stems = [s for s in (clean, "")]
        cand = (stems[0][: 8 - len(suffix)] + suffix).ljust(8) + ext.ljust(3)
        if cand not in used:
            used.add(cand)
            return cand.encode()
    raise RuntimeError("sem nome curto livre")


def build(files: list[tuple[str, bytes]]) -> bytes:
    img = bytearray(TOTAL_SECTORS * SECTOR)

    bs = bytearray(SECTOR)
    bs[0:3] = b"\xeb\x3c\x90"
    bs[3:11] = b"MSDOS5.0"
    struct.pack_into(
        "<HBHBHHBHHHII",
        bs,
        11,
        SECTOR,
        SPC,
        RESERVED,
        NFATS,
        ROOT_ENTRIES,
        TOTAL_SECTORS,
        MEDIA,
        SPF,
        18,
        2,
        0,
        0,
    )
    bs[36] = 0x00
    bs[38] = 0x29
    struct.pack_into("<I", bs, 39, 0x4C4142)
    bs[43:54] = b"HOLLOWLAB  "
    bs[54:62] = b"FAT12   "
    bs[510:512] = b"\x55\xaa"
    img[0:SECTOR] = bs

    fat = bytearray(SPF * SECTOR)
    fat[0:3] = bytes([MEDIA, 0xFF, 0xFF])
    next_cluster = 2
    root = bytearray(ROOT_SECTORS * SECTOR)
    slot = 0
    used_short: set[str] = set()

    for name, content in files:
        clusters = max(1, (len(content) + SECTOR - 1) // SECTOR)
        first = next_cluster
        for i in range(clusters):
            fat12_set(
                fat, next_cluster, next_cluster + 1 if i < clusters - 1 else 0xFFF
            )
            chunk = content[i * SECTOR : (i + 1) * SECTOR]
            sector = DATA_START + (next_cluster - 2)
            img[sector * SECTOR : sector * SECTOR + len(chunk)] = chunk
            next_cluster += 1

        short11 = short_name(name, used_short)

        # entradas LFN (se o nome nao couber em 8.3 puro)
        base, _, ext = name.upper().rpartition(".")
        if len(base) > 8:
            for entry in _iter_lfn(name, short11):
                root[slot * 32 : (slot + 1) * 32] = entry
                slot += 1

        off = slot * 32
        root[off : off + 11] = short11
        root[off + 11] = ATTR_ARCHIVE
        struct.pack_into("<H", root, off + 26, first & 0xFFFF)
        struct.pack_into("<I", root, off + 28, len(content))
        slot += 1

    img[RESERVED * SECTOR : (RESERVED + SPF) * SECTOR] = fat
    off = (RESERVED + SPF) * SECTOR
    img[off : off + SPF * SECTOR] = fat
    off = (RESERVED + 2 * SPF) * SECTOR
    img[off : off + ROOT_SECTORS * SECTOR] = root
    return bytes(img)


def _iter_lfn(long_name: str, short11: bytes):
    chars = list(long_name)
    if len(chars) % 13:
        chars += ["\0"] * (13 - len(chars) % 13)
    chunks = [chars[i : i + 13] for i in range(0, len(chars), 13)]
    csum = lfn_checksum(short11)
    for index in range(len(chunks) - 1, -1, -1):
        chunk = chunks[index]
        seq = index + 1
        if index == len(chunks) - 1:
            seq |= 0x40
        e = bytearray(32)
        e[0] = seq
        e[1:11] = "".join(chunk[0:5]).encode("utf-16-le")
        e[11] = ATTR_LFN
        e[12] = 0
        e[13] = csum
        e[14:26] = "".join(chunk[5:11]).encode("utf-16-le")
        e[26:28] = b"\0\0"
        e[28:32] = "".join(chunk[11:13]).encode("utf-16-le")
        yield bytes(e)


def main() -> int:
    if len(sys.argv) < 3:
        print("uso: mkfloppy.py <saida.img> <arquivo1> [arquivo2 ...]")
        return 2
    out = sys.argv[1]
    files = []
    for path in sys.argv[2:]:
        with open(path, "rb") as fh:
            files.append((path.rsplit("/", 1)[-1], fh.read()))
    data = build(files)
    with open(out, "wb") as fh:
        fh.write(data)
    print(f"[floppy] {out}: {len(data)} bytes")
    for n, c in files:
        print(f"         {n} ({len(c)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
