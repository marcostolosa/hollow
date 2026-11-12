#!/usr/bin/env python3
"""shot.py — screenshot do QEMU via monitor socket (screendump) e PPM->PNG puro.

Sem PIL, sem imagemagick: serve para inspecionar o guest em modo headless.
"""

import socket
import struct
import sys
import time
import zlib


def qmp_talk(sock_path: str, cmd: str) -> str:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock_path)
    time.sleep(0.2)
    try:
        s.recv(65536)
    except socket.timeout:
        pass
    s.sendall((cmd + "\n").encode())
    time.sleep(0.5)
    out = b""
    s.settimeout(3)
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    s.close()
    return out.decode(errors="replace")


def ppm_to_png(ppm_path: str, png_path: str) -> tuple[int, int]:
    with open(ppm_path, "rb") as fh:
        data = fh.read()

    # header: P6\n<w> <h>\n255\n  (comentarios opcionais)
    pos = 0
    fields = []
    while len(fields) < 4:
        # pula comentarios
        while data[pos : pos + 1] == b"#":
            pos = data.index(b"\n", pos) + 1
        end = pos
        while data[end : end + 1] not in b" \t\r\n":
            end += 1
        fields.append(data[pos:end])
        pos = end + 1
    if fields[0] != b"P6":
        raise SystemExit("nao e PPM P6")

    w, h = int(fields[1]), int(fields[2])
    raw = data[pos : pos + w * h * 3]

    rows = b"".join(b"\x00" + raw[y * w * 3 : (y + 1) * w * 3] for y in range(h))

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows, 6))
        + chunk(b"IEND", b"")
    )
    with open(png_path, "wb") as fh:
        fh.write(png)
    return w, h


def main() -> int:
    if len(sys.argv) < 3:
        print("uso: shot.py <monitor.sock> <saida.png>")
        return 2
    sock_path, png = sys.argv[1], sys.argv[2]
    tmp = png.rsplit(".", 1)[0] + ".ppm"
    qmp_talk(sock_path, f"screendump {tmp}")
    try:
        w, h = ppm_to_png(tmp, png)
        print(f"{png}: {w}x{h}")
    except FileNotFoundError:
        print("[!] screendump nao gerou arquivo (QEMU sem display?)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
