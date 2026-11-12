#!/usr/bin/env python3
"""sendkeys.py — injeta texto no guest via comando `sendkey` do monitor QEMU.

Canal independente do VNC: o monitor traduz nome de tecla -> scancode e injeta
direto no teclado do guest. Uso:
    sendkeys.py "<texto>"            # digita o texto (nao envia Enter)
    sendkeys.py "<texto>" --enter    # digita e pressiona Enter
    sendkeys.py --raw "ctrl-alt-delete"
"""

import os
import socket
import sys
import time

SOCK = os.environ.get("HOLLOW_SOCK") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "mon.sock")

NAMES = {
    " ": "spc",
    "-": "minus",
    "=": "equal",
    "[": "bracket_left",
    "]": "bracket_right",
    "\\": "backslash",
    ";": "semicolon",
    "'": "apostrophe",
    ",": "comma",
    ".": "dot",
    "/": "slash",
    "`": "grave_accent",
}
SHIFTED = {
    ":": "semicolon",
    "*": "8",
    "?": "slash",
    '"': "apostrophe",
    "<": "comma",
    ">": "dot",
    "_": "minus",
    "+": "equal",
    "(": "9",
    ")": "0",
    "{": "bracket_left",
    "}": "bracket_right",
    "|": "backslash",
    "!": "1",
    "@": "2",
    "#": "3",
    "$": "4",
    "%": "5",
    "^": "6",
    "&": "7",
    "~": "grave_accent",
}


def mon_cmd(cmd: str) -> str:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(SOCK)
    time.sleep(0.05)
    try:
        s.recv(4096)
    except socket.timeout:
        pass
    s.sendall((cmd + "\n").encode())
    time.sleep(0.05)
    try:
        s.recv(4096)
    except socket.timeout:
        pass
    s.close()
    return cmd


def key_for(ch: str) -> str:
    if ch.isupper():
        return "shift-" + ch.lower()
    if ch.isdigit():
        return ch
    if ch.isalpha():
        return ch
    if ch in SHIFTED:
        return "shift-" + SHIFTED[ch]
    return NAMES.get(ch, "")


def type_text(text: str) -> int:
    sent = 0
    for ch in text:
        k = key_for(ch)
        if not k:
            print(f"[!] sem mapeamento para {ch!r}", file=sys.stderr)
            continue
        mon_cmd(f"sendkey {k}")
        sent += 1
        time.sleep(0.02)
    return sent


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2
    if args[0] == "--raw":
        mon_cmd(f"sendkey {args[1]}")
        print(f"sendkey {args[1]}")
        return 0
    text = args[0]
    n = type_text(text)
    if "--enter" in args:
        mon_cmd("sendkey ret")
        print(f"sendkey ret")
    print(f"[sendkeys] {n} teclas")
    return 0


if __name__ == "__main__":
    sys.exit(main())
